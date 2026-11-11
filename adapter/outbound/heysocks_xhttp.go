package outbound

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strconv"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	heysocksxhttp "github.com/metacubex/mihomo/transport/heysocks/xhttp"

	"github.com/metacubex/sing/common/bufio"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/uot"
)

// HeySocksXHTTPOption is the directly decoded compatibility form of the
// native HeySocks XHTTP option.
//
// The native application normally reconstructs this internal option through
// its encrypted sidecar. Mihomo receives the already-decoded fields directly,
// so no private sidecar decryption is performed here.
//
// PaddingLen is retained for compatibility with decoded/exported configs.
// The currently validated xstream path does not consume it.
//
// E and H are retained so decoded configs can be represented, but non-default
// values are rejected until their native runtime semantics are established.
type HeySocksXHTTPOption struct {
	BasicOption

	Name     string `proxy:"name"`
	Server   string `proxy:"server"`
	Port     int    `proxy:"port"`
	Password string `proxy:"password"`

	Cipher string `proxy:"cipher,omitempty"`

	UDP               bool `proxy:"udp,omitempty"`
	UDPOverTCP        bool `proxy:"udp-over-tcp,omitempty"`
	UDPOverTCPVersion int  `proxy:"udp-over-tcp-version,omitempty"`

	PaddingLen string            `proxy:"padding-len,omitempty"`
	FakeNet    map[string]string `proxy:"fake-net,omitempty"`

	E bool   `proxy:"e,omitempty"`
	H string `proxy:"h,omitempty"`
}

// HeySocksXHTTP implements the proprietary HeySocks XHTTP/xstream outbound.
//
// This is intentionally separate from Mihomo's standard VLESS XHTTP
// implementation. The native HeySocks implementation uses its own xstream
// framing and AES-CTR data path over a generic dialer.
type HeySocksXHTTP struct {
	*Base

	cipher *heysocksxhttp.StreamCipher
	option *HeySocksXHTTPOption
}

// serializeHeySocksXHTTPSocksaddr serializes a sing Socksaddr using the same
// address representation used by the native outbound helpers.
func serializeHeySocksXHTTPSocksaddr(
	destination M.Socksaddr,
) ([]byte, error) {
	var buffer bytes.Buffer

	buffer.Grow(
		M.SocksaddrSerializer.AddrPortLen(destination),
	)

	if err := M.SocksaddrSerializer.WriteAddrPort(
		&buffer,
		destination,
	); err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

// streamDestination mirrors native Xhttp.StreamConnContext.
//
// Normal TCP:
//
//	SOCKS address of metadata target.
//
// UDP-over-TCP:
//
//	UOT protocol destination generated from UDPOverTCPVersion.
//
// Important:
// version 0 is deliberately NOT normalized to legacy version 1.
// Native XHTTP treats version == 1 as legacy and every other value as
// the lazy/current UOT path.
func (x *HeySocksXHTTP) streamDestination(
	metadata *C.Metadata,
) ([]byte, error) {
	if metadata == nil {
		return nil, fmt.Errorf(
			"heysocks xhttp: nil metadata",
		)
	}

	if metadata.NetWork == C.UDP &&
		x.option.UDPOverTCP {
		destination := uot.RequestDestination(
			uint8(x.option.UDPOverTCPVersion),
		)

		encoded, err :=
			serializeHeySocksXHTTPSocksaddr(
				destination,
			)
		if err != nil {
			return nil, fmt.Errorf(
				"heysocks xhttp: serialize UOT destination: %w",
				err,
			)
		}

		return encoded, nil
	}

	destination := serializesSocksAddr(metadata)

	if len(destination) == 0 {
		return nil, fmt.Errorf(
			"heysocks xhttp: invalid destination",
		)
	}

	return destination, nil
}

// StreamConnContext applies the recovered HeySocks xstream framing.
//
// The xstream connection owns the destination first flight.
// Write(nil) forces that destination before any application payload.
func (x *HeySocksXHTTP) StreamConnContext(
	ctx context.Context,
	conn net.Conn,
	metadata *C.Metadata,
) (net.Conn, error) {
	_ = ctx

	destination, err :=
		x.streamDestination(metadata)
	if err != nil {
		return nil, err
	}

	stream := heysocksxhttp.NewConn(
		conn,
		x.cipher,
		destination,
	)

	if _, err := stream.Write(nil); err != nil {
		return nil, fmt.Errorf(
			"heysocks xhttp: write destination: %w",
			err,
		)
	}

	return stream, nil
}

// DialContext implements C.ProxyAdapter.
func (x *HeySocksXHTTP) DialContext(
	ctx context.Context,
	metadata *C.Metadata,
) (_ C.Conn, err error) {
	conn, err := x.dialer.DialContext(
		ctx,
		"tcp",
		x.addr,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"%s connect error: %w",
			x.addr,
			err,
		)
	}

	defer func(conn net.Conn) {
		safeConnClose(conn, err)
	}(conn)

	conn, err = x.StreamConnContext(
		ctx,
		conn,
		metadata,
	)
	if err != nil {
		return nil, err
	}

	return NewConn(conn, x), nil
}

func (x *HeySocksXHTTP) listenPacketContext(
	ctx context.Context,
) (
	net.PacketConn,
	net.Addr,
	error,
) {
	addr, err := resolveUDPAddr(
		ctx,
		"udp",
		x.addr,
		x.prefer,
	)
	if err != nil {
		return nil, nil, err
	}

	packetConn, err := x.dialer.ListenPacket(
		ctx,
		"udp",
		"",
		addr.AddrPort(),
	)
	if err != nil {
		return nil, nil, err
	}

	return packetConn, addr, nil
}

// ListenPacketContext implements C.ProxyAdapter.
//
// HeySocks XHTTP has two independent UDP paths:
//
//   - UDP-over-TCP:
//     XHTTP TCP stream -> UOT.
//
//   - native UDP:
//     UDP socket to proxy server -> xstream PacketConn.
//
// Version handling intentionally mirrors native XHTTP:
// version == 1 -> legacy NewConn
// otherwise    -> NewLazyConn
func (x *HeySocksXHTTP) ListenPacketContext(
	ctx context.Context,
	metadata *C.Metadata,
) (_ C.PacketConn, err error) {
	if x.option.UDPOverTCP {
		var conn net.Conn

		conn, err = x.DialContext(
			ctx,
			metadata,
		)
		if err != nil {
			return nil, err
		}

		defer func(conn net.Conn) {
			safeConnClose(conn, err)
		}(conn)

		if err = x.ResolveUDP(
			ctx,
			metadata,
		); err != nil {
			return nil, err
		}

		destination :=
			M.SocksaddrFromNet(
				metadata.UDPAddr(),
			)

		if x.option.UDPOverTCPVersion ==
			uot.LegacyVersion {
			packetConn := uot.NewConn(
				conn,
				uot.Request{},
			)

			return NewPacketConn(
				N.NewThreadSafePacketConn(
					packetConn,
				),
				x,
			), nil
		}

		packetConn := uot.NewLazyConn(
			conn,
			uot.Request{
				Destination: destination,
			},
		)

		return NewPacketConn(
			N.NewThreadSafePacketConn(
				packetConn,
			),
			x,
		), nil
	}

	packetConn, proxyAddr, err :=
		x.listenPacketContext(ctx)
	if err != nil {
		return nil, err
	}

	// Build a fixed-remote PacketConn for the XHTTP UDP server.
	//
	// sing's BindPacketConn binds net.Conn.Write(), but its promoted
	// PacketConn.WriteTo() still preserves the caller-supplied address.
	// xstream.PacketConn uses WriteTo(), so BindPacketConn alone is not
	// sufficient.
	//
	// Wrapping BindPacketConn with UnbindPacketConn converts WriteTo()
	// back into net.Conn.Write(), which then uses the bound proxyAddr.
	//
	// Layering:
	//
	//     caller target
	//         -> xstream PacketConn.WriteTo
	//         -> UnbindPacketConn.WriteTo (ignores caller target)
	//         -> BindPacketConn.Write
	//         -> raw PacketConn.WriteTo(proxyAddr)
	//
	// This gives xstream a PacketConn API while keeping the actual UDP
	// transport fixed to the HeySocks XHTTP server.
	boundConn := bufio.NewBindPacketConn(
		packetConn,
		proxyAddr,
	)

	packetConn = bufio.NewUnbindPacketConn(
		boundConn,
	)

	packetConn = heysocksxhttp.NewPacketConn(
		packetConn,
		x.cipher,
	)

	return NewPacketConn(
		packetConn,
		x,
	), nil
}

// SupportUOT implements C.ProxyAdapter.
func (x *HeySocksXHTTP) SupportUOT() bool {
	return x.option.UDPOverTCP
}

// ProxyInfo implements C.ProxyAdapter.
func (x *HeySocksXHTTP) ProxyInfo() C.ProxyInfo {
	info := x.Base.ProxyInfo()

	info.DialerProxy =
		x.option.DialerProxy

	return info
}

func NewHeySocksXHTTP(
	option HeySocksXHTTPOption,
) (*HeySocksXHTTP, error) {
	addr := net.JoinHostPort(
		option.Server,
		strconv.Itoa(option.Port),
	)

	if option.Cipher == "" {
		option.Cipher = "aes-128-ctr"
	}

	if option.H != "" {
		return nil, fmt.Errorf(
			"heysocks xhttp: option h is not supported",
		)
	}

	streamCipher, err :=
		heysocksxhttp.NewStreamCipher(
			option.Cipher,
			option.Password,
			option.FakeNet,
		)
	if err != nil {
		return nil, fmt.Errorf(
			"heysocks xhttp %s initialize cipher: %w",
			addr,
			err,
		)
	}

	outbound := &HeySocksXHTTP{
		Base: NewBase(
			BaseOption{
				Name:         option.Name,
				Addr:         addr,
				Type:         C.HeySocksXHTTP,
				ProviderName: option.ProviderName,
				UDP:          option.UDP,
				XUDP:         false,
				TFO:          option.TFO,
				MPTCP:        option.MPTCP,
				Interface:    option.Interface,
				RoutingMark:  option.RoutingMark,
				Prefer:       option.IPVersion,
			},
		),

		cipher: streamCipher,
		option: &option,
	}

	outbound.dialer =
		option.NewDialer(
			outbound.DialOptions(),
		)

	return outbound, nil
}
