package outbound

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strconv"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	heysocksonesocks "github.com/metacubex/mihomo/transport/heysocks/onesocks"
	"github.com/metacubex/mihomo/transport/socks5"

	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/uot"
)

type OneSocksOption struct {
	BasicOption

	Name     string `proxy:"name"`
	Server   string `proxy:"server"`
	Port     int    `proxy:"port"`
	Password string `proxy:"password"`

	Cipher string `proxy:"cipher,omitempty"`

	UDP               bool `proxy:"udp,omitempty"`
	UDPOverTCP        bool `proxy:"udp-over-tcp,omitempty"`
	UDPOverTCPVersion int  `proxy:"udp-over-tcp-version,omitempty"`

	PaddingLen string `proxy:"padding-len,omitempty"`

	E bool   `proxy:"e,omitempty"`
	H string `proxy:"h,omitempty"`
}

type OneSocks struct {
	*Base

	cipher     *heysocksonesocks.StreamCipher
	paddingLen int
	option     *OneSocksOption
}

func serializeOneSocksSocksaddr(
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

func (o *OneSocks) streamDestination(
	metadata *C.Metadata,
) ([]byte, error) {
	if metadata == nil {
		return nil, fmt.Errorf(
			"onesocks: nil metadata",
		)
	}

	if metadata.NetWork == C.UDP &&
		o.option.UDPOverTCP {
		destination := uot.RequestDestination(
			uint8(o.option.UDPOverTCPVersion),
		)

		encoded, err :=
			serializeOneSocksSocksaddr(destination)
		if err != nil {
			return nil, fmt.Errorf(
				"onesocks: serialize UOT destination: %w",
				err,
			)
		}

		return encoded, nil
	}

	destination := serializesSocksAddr(metadata)

	if len(destination) == 0 {
		return nil, fmt.Errorf(
			"onesocks: invalid destination",
		)
	}

	return destination, nil
}

// StreamConnContext applies the recovered OneSocks TCP framing.
//
// The OneSocks stream owns the destination first flight.
// Write(nil) sends the encrypted SOCKS destination before application data.
func (o *OneSocks) StreamConnContext(
	ctx context.Context,
	conn net.Conn,
	metadata *C.Metadata,
) (net.Conn, error) {
	_ = ctx

	destination, err :=
		o.streamDestination(metadata)
	if err != nil {
		return nil, err
	}

	stream, err := heysocksonesocks.NewConn(
		conn,
		o.cipher,
		destination,
		o.paddingLen,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"onesocks: create stream: %w",
			err,
		)
	}

	if _, err := stream.Write(nil); err != nil {
		return nil, fmt.Errorf(
			"onesocks: write destination: %w",
			err,
		)
	}

	return stream, nil
}

func (o *OneSocks) DialContext(
	ctx context.Context,
	metadata *C.Metadata,
) (_ C.Conn, err error) {
	conn, err := o.dialer.DialContext(
		ctx,
		"tcp",
		o.addr,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"%s connect error: %w",
			o.addr,
			err,
		)
	}

	defer func(conn net.Conn) {
		safeConnClose(conn, err)
	}(conn)

	conn, err = o.StreamConnContext(
		ctx,
		conn,
		metadata,
	)
	if err != nil {
		return nil, err
	}

	return NewConn(conn, o), nil
}

func (o *OneSocks) listenPacketContext(
	ctx context.Context,
) (net.PacketConn, net.Addr, error) {
	addr, err := resolveUDPAddr(
		ctx,
		"udp",
		o.addr,
		o.prefer,
	)
	if err != nil {
		return nil, nil, err
	}

	packetConn, err := o.dialer.ListenPacket(
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

// oneSocksPacketConn mirrors the recovered native ssPacketConn.
//
// The inner PacketConn owns OneSocks UDP encryption. This wrapper owns the
// SOCKS destination/source address framing and fixes the actual network
// destination to the OneSocks UDP server.
type oneSocksPacketConn struct {
	net.PacketConn

	rAddr net.Addr
}

func (c *oneSocksPacketConn) WriteTo(
	p []byte,
	addr net.Addr,
) (int, error) {
	packet, err := socks5.EncodeUDPPacket(
		socks5.ParseAddrToSocksAddr(addr),
		p,
	)
	if err != nil {
		return 0, err
	}

	// EncodeUDPPacket produces:
	//
	//	00 00 00 || SOCKS_ADDR || payload
	//
	// Native OneSocks removes the three-byte SOCKS5 UDP prefix before
	// passing the plaintext into the encrypted PacketConn.
	if len(packet) < 3 {
		return 0, fmt.Errorf(
			"onesocks: invalid encoded UDP packet",
		)
	}

	plaintext := packet[3:]

	n, err := c.PacketConn.WriteTo(
		plaintext,
		c.rAddr,
	)
	if err != nil {
		return 0, err
	}

	if n != len(plaintext) {
		return 0, fmt.Errorf(
			"onesocks: short native UDP plaintext write: wrote=%d want=%d",
			n,
			len(plaintext),
		)
	}

	return len(p), nil
}

func (c *oneSocksPacketConn) ReadFrom(
	p []byte,
) (int, net.Addr, error) {
	n, _, err := c.PacketConn.ReadFrom(p)
	if err != nil {
		return n, nil, err
	}

	if n == 0 {
		return 0, nil, fmt.Errorf(
			"onesocks: empty native UDP packet",
		)
	}

	addr := socks5.SplitAddr(p[:n])
	if addr == nil {
		return 0, nil, fmt.Errorf(
			"onesocks: failed to parse native UDP source address",
		)
	}

	// Recovered native ssPacketConn.ReadFrom constructs source net.Addr
	// values only for IPv4 and IPv6. Domain-form source addresses are
	// rejected here for wire compatibility.
	switch addr[0] {
	case socks5.AtypIPv4, socks5.AtypIPv6:
	default:
		return 0, nil, fmt.Errorf(
			"onesocks: unsupported native UDP source address type %#x",
			addr[0],
		)
	}

	udpAddr := addr.UDPAddr()
	if udpAddr == nil {
		return 0, nil, fmt.Errorf(
			"onesocks: failed to build native UDP source address",
		)
	}

	if len(addr) > n {
		return 0, nil, fmt.Errorf(
			"onesocks: invalid native UDP source address length",
		)
	}

	copy(
		p,
		p[len(addr):n],
	)

	return n - len(addr), udpAddr, nil
}

func (o *OneSocks) ListenPacketContext(
	ctx context.Context,
	metadata *C.Metadata,
) (_ C.PacketConn, err error) {
	if o.option.UDPOverTCP {
		var conn net.Conn

		conn, err = o.DialContext(
			ctx,
			metadata,
		)
		if err != nil {
			return nil, err
		}

		defer func(conn net.Conn) {
			safeConnClose(conn, err)
		}(conn)

		if err = o.ResolveUDP(
			ctx,
			metadata,
		); err != nil {
			return nil, err
		}

		destination :=
			M.SocksaddrFromNet(metadata.UDPAddr())

		if o.option.UDPOverTCPVersion ==
			uot.LegacyVersion {
			packetConn := uot.NewConn(
				conn,
				uot.Request{},
			)

			return NewPacketConn(
				N.NewThreadSafePacketConn(
					packetConn,
				),
				o,
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
			o,
		), nil
	}

	packetConn, proxyAddr, err :=
		o.listenPacketContext(ctx)
	if err != nil {
		return nil, err
	}

	encryptedPacketConn, err :=
		heysocksonesocks.NewPacketConn(
			packetConn,
			o.cipher,
			o.paddingLen,
		)
	if err != nil {
		_ = packetConn.Close()

		return nil, fmt.Errorf(
			"onesocks: create native UDP cipher packet connection: %w",
			err,
		)
	}

	packetConn = &oneSocksPacketConn{
		PacketConn: encryptedPacketConn,
		rAddr:      proxyAddr,
	}

	return NewPacketConn(
		packetConn,
		o,
	), nil
}

// SupportUDP implements C.ProxyAdapter.
//
// UDP-over-TCP and native OneSocks UDP are both implemented.
func (o *OneSocks) SupportUDP() bool {
	return o.option.UDP
}

func (o *OneSocks) SupportUOT() bool {
	return o.option.UDPOverTCP
}

func (o *OneSocks) ProxyInfo() C.ProxyInfo {
	info := o.Base.ProxyInfo()
	info.DialerProxy = o.option.DialerProxy
	return info
}

func NewOneSocks(
	option OneSocksOption,
) (*OneSocks, error) {
	addr := net.JoinHostPort(
		option.Server,
		strconv.Itoa(option.Port),
	)

	if option.Cipher == "" {
		option.Cipher = "aes-128-ctr"
	}

	if option.UDPOverTCP {
		switch option.UDPOverTCPVersion {
		case 0, uot.LegacyVersion, uot.Version:
		default:
			return nil, fmt.Errorf(
				"onesocks %s unsupported udp-over-tcp-version %d",
				addr,
				option.UDPOverTCPVersion,
			)
		}
	}

	paddingLen, err :=
		heysocksonesocks.ParsePaddingLen(
			option.PaddingLen,
		)
	if err != nil {
		return nil, fmt.Errorf(
			"onesocks %s parse padding-len: %w",
			addr,
			err,
		)
	}

	streamCipher, err :=
		heysocksonesocks.NewStreamCipher(
			option.Cipher,
			option.Password,
		)
	if err != nil {
		return nil, fmt.Errorf(
			"onesocks %s initialize cipher: %w",
			addr,
			err,
		)
	}

	outbound := &OneSocks{
		Base: NewBase(
			BaseOption{
				Name:         option.Name,
				Addr:         addr,
				Type:         C.OneSocks,
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

		cipher:     streamCipher,
		paddingLen: paddingLen,
		option:     &option,
	}

	outbound.dialer =
		option.NewDialer(
			outbound.DialOptions(),
		)

	return outbound, nil
}
