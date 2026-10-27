package outbound

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/socks5"
)

type oneSocksNativeTestPacketConn struct {
	readPacket []byte
	readAddr   net.Addr

	wrote     []byte
	writeAddr net.Addr
}

func (c *oneSocksNativeTestPacketConn) ReadFrom(
	p []byte,
) (int, net.Addr, error) {
	n := copy(p, c.readPacket)
	return n, c.readAddr, nil
}

func (c *oneSocksNativeTestPacketConn) WriteTo(
	p []byte,
	addr net.Addr,
) (int, error) {
	c.wrote = append(
		c.wrote[:0],
		p...,
	)
	c.writeAddr = addr

	return len(p), nil
}

func (c *oneSocksNativeTestPacketConn) Close() error {
	return nil
}

func (c *oneSocksNativeTestPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{}
}

func (c *oneSocksNativeTestPacketConn) SetDeadline(
	time.Time,
) error {
	return nil
}

func (c *oneSocksNativeTestPacketConn) SetReadDeadline(
	time.Time,
) error {
	return nil
}

func (c *oneSocksNativeTestPacketConn) SetWriteDeadline(
	time.Time,
) error {
	return nil
}

func TestOneSocksPacketWrapperWrite(
	t *testing.T,
) {
	proxyAddr := &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 443,
	}

	targetAddr := &net.UDPAddr{
		IP:   net.IPv4(1, 1, 1, 1),
		Port: 53,
	}

	payload := []byte{
		0xde,
		0xad,
		0xbe,
		0xef,
	}

	base := &oneSocksNativeTestPacketConn{}

	conn := &oneSocksPacketConn{
		PacketConn: base,
		rAddr:      proxyAddr,
	}

	n, err := conn.WriteTo(
		payload,
		targetAddr,
	)
	if err != nil {
		t.Fatal(err)
	}

	if n != len(payload) {
		t.Fatalf(
			"WriteTo n=%d want=%d",
			n,
			len(payload),
		)
	}

	if base.writeAddr != proxyAddr {
		t.Fatalf(
			"network destination=%v want=%v",
			base.writeAddr,
			proxyAddr,
		)
	}

	target := socks5.ParseAddrToSocksAddr(
		targetAddr,
	)

	want := append(
		append(
			[]byte(nil),
			target...,
		),
		payload...,
	)

	if !bytes.Equal(
		base.wrote,
		want,
	) {
		t.Fatalf(
			"plaintext=%x want=%x",
			base.wrote,
			want,
		)
	}
}

func TestOneSocksPacketWrapperRead(
	t *testing.T,
) {
	sourceAddr := &net.UDPAddr{
		IP:   net.IPv4(8, 8, 8, 8),
		Port: 53,
	}

	payload := []byte(
		"native-udp-reply",
	)

	source := socks5.ParseAddrToSocksAddr(
		sourceAddr,
	)

	base := &oneSocksNativeTestPacketConn{
		readPacket: append(
			append(
				[]byte(nil),
				source...,
			),
			payload...,
		),
		readAddr: &net.UDPAddr{
			IP:   net.IPv4(127, 0, 0, 1),
			Port: 443,
		},
	}

	conn := &oneSocksPacketConn{
		PacketConn: base,
		rAddr:      base.readAddr,
	}

	buf := make(
		[]byte,
		len(base.readPacket)+32,
	)

	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}

	if n != len(payload) {
		t.Fatalf(
			"ReadFrom n=%d want=%d",
			n,
			len(payload),
		)
	}

	gotAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		t.Fatalf(
			"ReadFrom addr type=%T",
			addr,
		)
	}

	if gotAddr.String() !=
		sourceAddr.String() {
		t.Fatalf(
			"ReadFrom addr=%v want=%v",
			gotAddr,
			sourceAddr,
		)
	}

	if !bytes.Equal(
		buf[:n],
		payload,
	) {
		t.Fatalf(
			"payload=%x want=%x",
			buf[:n],
			payload,
		)
	}
}

func TestOneSocksPacketWrapperRejectDomainSource(
	t *testing.T,
) {
	const domain = "example.com"

	packet := []byte{
		socks5.AtypDomainName,
		byte(len(domain)),
	}

	packet = append(
		packet,
		domain...,
	)

	packet = append(
		packet,
		0x00,
		0x35,
		0xaa,
	)

	base := &oneSocksNativeTestPacketConn{
		readPacket: packet,
		readAddr: &net.UDPAddr{
			IP:   net.IPv4(127, 0, 0, 1),
			Port: 443,
		},
	}

	conn := &oneSocksPacketConn{
		PacketConn: base,
		rAddr:      base.readAddr,
	}

	buf := make(
		[]byte,
		len(packet)+16,
	)

	if _, _, err := conn.ReadFrom(buf); err == nil {
		t.Fatal(
			"expected domain source rejection",
		)
	}
}

func TestOneSocksAdvertisesNativeUDP(
	t *testing.T,
) {
	proxy, err := NewOneSocks(
		OneSocksOption{
			Name:     "native-udp-test",
			Server:   "127.0.0.1",
			Port:     443,
			Password: "password",
			UDP:      true,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if !proxy.SupportUDP() {
		t.Fatal(
			"native UDP should be advertised",
		)
	}

	if proxy.SupportUOT() {
		t.Fatal(
			"native-only config should not advertise UOT",
		)
	}
}
