package outbound

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	heysocksxhttp "github.com/metacubex/mihomo/transport/heysocks/xhttp"

	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/uot"
)

func newLocalHeySocksXHTTP(
	t *testing.T,
	server string,
	port int,
	udpOverTCP bool,
	version int,
) *HeySocksXHTTP {
	t.Helper()

	proxy, err := NewHeySocksXHTTP(
		HeySocksXHTTPOption{
			Name:              "heysocks-xhttp-local-e2e",
			Server:            server,
			Port:              port,
			Password:          heySocksXHTTPTestPassword,
			Cipher:            "aes-128-ctr",
			UDP:               true,
			UDPOverTCP:        udpOverTCP,
			UDPOverTCPVersion: version,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	return proxy
}

func newLocalHeySocksXHTTPCipher(
	t *testing.T,
) *heysocksxhttp.StreamCipher {
	t.Helper()

	cipher, err := heysocksxhttp.NewStreamCipher(
		"aes-128-ctr",
		heySocksXHTTPTestPassword,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	return cipher
}

func TestHeySocksXHTTPLocalTCPE2E(
	t *testing.T,
) {
	listener, err := net.Listen(
		"tcp",
		"127.0.0.1:0",
	)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	proxyAddr :=
		listener.Addr().(*net.TCPAddr)

	metadata := &C.Metadata{
		NetWork: C.TCP,
		Host:    "example.com",
		DstPort: 443,
	}

	expectedDestination :=
		serializesSocksAddr(metadata)

	payload := []byte(
		"heysocks-xhttp-local-tcp-e2e",
	)

	serverErr := make(chan error, 1)

	serverCipher := newLocalHeySocksXHTTPCipher(t)

	go func() {
		rawConn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer rawConn.Close()

		if err := rawConn.SetDeadline(
			time.Now().Add(5 * time.Second),
		); err != nil {
			serverErr <- err
			return
		}

		stream := heysocksxhttp.NewConn(
			rawConn,
			serverCipher,
			nil,
		)

		gotDestination := make(
			[]byte,
			len(expectedDestination),
		)

		if _, err := io.ReadFull(
			stream,
			gotDestination,
		); err != nil {
			serverErr <- fmt.Errorf(
				"server read destination: %w",
				err,
			)
			return
		}

		if !bytes.Equal(
			gotDestination,
			expectedDestination,
		) {
			serverErr <- fmt.Errorf(
				"destination mismatch: got=%x want=%x",
				gotDestination,
				expectedDestination,
			)
			return
		}

		gotPayload := make(
			[]byte,
			len(payload),
		)

		if _, err := io.ReadFull(
			stream,
			gotPayload,
		); err != nil {
			serverErr <- fmt.Errorf(
				"server read payload: %w",
				err,
			)
			return
		}

		if !bytes.Equal(
			gotPayload,
			payload,
		) {
			serverErr <- fmt.Errorf(
				"payload mismatch: got=%q want=%q",
				gotPayload,
				payload,
			)
			return
		}

		if _, err := stream.Write(
			gotPayload,
		); err != nil {
			serverErr <- fmt.Errorf(
				"server write response: %w",
				err,
			)
			return
		}

		serverErr <- nil
	}()

	proxy := newLocalHeySocksXHTTP(
		t,
		"127.0.0.1",
		proxyAddr.Port,
		false,
		0,
	)

	ctx, cancel :=
		context.WithTimeout(
			context.Background(),
			5*time.Second,
		)
	defer cancel()

	conn, err := proxy.DialContext(
		ctx,
		metadata,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(
		time.Now().Add(5 * time.Second),
	); err != nil {
		t.Fatal(err)
	}

	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}

	response := make(
		[]byte,
		len(payload),
	)

	if _, err := io.ReadFull(
		conn,
		response,
	); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(
		response,
		payload,
	) {
		t.Fatalf(
			"response mismatch: got=%q want=%q",
			response,
			payload,
		)
	}

	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestHeySocksXHTTPLocalNativeUDPE2E(
	t *testing.T,
) {
	rawServer, err := net.ListenPacket(
		"udp",
		"127.0.0.1:0",
	)
	if err != nil {
		t.Fatal(err)
	}
	defer rawServer.Close()

	proxyAddr :=
		rawServer.LocalAddr().(*net.UDPAddr)

	serverPacketConn :=
		heysocksxhttp.NewPacketConn(
			rawServer,
			newLocalHeySocksXHTTPCipher(t),
		)

	if err := serverPacketConn.SetDeadline(
		time.Now().Add(5 * time.Second),
	); err != nil {
		t.Fatal(err)
	}

	payload := []byte(
		"heysocks-xhttp-local-native-udp-e2e",
	)

	serverErr := make(chan error, 1)

	go func() {
		buffer := make([]byte, 65535)

		n, clientAddr, err :=
			serverPacketConn.ReadFrom(buffer)
		if err != nil {
			serverErr <- fmt.Errorf(
				"server UDP read: %w",
				err,
			)
			return
		}

		if !bytes.Equal(
			buffer[:n],
			payload,
		) {
			serverErr <- fmt.Errorf(
				"server UDP payload mismatch: got=%q want=%q",
				buffer[:n],
				payload,
			)
			return
		}

		if _, err := serverPacketConn.WriteTo(
			buffer[:n],
			clientAddr,
		); err != nil {
			serverErr <- fmt.Errorf(
				"server UDP write: %w",
				err,
			)
			return
		}

		serverErr <- nil
	}()

	proxy := newLocalHeySocksXHTTP(
		t,
		"127.0.0.1",
		proxyAddr.Port,
		false,
		0,
	)

	metadata := &C.Metadata{
		NetWork: C.UDP,
		Host:    "target.example",
		DstPort: 53,
	}

	ctx, cancel :=
		context.WithTimeout(
			context.Background(),
			5*time.Second,
		)
	defer cancel()

	packetConn, err :=
		proxy.ListenPacketContext(
			ctx,
			metadata,
		)
	if err != nil {
		t.Fatal(err)
	}
	defer packetConn.Close()

	if err := packetConn.SetDeadline(
		time.Now().Add(5 * time.Second),
	); err != nil {
		t.Fatal(err)
	}

	// Deliberately use an unrelated TEST-NET destination.
	//
	// If the adapter failed to bind the encrypted UDP socket to the
	// XHTTP proxy endpoint, this datagram would not reach rawServer.
	fakeTarget := &net.UDPAddr{
		IP:   net.IPv4(203, 0, 113, 9),
		Port: 53,
	}

	n, err := packetConn.WriteTo(
		payload,
		fakeTarget,
	)
	if err != nil {
		t.Fatal(err)
	}

	if n != len(payload) {
		t.Fatalf(
			"UDP WriteTo returned n=%d want=%d",
			n,
			len(payload),
		)
	}

	response := make([]byte, 65535)

	n, _, err = packetConn.ReadFrom(
		response,
	)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(
		response[:n],
		payload,
	) {
		t.Fatalf(
			"UDP response mismatch: got=%q want=%q",
			response[:n],
			payload,
		)
	}

	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func runHeySocksXHTTPLocalUOTE2E(
	t *testing.T,
	optionVersion int,
	serverVersion int,
) {
	t.Helper()

	payload := []byte(
		"heysocks-xhttp-local-uot-e2e",
	)

	targetConn, err := net.ListenPacket(
		"udp",
		"127.0.0.1:0",
	)
	if err != nil {
		t.Fatal(err)
	}
	defer targetConn.Close()

	targetAddr, ok :=
		targetConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf(
			"unexpected target address type: %T",
			targetConn.LocalAddr(),
		)
	}

	if err := targetConn.SetDeadline(
		time.Now().Add(5 * time.Second),
	); err != nil {
		t.Fatal(err)
	}

	targetErr := make(chan error, 1)

	go func() {
		buffer := make([]byte, 65535)

		n, clientAddr, err :=
			targetConn.ReadFrom(buffer)
		if err != nil {
			targetErr <- fmt.Errorf(
				"target UDP read: %w",
				err,
			)
			return
		}

		if !bytes.Equal(
			buffer[:n],
			payload,
		) {
			targetErr <- fmt.Errorf(
				"target UDP payload mismatch: got=%q want=%q",
				buffer[:n],
				payload,
			)
			return
		}

		if _, err := targetConn.WriteTo(
			buffer[:n],
			clientAddr,
		); err != nil {
			targetErr <- fmt.Errorf(
				"target UDP echo: %w",
				err,
			)
			return
		}

		targetErr <- nil
	}()

	listener, err := net.Listen(
		"tcp",
		"127.0.0.1:0",
	)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	proxyAddr, ok :=
		listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf(
			"unexpected proxy listener address type: %T",
			listener.Addr(),
		)
	}

	expectedXHTTPDestination, err :=
		serializeHeySocksXHTTPSocksaddr(
			uot.RequestDestination(
				uint8(optionVersion),
			),
		)
	if err != nil {
		t.Fatal(err)
	}

	serverCipher :=
		newLocalHeySocksXHTTPCipher(t)

	serverDone := make(chan struct{})
	serverErr := make(chan error, 1)

	stopServer := func() {
		select {
		case <-serverDone:
		default:
			close(serverDone)
		}
	}
	defer stopServer()

	go func() {
		rawConn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer rawConn.Close()

		if err := rawConn.SetDeadline(
			time.Now().Add(5 * time.Second),
		); err != nil {
			serverErr <- err
			return
		}

		stream := heysocksxhttp.NewConn(
			rawConn,
			serverCipher,
			nil,
		)

		gotDestination := make(
			[]byte,
			len(expectedXHTTPDestination),
		)

		if _, err := io.ReadFull(
			stream,
			gotDestination,
		); err != nil {
			serverErr <- fmt.Errorf(
				"server read XHTTP UOT destination: %w",
				err,
			)
			return
		}

		if !bytes.Equal(
			gotDestination,
			expectedXHTTPDestination,
		) {
			serverErr <- fmt.Errorf(
				"XHTTP UOT destination mismatch: got=%x want=%x",
				gotDestination,
				expectedXHTTPDestination,
			)
			return
		}

		udpTransport, err := net.ListenPacket(
			"udp",
			"127.0.0.1:0",
		)
		if err != nil {
			serverErr <- err
			return
		}

		if err := udpTransport.SetDeadline(
			time.Now().Add(5 * time.Second),
		); err != nil {
			udpTransport.Close()
			serverErr <- err
			return
		}

		uotServer := uot.NewServerConn(
			udpTransport,
			serverVersion,
		)

		go func() {
			_, _ = io.Copy(
				uotServer,
				stream,
			)
		}()

		go func() {
			_, _ = io.Copy(
				stream,
				uotServer,
			)
		}()

		<-serverDone

		_ = uotServer.Close()

		serverErr <- nil
	}()

	proxy := newLocalHeySocksXHTTP(
		t,
		"127.0.0.1",
		proxyAddr.Port,
		true,
		optionVersion,
	)

	metadata := &C.Metadata{
		NetWork: C.UDP,
		Host:    "127.0.0.1",
		DstPort: uint16(targetAddr.Port),
	}

	ctx, cancel :=
		context.WithTimeout(
			context.Background(),
			5*time.Second,
		)
	defer cancel()

	packetConn, err :=
		proxy.ListenPacketContext(
			ctx,
			metadata,
		)
	if err != nil {
		t.Fatal(err)
	}
	defer packetConn.Close()

	if err := packetConn.SetDeadline(
		time.Now().Add(5 * time.Second),
	); err != nil {
		t.Fatal(err)
	}

	n, err := packetConn.WriteTo(
		payload,
		targetAddr,
	)
	if err != nil {
		t.Fatal(err)
	}

	expectedWriteN := len(payload)

	// sing v0.5.7 legacy UOT uses NewConn directly over the
	// underlying stream. When no vectorised writer is available,
	// Conn.WriteTo returns the complete encoded legacy frame length:
	//
	//     destination + uint16 payload length + payload
	//
	// Current/v2 NewLazyConn uses the vectorised path and reports
	// the original plaintext payload length instead.
	if optionVersion == uot.LegacyVersion {
		destination := M.SocksaddrFromNet(targetAddr)

		expectedWriteN =
			uot.AddrParser.AddrPortLen(destination) +
				2 +
				len(payload)
	}

	if n != expectedWriteN {
		t.Fatalf(
			"UOT WriteTo returned n=%d want=%d for version=%d",
			n,
			expectedWriteN,
			optionVersion,
		)
	}

	response := make([]byte, 65535)

	n, responseAddr, err :=
		packetConn.ReadFrom(response)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(
		response[:n],
		payload,
	) {
		t.Fatalf(
			"UOT response mismatch: got=%q want=%q",
			response[:n],
			payload,
		)
	}

	responseUDPAddr, ok :=
		responseAddr.(*net.UDPAddr)
	if !ok {
		t.Fatalf(
			"unexpected UOT response address type: %T",
			responseAddr,
		)
	}

	if responseUDPAddr.Port != targetAddr.Port ||
		!responseUDPAddr.IP.Equal(targetAddr.IP) {
		t.Fatalf(
			"unexpected UOT response address: got=%v want=%v",
			responseUDPAddr,
			targetAddr,
		)
	}

	if err := <-targetErr; err != nil {
		t.Fatal(err)
	}

	stopServer()

	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestHeySocksXHTTPLocalUOTDefaultZeroE2E(
	t *testing.T,
) {
	runHeySocksXHTTPLocalUOTE2E(
		t,
		0,
		uot.Version,
	)
}

func TestHeySocksXHTTPLocalUOTLegacyOneE2E(
	t *testing.T,
) {
	runHeySocksXHTTPLocalUOTE2E(
		t,
		uot.LegacyVersion,
		uot.LegacyVersion,
	)
}

func TestHeySocksXHTTPLocalUOTCurrentTwoE2E(
	t *testing.T,
) {
	runHeySocksXHTTPLocalUOTE2E(
		t,
		uot.Version,
		uot.Version,
	)
}
