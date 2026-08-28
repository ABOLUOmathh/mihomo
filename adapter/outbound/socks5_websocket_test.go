package outbound

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/auth"
	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	socks5Transport "github.com/metacubex/mihomo/transport/socks5"
	mihomoVMess "github.com/metacubex/mihomo/transport/vmess"

	"github.com/metacubex/http"
	"github.com/metacubex/tls"
	"github.com/stretchr/testify/require"
)

const customSocksWSTestTimeout = 5 * time.Second

func customSplitHostPort(t *testing.T, addr string) (string, int) {
	t.Helper()

	host, portString, err := net.SplitHostPort(addr)
	require.NoError(t, err)

	port, err := strconv.ParseUint(portString, 10, 16)
	require.NoError(t, err)

	return host, int(port)
}

func startCustomEchoServer(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = listener.Close()
	})

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			go func(conn net.Conn) {
				defer conn.Close()

				// Echo everything received back to the client.
				_, _ = io.Copy(conn, conn)
			}(conn)
		}
	}()

	return listener.Addr().String()
}

func handleCustomSocks5ServerConn(conn net.Conn) {
	handleCustomSocks5ServerConnWithAuthenticator(conn, nil)
}

func handleCustomSocks5ServerConnWithAuthenticator(
	conn net.Conn,
	authenticator auth.Authenticator,
) {
	defer conn.Close()

	target, command, _, err := socks5Transport.ServerHandshake(
		conn,
		authenticator,
	)
	if err != nil {
		return
	}

	if command != socks5Transport.CmdConnect {
		return
	}

	upstream, err := net.DialTimeout(
		"tcp",
		target.String(),
		customSocksWSTestTimeout,
	)
	if err != nil {
		return
	}
	defer upstream.Close()

	// Client -> target.
	go func() {
		_, _ = io.Copy(upstream, conn)

		if tcpConn, ok := upstream.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
	}()

	// Target -> client.
	_, _ = io.Copy(conn, upstream)
}

func startCustomPlainSocks5Server(t *testing.T) (string, int) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = listener.Close()
	})

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			go handleCustomSocks5ServerConn(conn)
		}
	}()

	return customSplitHostPort(t, listener.Addr().String())
}

type customWebSocketSocks5ServerOptions struct {
	path          string
	useTLS        bool
	authenticator auth.Authenticator
	observedHost  chan<- string
}

func startCustomWebSocketSocks5ServerWithOptions(
	t *testing.T,
	options customWebSocketSocks5ServerOptions,
) (string, int) {
	t.Helper()

	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	var listener net.Listener = rawListener

	if options.useTLS {
		certificatePEM, privateKeyPEM, _, err :=
			ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
		require.NoError(t, err)

		certificate, err := tls.X509KeyPair(
			[]byte(certificatePEM),
			[]byte(privateKeyPEM),
		)
		require.NoError(t, err)

		listener = tls.NewListener(
			rawListener,
			&tls.Config{
				Certificates: []tls.Certificate{certificate},
				NextProtos:   []string{"http/1.1"},
			},
		)
	}

	mux := http.NewServeMux()

	mux.HandleFunc(options.path, func(w http.ResponseWriter, r *http.Request) {
		if options.observedHost != nil {
			select {
			case options.observedHost <- r.Host:
			default:
			}
		}

		conn, err := mihomoVMess.StreamUpgradedWebsocketConn(w, r)
		if err != nil {
			return
		}

		handleCustomSocks5ServerConnWithAuthenticator(
			conn,
			options.authenticator,
		)
	})

	server := &http.Server{
		Handler: mux,
	}

	t.Cleanup(func() {
		_ = listener.Close()
	})

	go func() {
		_ = server.Serve(listener)
	}()

	return customSplitHostPort(t, listener.Addr().String())
}

func startCustomWebSocketSocks5Server(
	t *testing.T,
	path string,
) (string, int) {
	t.Helper()

	return startCustomWebSocketSocks5ServerWithOptions(
		t,
		customWebSocketSocks5ServerOptions{
			path: path,
		},
	)
}

func exerciseCustomSocks5Proxy(
	t *testing.T,
	proxy *Socks5,
	targetAddr string,
) {
	t.Helper()

	targetHost, targetPort := customSplitHostPort(t, targetAddr)

	targetIP, err := netip.ParseAddr(targetHost)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(
		context.Background(),
		customSocksWSTestTimeout,
	)
	defer cancel()

	conn, err := proxy.DialContext(ctx, &C.Metadata{
		NetWork: C.TCP,
		DstIP:   targetIP,
		DstPort: uint16(targetPort),
	})
	require.NoError(t, err)
	defer conn.Close()

	// Prevent a transport regression from hanging the entire test process.
	timeout := time.AfterFunc(customSocksWSTestTimeout, func() {
		_ = conn.Close()
	})
	defer timeout.Stop()

	payload := []byte("mihomo-socks5-websocket-regression")

	_, err = conn.Write(payload)
	require.NoError(t, err)

	received := make([]byte, len(payload))

	_, err = io.ReadFull(conn, received)
	require.NoError(t, err)

	require.Equal(t, payload, received)
}

func TestSocks5WebSocketConnect(t *testing.T) {
	echoAddr := startCustomEchoServer(t)

	wsHost, wsPort := startCustomWebSocketSocks5Server(
		t,
		"/custom-socks-ws",
	)

	proxy, err := NewSocks5(Socks5Option{
		Name:    "custom-socks5-websocket-test",
		Server:  wsHost,
		Port:    wsPort,
		Network: "ws",
		WSOpts: WSOptions{
			Path: "/custom-socks-ws",
		},
	})
	require.NoError(t, err)

	exerciseCustomSocks5Proxy(t, proxy, echoAddr)
}

func TestSocks5WebSocketHostHeader(t *testing.T) {
	echoAddr := startCustomEchoServer(t)

	hostObserved := make(chan string, 1)

	const expectedHost = "custom-websocket-host.test"

	wsHost, wsPort := startCustomWebSocketSocks5ServerWithOptions(
		t,
		customWebSocketSocks5ServerOptions{
			path:         "/custom-socks-ws-host",
			observedHost: hostObserved,
		},
	)

	proxy, err := NewSocks5(Socks5Option{
		Name:    "custom-socks5-websocket-host-test",
		Server:  wsHost,
		Port:    wsPort,
		Network: "ws",
		WSOpts: WSOptions{
			Path: "/custom-socks-ws-host",
			Headers: map[string]string{
				"Host": expectedHost,
			},
		},
	})
	require.NoError(t, err)

	exerciseCustomSocks5Proxy(t, proxy, echoAddr)

	select {
	case actualHost := <-hostObserved:
		require.Equal(t, expectedHost, actualHost)
	case <-time.After(customSocksWSTestTimeout):
		t.Fatal("websocket Host header was not observed")
	}
}

func TestSocks5WebSocketTLS(t *testing.T) {
	echoAddr := startCustomEchoServer(t)

	wsHost, wsPort := startCustomWebSocketSocks5ServerWithOptions(
		t,
		customWebSocketSocks5ServerOptions{
			path:   "/custom-socks-wss",
			useTLS: true,
		},
	)

	proxy, err := NewSocks5(Socks5Option{
		Name:           "custom-socks5-websocket-tls-test",
		Server:         wsHost,
		Port:           wsPort,
		Network:        "ws",
		TLS:            true,
		SkipCertVerify: true,
		WSOpts: WSOptions{
			Path: "/custom-socks-wss",
		},
	})
	require.NoError(t, err)

	exerciseCustomSocks5Proxy(t, proxy, echoAddr)
}

func TestSocks5WebSocketAuthentication(t *testing.T) {
	echoAddr := startCustomEchoServer(t)

	const (
		username = "synthetic-user"
		password = "synthetic-password"
	)

	wsHost, wsPort := startCustomWebSocketSocks5ServerWithOptions(
		t,
		customWebSocketSocks5ServerOptions{
			path: "/custom-socks-ws-auth",
			authenticator: auth.NewAuthenticator([]auth.AuthUser{
				{
					User: username,
					Pass: password,
				},
			}),
		},
	)

	t.Run("accepts-valid-credentials", func(t *testing.T) {
		proxy, err := NewSocks5(Socks5Option{
			Name:     "custom-socks5-websocket-auth-success-test",
			Server:   wsHost,
			Port:     wsPort,
			UserName: username,
			Password: password,
			Network:  "ws",
			WSOpts: WSOptions{
				Path: "/custom-socks-ws-auth",
			},
		})
		require.NoError(t, err)

		exerciseCustomSocks5Proxy(t, proxy, echoAddr)
	})

	t.Run("rejects-invalid-password", func(t *testing.T) {
		proxy, err := NewSocks5(Socks5Option{
			Name:     "custom-socks5-websocket-auth-failure-test",
			Server:   wsHost,
			Port:     wsPort,
			UserName: username,
			Password: "incorrect-password",
			Network:  "ws",
			WSOpts: WSOptions{
				Path: "/custom-socks-ws-auth",
			},
		})
		require.NoError(t, err)

		targetHost, targetPort := customSplitHostPort(t, echoAddr)

		targetIP, err := netip.ParseAddr(targetHost)
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(
			context.Background(),
			customSocksWSTestTimeout,
		)
		defer cancel()

		conn, err := proxy.DialContext(ctx, &C.Metadata{
			NetWork: C.TCP,
			DstIP:   targetIP,
			DstPort: uint16(targetPort),
		})

		if conn != nil {
			_ = conn.Close()
		}

		require.Error(t, err)
		require.Contains(t, err.Error(), "rejected username/password")
	})
}

func TestSocks5TCPRegression(t *testing.T) {
	echoAddr := startCustomEchoServer(t)
	socksHost, socksPort := startCustomPlainSocks5Server(t)

	tests := []struct {
		name    string
		network string
	}{
		{
			name:    "default-network",
			network: "",
		},
		{
			name:    "explicit-tcp",
			network: "tcp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxy, err := NewSocks5(Socks5Option{
				Name:    "custom-socks5-tcp-regression-test",
				Server:  socksHost,
				Port:    socksPort,
				Network: tt.network,
			})
			require.NoError(t, err)

			exerciseCustomSocks5Proxy(t, proxy, echoAddr)
		})
	}
}

func TestSocks5WebSocketUDPRejected(t *testing.T) {
	proxy, err := NewSocks5(Socks5Option{
		Name:    "custom-socks5-websocket-udp-test",
		Server:  "127.0.0.1",
		Port:    1,
		Network: "ws",
		UDP:     true,
	})
	require.NoError(t, err)

	_, err = proxy.ListenPacketContext(
		context.Background(),
		&C.Metadata{
			NetWork: C.UDP,
			DstIP:   netip.MustParseAddr("127.0.0.1"),
			DstPort: 53,
		},
	)

	require.EqualError(
		t,
		err,
		"socks5 over websocket UDP is not supported yet",
	)
}
