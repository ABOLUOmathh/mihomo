package outbound

import (
	"bytes"
	"testing"

	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/sing/common/uot"
)

const heySocksXHTTPTestPassword = "abc:03010203"

func newHeySocksXHTTPTestProxy(
	t *testing.T,
	mutate func(
		*HeySocksXHTTPOption,
	),
) *HeySocksXHTTP {
	t.Helper()

	option := HeySocksXHTTPOption{
		Name:     "heysocks-xhttp-test",
		Server:   "127.0.0.1",
		Port:     443,
		Password: heySocksXHTTPTestPassword,
		Cipher:   "aes-128-ctr",
		UDP:      true,
	}

	if mutate != nil {
		mutate(&option)
	}

	proxy, err :=
		NewHeySocksXHTTP(option)
	if err != nil {
		t.Fatal(err)
	}

	return proxy
}

func TestHeySocksXHTTPConstructor(
	t *testing.T,
) {
	proxy :=
		newHeySocksXHTTPTestProxy(
			t,
			nil,
		)

	if proxy.Type() != C.HeySocksXHTTP {
		t.Fatalf(
			"unexpected adapter type: %v",
			proxy.Type(),
		)
	}

	if got := proxy.Type().String(); got != "HeySocksXHTTP" {
		t.Fatalf(
			"unexpected type string: %q",
			got,
		)
	}

	if got := proxy.Addr(); got != "127.0.0.1:443" {
		t.Fatalf(
			"unexpected addr: %q",
			got,
		)
	}

	if !proxy.SupportUDP() {
		t.Fatal(
			"UDP should be reported as supported",
		)
	}

	if proxy.SupportUOT() {
		t.Fatal(
			"UOT should be disabled by default",
		)
	}

	if proxy.ProxyInfo().XUDP {
		t.Fatal(
			"constructor-created XHTTP should default XUDP=false",
		)
	}
}

func TestHeySocksXHTTPDefaultCipher(
	t *testing.T,
) {
	proxy :=
		newHeySocksXHTTPTestProxy(
			t,
			func(
				option *HeySocksXHTTPOption,
			) {
				option.Cipher = ""
			},
		)

	if proxy.option.Cipher !=
		"aes-128-ctr" {
		t.Fatalf(
			"unexpected default cipher: %q",
			proxy.option.Cipher,
		)
	}
}

func TestHeySocksXHTTPRejectsUnknownCipher(
	t *testing.T,
) {
	_, err :=
		NewHeySocksXHTTP(
			HeySocksXHTTPOption{
				Name:     "bad-cipher",
				Server:   "127.0.0.1",
				Port:     443,
				Password: heySocksXHTTPTestPassword,
				Cipher:   "not-a-real-cipher",
			},
		)

	if err == nil {
		t.Fatal(
			"expected unsupported cipher error",
		)
	}
}

func TestHeySocksXHTTPKeepsUOTVersionZero(
	t *testing.T,
) {
	proxy :=
		newHeySocksXHTTPTestProxy(
			t,
			func(
				option *HeySocksXHTTPOption,
			) {
				option.UDPOverTCP = true
				option.UDPOverTCPVersion = 0
			},
		)

	if !proxy.SupportUOT() {
		t.Fatal(
			"UOT should be enabled",
		)
	}

	if proxy.option.UDPOverTCPVersion != 0 {
		t.Fatalf(
			"version 0 was unexpectedly normalized to %d",
			proxy.option.UDPOverTCPVersion,
		)
	}
}

func TestHeySocksXHTTPTCPDestination(
	t *testing.T,
) {
	proxy :=
		newHeySocksXHTTPTestProxy(
			t,
			nil,
		)

	metadata := &C.Metadata{
		NetWork: C.TCP,
		Host:    "example.com",
		DstPort: 443,
	}

	got, err :=
		proxy.streamDestination(
			metadata,
		)
	if err != nil {
		t.Fatal(err)
	}

	want :=
		serializesSocksAddr(
			metadata,
		)

	if !bytes.Equal(got, want) {
		t.Fatalf(
			"TCP destination mismatch:\ngot  %x\nwant %x",
			got,
			want,
		)
	}
}

func TestHeySocksXHTTPUOTDestination(
	t *testing.T,
) {
	tests := []struct {
		name    string
		version int
	}{
		{
			name:    "default-zero-current",
			version: 0,
		},
		{
			name: "legacy-one",
			version: int(
				uot.LegacyVersion,
			),
		},
		{
			name:    "explicit-current",
			version: 2,
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				proxy :=
					newHeySocksXHTTPTestProxy(
						t,
						func(
							option *HeySocksXHTTPOption,
						) {
							option.UDPOverTCP = true
							option.UDPOverTCPVersion =
								tt.version
						},
					)

				metadata :=
					&C.Metadata{
						NetWork: C.UDP,
						Host:    "target.example",
						DstPort: 53,
					}

				got, err :=
					proxy.streamDestination(
						metadata,
					)
				if err != nil {
					t.Fatal(err)
				}

				want, err :=
					serializeHeySocksXHTTPSocksaddr(
						uot.RequestDestination(
							uint8(
								tt.version,
							),
						),
					)
				if err != nil {
					t.Fatal(err)
				}

				if !bytes.Equal(
					got,
					want,
				) {
					t.Fatalf(
						"UOT destination mismatch for version %d:\ngot  %x\nwant %x",
						tt.version,
						got,
						want,
					)
				}
			},
		)
	}
}

func TestHeySocksXHTTPProxyInfoDialerProxy(
	t *testing.T,
) {
	proxy :=
		newHeySocksXHTTPTestProxy(
			t,
			func(
				option *HeySocksXHTTPOption,
			) {
				option.DialerProxy =
					"upstream-test-proxy"
			},
		)

	if got :=
		proxy.ProxyInfo().DialerProxy; got != "upstream-test-proxy" {
		t.Fatalf(
			"unexpected dialer proxy: %q",
			got,
		)
	}
}

func TestHeySocksXHTTPAllowsETrue(
	t *testing.T,
) {
	_, err :=
		NewHeySocksXHTTP(
			HeySocksXHTTPOption{
				Name:     "e-pass-through",
				Server:   "127.0.0.1",
				Port:     443,
				Password: heySocksXHTTPTestPassword,
				Cipher:   "aes-128-ctr",
				E:        true,
			},
		)

	if err != nil {
		t.Fatalf(
			"e:true should be accepted: %v",
			err,
		)
	}
}

func TestHeySocksXHTTPRejectsNonEmptyH(
	t *testing.T,
) {
	_, err :=
		NewHeySocksXHTTP(
			HeySocksXHTTPOption{
				Name:     "unsupported-h",
				Server:   "127.0.0.1",
				Port:     443,
				Password: heySocksXHTTPTestPassword,
				Cipher:   "aes-128-ctr",
				H:        "synthetic-h",
			},
		)

	if err == nil {
		t.Fatal(
			"expected unsupported H error",
		)
	}
}
