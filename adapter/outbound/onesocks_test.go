package outbound

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func TestNewOneSocksDefaultsAndNativeUDP(t *testing.T) {
	outbound, err := NewOneSocks(
		OneSocksOption{
			Name:       "os-test",
			Server:     "127.0.0.1",
			Port:       443,
			Password:   "password",
			PaddingLen: "0-0",
			UDP:        true,
			UDPOverTCP: false,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if outbound.Type() != C.OneSocks {
		t.Fatalf(
			"type = %v, want %v",
			outbound.Type(),
			C.OneSocks,
		)
	}

	if outbound.Addr() != "127.0.0.1:443" {
		t.Fatalf(
			"addr = %q",
			outbound.Addr(),
		)
	}

	if outbound.option.Cipher != "aes-128-ctr" {
		t.Fatalf(
			"default cipher = %q",
			outbound.option.Cipher,
		)
	}

	if outbound.paddingLen != 0 {
		t.Fatalf(
			"padding = %d",
			outbound.paddingLen,
		)
	}

	if !outbound.SupportUDP() {
		t.Fatal("native UDP must be supported")
	}

	if outbound.SupportUOT() {
		t.Fatal("UOT must remain disabled when udp-over-tcp is false")
	}
}
