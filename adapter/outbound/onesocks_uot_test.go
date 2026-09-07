package outbound

import (
	"bytes"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func TestOneSocksUOTDestinations(t *testing.T) {
	tests := []struct {
		version int
		domain  string
	}{
		{0, "sp.v2.udp-over-tcp.arpa"},
		{1, "sp.udp-over-tcp.arpa"},
		{2, "sp.v2.udp-over-tcp.arpa"},
	}

	for _, tt := range tests {
		outbound, err := NewOneSocks(
			OneSocksOption{
				Name:              "os-uot",
				Server:            "127.0.0.1",
				Port:              443,
				Password:          "password",
				UDP:               true,
				UDPOverTCP:        true,
				UDPOverTCPVersion: tt.version,
				PaddingLen:        "0-0",
			},
		)
		if err != nil {
			t.Fatalf(
				"version %d: %v",
				tt.version,
				err,
			)
		}

		got, err := outbound.streamDestination(
			&C.Metadata{
				NetWork: C.UDP,
			},
		)
		if err != nil {
			t.Fatal(err)
		}

		want := make(
			[]byte,
			0,
			2+len(tt.domain)+2,
		)

		want = append(
			want,
			0x03,
			byte(len(tt.domain)),
		)

		want = append(
			want,
			[]byte(tt.domain)...,
		)

		want = append(want, 0x00, 0x00)

		if !bytes.Equal(got, want) {
			t.Fatalf(
				"version %d destination = %x, want %x",
				tt.version,
				got,
				want,
			)
		}

		if !outbound.SupportUDP() {
			t.Fatalf(
				"version %d should advertise UDP",
				tt.version,
			)
		}

		if !outbound.SupportUOT() {
			t.Fatalf(
				"version %d should advertise UOT",
				tt.version,
			)
		}
	}
}

func TestOneSocksRejectInvalidUOTVersion(t *testing.T) {
	_, err := NewOneSocks(
		OneSocksOption{
			Name:              "os-uot-invalid",
			Server:            "127.0.0.1",
			Port:              443,
			Password:          "password",
			UDP:               true,
			UDPOverTCP:        true,
			UDPOverTCPVersion: 3,
		},
	)

	if err == nil {
		t.Fatal(
			"expected invalid UOT version error",
		)
	}
}

func TestOneSocksNativeUDPStillDisabled(t *testing.T) {
	outbound, err := NewOneSocks(
		OneSocksOption{
			Name:       "os-no-native-udp",
			Server:     "127.0.0.1",
			Port:       443,
			Password:   "password",
			UDP:        true,
			UDPOverTCP: false,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if outbound.SupportUDP() {
		t.Fatal(
			"native UDP must remain disabled",
		)
	}

	if outbound.SupportUOT() {
		t.Fatal(
			"UOT must be false",
		)
	}
}
