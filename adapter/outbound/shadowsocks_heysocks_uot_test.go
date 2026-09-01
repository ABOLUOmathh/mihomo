package outbound

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/transport/shadowsocks/heysocks2022"
	"github.com/metacubex/sing/common/uot"
)

func testHeySocks2022Password() string {
	identity := base64.StdEncoding.EncodeToString(
		bytes.Repeat([]byte{0x11}, 16),
	)
	master := base64.StdEncoding.EncodeToString(
		bytes.Repeat([]byte{0x22}, 16),
	)

	return identity + ":" + master
}

func TestHeySocksBlackstoneUOTLegacy(t *testing.T) {
	basePassword := testHeySocks2022Password()

	ss, err := NewShadowSocks(ShadowSocksOption{
		Name:              "heysocks-blackstone-uot-test",
		Server:            "127.0.0.1",
		Port:              443,
		Cipher:            heysocks2022.MethodAES128GCM,
		Password:          basePassword + heysocks2022.BlackstoneSuffix,
		UDP:               true,
		UDPOverTCP:        true,
		UDPOverTCPVersion: uot.LegacyVersion,
	})
	if err != nil {
		t.Fatal(err)
	}

	if ss.heySocks2022 == nil {
		t.Fatal("BLACKSTONE did not enable HeySocks SS2022 compatibility")
	}

	if !ss.SupportUOT() {
		t.Fatal("BLACKSTONE UOT should be reported as supported")
	}

	if ss.option.UDPOverTCPVersion != uot.LegacyVersion {
		t.Fatalf(
			"UOT version = %d, want %d",
			ss.option.UDPOverTCPVersion,
			uot.LegacyVersion,
		)
	}

	if strings.HasSuffix(
		ss.option.Password,
		heysocks2022.BlackstoneSuffix,
	) {
		t.Fatal("BLACKSTONE marker was not stripped from the actual password")
	}

	if ss.option.Password != basePassword {
		t.Fatal("normalized BLACKSTONE password mismatch")
	}
}

func TestHeySocksBlackstoneWithoutUOT(t *testing.T) {
	ss, err := NewShadowSocks(ShadowSocksOption{
		Name:     "heysocks-blackstone-no-uot-test",
		Server:   "127.0.0.1",
		Port:     443,
		Cipher:   heysocks2022.MethodAES128GCM,
		Password: testHeySocks2022Password() + heysocks2022.BlackstoneSuffix,
		UDP:      true,
	})
	if err != nil {
		t.Fatal(err)
	}

	if ss.heySocks2022 == nil {
		t.Fatal("BLACKSTONE did not enable HeySocks SS2022 compatibility")
	}

	if ss.SupportUOT() {
		t.Fatal("UOT should not be reported when udp-over-tcp is disabled")
	}
}

func TestHeySocksExplicitEUOTLegacy(t *testing.T) {
	ss, err := NewShadowSocks(ShadowSocksOption{
		Name:              "heysocks-explicit-e-uot-test",
		Server:            "127.0.0.1",
		Port:              443,
		Cipher:            heysocks2022.MethodAES128GCM,
		Password:          testHeySocks2022Password(),
		E:                 true,
		UDP:               true,
		UDPOverTCP:        true,
		UDPOverTCPVersion: uot.LegacyVersion,
	})
	if err != nil {
		t.Fatal(err)
	}

	if ss.heySocks2022 == nil {
		t.Fatal("explicit e:true did not enable HeySocks SS2022 compatibility")
	}

	if !ss.SupportUOT() {
		t.Fatal("explicit e:true UOT should be supported")
	}
}

func TestHeySocksBlackstoneUOTDefaultsToLegacy(t *testing.T) {
	ss, err := NewShadowSocks(ShadowSocksOption{
		Name:       "heysocks-blackstone-default-uot-test",
		Server:     "127.0.0.1",
		Port:       443,
		Cipher:     heysocks2022.MethodAES128GCM,
		Password:   testHeySocks2022Password() + heysocks2022.BlackstoneSuffix,
		UDP:        true,
		UDPOverTCP: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	if ss.option.UDPOverTCPVersion != uot.LegacyVersion {
		t.Fatalf(
			"default UOT version = %d, want legacy version %d",
			ss.option.UDPOverTCPVersion,
			uot.LegacyVersion,
		)
	}

	if !ss.SupportUOT() {
		t.Fatal("BLACKSTONE default UOT should be supported")
	}
}
