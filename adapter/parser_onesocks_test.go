package adapter

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func TestParseOneSocksMinimalTCP(t *testing.T) {
	mapping := map[string]any{
		"type":        "os",
		"name":        "onesocks-parser-tcp",
		"server":      "127.0.0.1",
		"port":        443,
		"password":    "password",
		"cipher":      "aes-128-ctr",
		"padding-len": "0-0",
	}

	proxy, err := ParseProxy(mapping)
	if err != nil {
		t.Fatal(err)
	}

	if proxy.Type() != C.OneSocks {
		t.Fatalf(
			"unexpected adapter type: %v",
			proxy.Type(),
		)
	}

	if got := proxy.Type().String(); got != "OneSocks" {
		t.Fatalf(
			"unexpected adapter type string: %q",
			got,
		)
	}

	if got := proxy.Name(); got != "onesocks-parser-tcp" {
		t.Fatalf(
			"unexpected proxy name: %q",
			got,
		)
	}

	if proxy.SupportUDP() {
		t.Fatal(
			"TCP-only OneSocks must not advertise UDP",
		)
	}

	if proxy.SupportUOT() {
		t.Fatal(
			"TCP-only OneSocks must not advertise UOT",
		)
	}
}

func TestParseOneSocksUOTVersions(t *testing.T) {
	versions := []int{0, 1, 2}

	for _, version := range versions {
		mapping := map[string]any{
			"type":     "os",
			"name":     "onesocks-parser-uot",
			"server":   "127.0.0.1",
			"port":     443,
			"password": "password",

			"cipher":      "aes-128-ctr",
			"padding-len": "8-64",

			"udp":                  true,
			"udp-over-tcp":         true,
			"udp-over-tcp-version": version,

			"e": true,
			"h": "",
		}

		proxy, err := ParseProxy(mapping)
		if err != nil {
			t.Fatalf(
				"version %d: %v",
				version,
				err,
			)
		}

		if proxy.Type() != C.OneSocks {
			t.Fatalf(
				"version %d routed to wrong adapter: %v",
				version,
				proxy.Type(),
			)
		}

		if !proxy.SupportUDP() {
			t.Fatalf(
				"version %d should advertise UDP",
				version,
			)
		}

		if !proxy.SupportUOT() {
			t.Fatalf(
				"version %d should advertise UOT",
				version,
			)
		}
	}
}

func TestParseOneSocksGeneratedCompatibilityFields(t *testing.T) {
	mapping := map[string]any{
		"type":        "os",
		"name":        "onesocks-generated-shape",
		"server":      "127.0.0.1",
		"port":        443,
		"password":    "password",
		"cipher":      "aes-128-ctr",
		"padding-len": "8-64",

		"udp":                  true,
		"udp-over-tcp":         true,
		"udp-over-tcp-version": 0,

		// Present in native HeySocks BasicOption.
		"e": true,
		"h": "",

		// Deliberately unrelated/generated compatibility metadata.
		// This test determines actual decoder behavior for unused keys.
		"network":            "tcp",
		"tls":                true,
		"alpn":               []any{"h2"},
		"client-fingerprint": "chrome",
		"uuid":               "00000000-0000-0000-0000-000000000000",
		"certificate":        "synthetic-certificate",
		"private-key":        "synthetic-private-key",
	}

	proxy, err := ParseProxy(mapping)
	if err != nil {
		t.Fatal(err)
	}

	if proxy.Type() != C.OneSocks {
		t.Fatalf(
			"generated shape routed to wrong adapter: %v",
			proxy.Type(),
		)
	}

	if !proxy.SupportUOT() {
		t.Fatal(
			"generated OneSocks shape should retain UOT",
		)
	}
}

func TestParseOneSocksRejectsUnknownCipher(t *testing.T) {
	mapping := map[string]any{
		"type":     "os",
		"name":     "onesocks-invalid-cipher",
		"server":   "127.0.0.1",
		"port":     443,
		"password": "password",
		"cipher":   "not-a-real-cipher",
	}

	_, err := ParseProxy(mapping)

	if err == nil {
		t.Fatal(
			"expected unsupported OneSocks cipher to fail parsing",
		)
	}
}

func TestParseOneSocksRejectsInvalidUOTVersion(t *testing.T) {
	mapping := map[string]any{
		"type":                 "os",
		"name":                 "onesocks-invalid-uot",
		"server":               "127.0.0.1",
		"port":                 443,
		"password":             "password",
		"udp":                  true,
		"udp-over-tcp":         true,
		"udp-over-tcp-version": 3,
	}

	_, err := ParseProxy(mapping)

	if err == nil {
		t.Fatal(
			"expected invalid OneSocks UOT version to fail parsing",
		)
	}
}
