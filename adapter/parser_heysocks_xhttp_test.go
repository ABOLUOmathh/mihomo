package adapter

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func TestParseHeySocksXHTTPMinimal(
	t *testing.T,
) {
	mapping := map[string]any{
		"type":     "xhttp",
		"name":     "heysocks-xhttp-parser-minimal",
		"server":   "127.0.0.1",
		"port":     443,
		"password": "abc:03010203",
		"cipher":   "aes-128-ctr",
		"udp":      true,
	}

	proxy, err := ParseProxy(mapping)
	if err != nil {
		t.Fatal(err)
	}

	if proxy.Type() != C.HeySocksXHTTP {
		t.Fatalf(
			"unexpected adapter type: %v",
			proxy.Type(),
		)
	}

	if got := proxy.Name(); got != "heysocks-xhttp-parser-minimal" {
		t.Fatalf(
			"unexpected proxy name: %q",
			got,
		)
	}

	if !proxy.SupportUDP() {
		t.Fatal(
			"parsed XHTTP proxy should support UDP",
		)
	}

	if proxy.SupportUOT() {
		t.Fatal(
			"minimal XHTTP proxy should not enable UOT",
		)
	}
}

func TestParseHeySocksXHTTPGeneratedCompatibilityFields(
	t *testing.T,
) {
	// This deliberately resembles the clear/generated HeySocks form while
	// using only synthetic values.
	//
	// Fields such as tls, alpn, network and xhttp-opts are accepted as
	// compatibility/export metadata. They must not cause this top-level
	// type:xhttp proxy to be routed through Mihomo's VLESS XHTTP stack.
	mapping := map[string]any{
		"type":     "xhttp",
		"name":     "heysocks-xhttp-generated-shape",
		"server":   "127.0.0.1",
		"port":     443,
		"password": "abc:03010203",
		"cipher":   "aes-128-ctr",

		"udp":                  true,
		"udp-over-tcp":         true,
		"udp-over-tcp-version": 0,

		"padding-len": "8-64",
		"fake-net": map[string]any{
			"tcp": "",
			"udp": "",
		},

		"e":      false,
		"h":      "",
		"clover": 0,

		// Generated/export compatibility fields. These are intentionally
		// NOT consumed by the proprietary xstream implementation.
		"network":            "xhttp",
		"tls":                true,
		"alpn":               []any{"h2"},
		"client-fingerprint": "chrome",
		"encryption":         "",

		"xhttp-opts": map[string]any{
			"host": "synthetic.example",
			"path": "/synthetic-xhttp",
		},

		// Synthetic placeholders only. The native constructor's encrypted
		// sidecar mechanism is not implemented in this Mihomo compatibility
		// path because the direct decoded fields above are already present.
		"uuid":        "00000000-0000-0000-0000-000000000000",
		"certificate": "synthetic-certificate",
		"private-key": "synthetic-private-key",

		"dialer-proxy": "synthetic-upstream",
	}

	proxy, err := ParseProxy(mapping)
	if err != nil {
		t.Fatal(err)
	}

	if proxy.Type() != C.HeySocksXHTTP {
		t.Fatalf(
			"generated shape was routed to wrong adapter: %v",
			proxy.Type(),
		)
	}

	if got := proxy.Type().String(); got != "HeySocksXHTTP" {
		t.Fatalf(
			"unexpected adapter type string: %q",
			got,
		)
	}

	if !proxy.SupportUDP() {
		t.Fatal(
			"generated XHTTP proxy should support UDP",
		)
	}

	if !proxy.SupportUOT() {
		t.Fatal(
			"generated XHTTP proxy should report UOT support",
		)
	}

	info := proxy.ProxyInfo()

	if info.XUDP {
		t.Fatal(
			"constructor-created HeySocks XHTTP must default XUDP=false",
		)
	}

	if got := info.DialerProxy; got != "synthetic-upstream" {
		t.Fatalf(
			"unexpected dialer proxy: %q",
			got,
		)
	}
}

func TestParseHeySocksXHTTPRejectsUnknownCipher(
	t *testing.T,
) {
	mapping := map[string]any{
		"type":     "xhttp",
		"name":     "heysocks-xhttp-invalid-cipher",
		"server":   "127.0.0.1",
		"port":     443,
		"password": "abc:03010203",
		"cipher":   "not-a-real-cipher",
	}

	_, err := ParseProxy(mapping)

	if err == nil {
		t.Fatal(
			"expected unsupported XHTTP cipher to fail parsing",
		)
	}
}

func TestParseHeySocksXHTTPDoesNotHijackVlessXHTTP(
	t *testing.T,
) {
	// Guard the architectural boundary:
	// network:xhttp alone must never select the HeySocks adapter.
	mapping := map[string]any{
		"type":    "vless",
		"name":    "standard-vless-xhttp-boundary-test",
		"server":  "127.0.0.1",
		"port":    443,
		"uuid":    "00000000-0000-0000-0000-000000000000",
		"network": "xhttp",
	}

	proxy, err := ParseProxy(mapping)
	if err != nil {
		// A later VLESS transport validation error is acceptable here.
		// The important invariant is that type:vless is not interpreted
		// as HeySocksXHTTP.
		return
	}

	if proxy.Type() == C.HeySocksXHTTP {
		t.Fatal(
			"type:vless + network:xhttp was incorrectly routed to HeySocksXHTTP",
		)
	}
}
