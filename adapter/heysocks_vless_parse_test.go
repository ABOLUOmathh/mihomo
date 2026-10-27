package adapter

import "testing"

func heySocksVlessParseMapping() map[string]any {
	return map[string]any{
		"name":    "heysocks-vless-parser-test",
		"type":    "vless",
		"server":  "127.0.0.1",
		"port":    443,
		"uuid":    "00112233-4455-6677-8899-aabbccddeeff",
		"network": "tcp",
	}
}

func TestParseProxyHeySocksVlessLegacy(t *testing.T) {
	mapping := heySocksVlessParseMapping()

	if _, err := ParseProxy(mapping); err != nil {
		t.Fatalf("legacy VLESS ParseProxy failed: %v", err)
	}
}

func TestParseProxyHeySocksVlessEH(t *testing.T) {
	mapping := heySocksVlessParseMapping()
	mapping["e"] = true
	mapping["h"] = "03aabbcc"

	if _, err := ParseProxy(mapping); err != nil {
		t.Fatalf("HeySocks VLESS ParseProxy failed: %v", err)
	}
}

func TestParseProxyHeySocksVlessRejectsInvalidH(t *testing.T) {
	mapping := heySocksVlessParseMapping()
	mapping["e"] = true
	mapping["h"] = "zz"

	if _, err := ParseProxy(mapping); err == nil {
		t.Fatal("ParseProxy unexpectedly accepted invalid HeySocks H")
	}
}
