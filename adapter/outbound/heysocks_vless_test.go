package outbound

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"

	V "github.com/metacubex/mihomo/transport/vless"
)

type heySocksWriteResult struct {
	n   int
	err error
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString: %v", err)
	}

	return b
}

func TestVlessOptionHeySocksReachesCore(t *testing.T) {
	const uuidStr = "00112233-4455-6677-8899-aabbccddeeff"
	const hHex = "03aabbcc"

	proxy, err := NewVless(VlessOption{
		Name:   "heysocks-test",
		Server: "127.0.0.1",
		Port:   443,
		UUID:   uuidStr,
		E:      true,
		H:      hHex,
	})
	if err != nil {
		t.Fatalf("NewVless: %v", err)
	}

	dst := &V.DstAddr{
		UDP:      false,
		AddrType: V.AtypIPv4,
		Addr:     []byte{1, 2, 3, 4},
		Port:     443,
		Mux:      false,
	}

	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()

	deadline := time.Now().Add(5 * time.Second)
	if err := clientSide.SetDeadline(deadline); err != nil {
		t.Fatalf("client SetDeadline: %v", err)
	}
	if err := serverSide.SetDeadline(deadline); err != nil {
		t.Fatalf("server SetDeadline: %v", err)
	}

	conn, err := proxy.client.StreamConn(clientSide, dst)
	if err != nil {
		t.Fatalf("StreamConn: %v", err)
	}

	rawUUID := mustDecodeHex(
		t,
		"00112233445566778899aabbccddeeff",
	)
	sum := md5.Sum(rawUUID)

	want := mustDecodeHex(
		t,
		"00"+
			"00112233445566778899aabbccddeeff"+
			"00"+
			"01"+
			"01bb"+
			"01"+
			"01020304",
	)
	want = append(want, sum[:]...)
	want = append(want, mustDecodeHex(t, hHex)...)
	want = append(want, []byte("hello")...)

	writeCh := make(chan heySocksWriteResult, 1)

	go func() {
		n, err := conn.Write([]byte("hello"))
		writeCh <- heySocksWriteResult{n: n, err: err}
	}()

	got := make([]byte, len(want))
	if _, err := io.ReadFull(serverSide, got); err != nil {
		t.Fatalf("ReadFull request: %v", err)
	}

	wr := <-writeCh
	if wr.err != nil {
		t.Fatalf("Write: %v", wr.err)
	}
	if wr.n != len("hello") {
		t.Fatalf("Write returned n=%d, want %d", wr.n, len("hello"))
	}

	if !bytes.Equal(got, want) {
		t.Fatalf(
			"adapter HeySocks wire mismatch:\n got  %x\n want %x",
			got,
			want,
		)
	}
}

func TestVlessOptionHeySocksRejectsInvalidH(t *testing.T) {
	_, err := NewVless(VlessOption{
		Name:   "heysocks-invalid-h",
		Server: "127.0.0.1",
		Port:   443,
		UUID:   "00112233-4455-6677-8899-aabbccddeeff",
		H:      "zz",
	})

	if err == nil {
		t.Fatal("NewVless accepted invalid HeySocks H")
	}
}
