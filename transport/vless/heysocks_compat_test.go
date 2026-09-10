package vless_test

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/vless"
)

type writeResult struct {
	n   int
	err error
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString: %v", err)
	}

	return b
}

func testDst() *vless.DstAddr {
	return &vless.DstAddr{
		UDP:      false,
		AddrType: vless.AtypIPv4,
		Addr:     []byte{1, 2, 3, 4},
		Port:     443,
		Mux:      false,
	}
}

func setPipeDeadline(t *testing.T, conns ...net.Conn) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for _, conn := range conns {
		if err := conn.SetDeadline(deadline); err != nil {
			t.Fatalf("SetDeadline: %v", err)
		}
	}
}

func TestLegacyVLESSRequestWireUnchanged(t *testing.T) {
	const uuidStr = "00112233-4455-6677-8899-aabbccddeeff"

	client, err := vless.NewClient(uuidStr, nil)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	expected := mustHex(
		t,
		"00"+
			"00112233445566778899aabbccddeeff"+
			"00"+
			"01"+
			"01bb"+
			"01"+
			"01020304"+
			"68656c6c6f",
	)

	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()

	setPipeDeadline(t, clientSide, serverSide)

	conn, err := client.StreamConn(clientSide, testDst())
	if err != nil {
		t.Fatalf("StreamConn: %v", err)
	}

	writeCh := make(chan writeResult, 1)

	go func() {
		n, err := conn.Write([]byte("hello"))
		writeCh <- writeResult{n: n, err: err}
	}()

	got := make([]byte, len(expected))
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

	if !bytes.Equal(got, expected) {
		t.Fatalf(
			"legacy VLESS wire changed:\n got  %x\n want %x",
			got,
			expected,
		)
	}
}

func TestLegacyVLESSResponseDoesNotOverRead(t *testing.T) {
	const uuidStr = "00112233-4455-6677-8899-aabbccddeeff"

	client, err := vless.NewClient(uuidStr, nil)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()

	setPipeDeadline(t, clientSide, serverSide)

	conn, err := client.StreamConn(clientSide, testDst())
	if err != nil {
		t.Fatalf("StreamConn: %v", err)
	}

	serverWriteCh := make(chan error, 1)

	go func() {
		_, err := serverSide.Write([]byte{
			0x00, 0x00,
			0xaa, 0xbb, 0xcc,
		})
		serverWriteCh <- err
	}()

	got := make([]byte, 3)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("ReadFull response payload: %v", err)
	}

	if err := <-serverWriteCh; err != nil {
		t.Fatalf("server write: %v", err)
	}

	want := []byte{0xaa, 0xbb, 0xcc}
	if !bytes.Equal(got, want) {
		t.Fatalf(
			"legacy response over-read:\n got  %x\n want %x",
			got,
			want,
		)
	}
}

func captureRequest(
	t *testing.T,
	client *vless.Client,
	expectedLen int,
) []byte {
	t.Helper()

	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()

	setPipeDeadline(t, clientSide, serverSide)

	conn, err := client.StreamConn(clientSide, testDst())
	if err != nil {
		t.Fatalf("StreamConn: %v", err)
	}

	writeCh := make(chan writeResult, 1)

	go func() {
		n, err := conn.Write([]byte("hello"))
		writeCh <- writeResult{n: n, err: err}
	}()

	got := make([]byte, expectedLen)
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

	return got
}

func legacyPrefix(t *testing.T) []byte {
	t.Helper()

	return mustHex(
		t,
		"00"+
			"00112233445566778899aabbccddeeff"+
			"00"+
			"01"+
			"01bb"+
			"01"+
			"01020304",
	)
}

func rawUUIDMD5(t *testing.T) []byte {
	t.Helper()

	rawUUID := mustHex(
		t,
		"00112233445566778899aabbccddeeff",
	)

	sum := md5.Sum(rawUUID)
	return sum[:]
}

func TestHeySocksEOnlyRequest(t *testing.T) {
	const uuidStr = "00112233-4455-6677-8899-aabbccddeeff"

	client, err := vless.NewClient(uuidStr, nil)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if err := client.ConfigureHeySocks(true, ""); err != nil {
		t.Fatalf("ConfigureHeySocks: %v", err)
	}

	want := append([]byte{}, legacyPrefix(t)...)
	want = append(want, rawUUIDMD5(t)...)
	want = append(want, []byte("hello")...)

	got := captureRequest(t, client, len(want))

	if !bytes.Equal(got, want) {
		t.Fatalf(
			"E-only request mismatch:\n got  %x\n want %x",
			got,
			want,
		)
	}
}

func TestHeySocksHOnlyRequest(t *testing.T) {
	const uuidStr = "00112233-4455-6677-8899-aabbccddeeff"
	const hHex = "03aabbcc"

	client, err := vless.NewClient(uuidStr, nil)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if err := client.ConfigureHeySocks(false, hHex); err != nil {
		t.Fatalf("ConfigureHeySocks: %v", err)
	}

	h := mustHex(t, hHex)

	want := append([]byte{}, legacyPrefix(t)...)
	want = append(want, h...)
	want = append(want, []byte("hello")...)

	got := captureRequest(t, client, len(want))

	if !bytes.Equal(got, want) {
		t.Fatalf(
			"H-only request mismatch:\n got  %x\n want %x",
			got,
			want,
		)
	}
}

func TestHeySocksEAndHRequest(t *testing.T) {
	const uuidStr = "00112233-4455-6677-8899-aabbccddeeff"
	const hHex = "03aabbcc"

	client, err := vless.NewClient(uuidStr, nil)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if err := client.ConfigureHeySocks(true, hHex); err != nil {
		t.Fatalf("ConfigureHeySocks: %v", err)
	}

	want := append([]byte{}, legacyPrefix(t)...)
	want = append(want, rawUUIDMD5(t)...)
	want = append(want, mustHex(t, hHex)...)
	want = append(want, []byte("hello")...)

	got := captureRequest(t, client, len(want))

	if !bytes.Equal(got, want) {
		t.Fatalf(
			"E+H request mismatch:\n got  %x\n want %x",
			got,
			want,
		)
	}
}

func exerciseHeySocksResponse(
	t *testing.T,
	client *vless.Client,
	response []byte,
) {
	t.Helper()

	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()

	setPipeDeadline(t, clientSide, serverSide)

	conn, err := client.StreamConn(clientSide, testDst())
	if err != nil {
		t.Fatalf("StreamConn: %v", err)
	}

	writeCh := make(chan error, 1)

	go func() {
		_, err := serverSide.Write(response)
		writeCh <- err
	}()

	payload := make([]byte, 1)
	if _, err := io.ReadFull(conn, payload); err != nil {
		t.Fatalf("ReadFull application payload: %v", err)
	}

	if err := <-writeCh; err != nil {
		t.Fatalf("server write: %v", err)
	}

	if payload[0] != 0x99 {
		t.Fatalf(
			"application payload=%02x, want 99",
			payload[0],
		)
	}
}

func TestHeySocksResponseUpdatesH(t *testing.T) {
	const uuidStr = "00112233-4455-6677-8899-aabbccddeeff"

	client, err := vless.NewClient(uuidStr, nil)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if err := client.ConfigureHeySocks(false, "03aabbcc"); err != nil {
		t.Fatalf("ConfigureHeySocks: %v", err)
	}

	exerciseHeySocksResponse(
		t,
		client,
		[]byte{
			0x00, 0x00,
			0x02, 0xde, 0xad,
			0x99,
		},
	)

	want := append([]byte{}, legacyPrefix(t)...)
	want = append(want, 0x02, 0xde, 0xad)
	want = append(want, []byte("hello")...)

	got := captureRequest(t, client, len(want))

	if !bytes.Equal(got, want) {
		t.Fatalf(
			"updated H not used by next connection:\n got  %x\n want %x",
			got,
			want,
		)
	}
}

func TestHeySocksResponseZeroLengthPreservesH(t *testing.T) {
	const uuidStr = "00112233-4455-6677-8899-aabbccddeeff"
	const hHex = "03aabbcc"

	client, err := vless.NewClient(uuidStr, nil)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if err := client.ConfigureHeySocks(false, hHex); err != nil {
		t.Fatalf("ConfigureHeySocks: %v", err)
	}

	exerciseHeySocksResponse(
		t,
		client,
		[]byte{
			0x00, 0x00,
			0x00,
			0x99,
		},
	)

	want := append([]byte{}, legacyPrefix(t)...)
	want = append(want, mustHex(t, hHex)...)
	want = append(want, []byte("hello")...)

	got := captureRequest(t, client, len(want))

	if !bytes.Equal(got, want) {
		t.Fatalf(
			"HLen=0 should preserve old H:\n got  %x\n want %x",
			got,
			want,
		)
	}
}
