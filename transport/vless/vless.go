package vless

import (
	"encoding/hex"
	"net"
	"sync"

	"github.com/metacubex/mihomo/common/utils"

	"github.com/gofrs/uuid/v5"
)

const (
	XRO = "xtls-rprx-origin"
	XRD = "xtls-rprx-direct"
	XRS = "xtls-rprx-splice"
	XRV = "xtls-rprx-vision"

	Version byte = 0 // protocol version. preview version is 0
)

// Command types
const (
	CommandTCP byte = 1
	CommandUDP byte = 2
	CommandMux byte = 3
)

// Addr types
const (
	AtypIPv4       byte = 1
	AtypDomainName byte = 2
	AtypIPv6       byte = 3
)

// DstAddr store destination address
type DstAddr struct {
	UDP      bool
	AddrType byte
	Addr     []byte
	Port     uint16
	Mux      bool // currently used for XUDP only
}

// Client is vless connection generator
type Client struct {
	uuid   uuid.UUID
	Addons *Addons

	heySocksMu sync.RWMutex
	heySocksE  bool
	heySocksH  []byte
}

// ConfigureHeySocks enables the optional HeySocks VLESS compatibility fields.
// hHex is decoded once from configuration and kept as shared client state.
func (c *Client) ConfigureHeySocks(e bool, hHex string) error {
	var h []byte

	if hHex != "" {
		decoded, err := hex.DecodeString(hHex)
		if err != nil {
			return err
		}
		h = decoded
	}

	c.heySocksMu.Lock()
	c.heySocksE = e
	c.heySocksH = h
	c.heySocksMu.Unlock()

	return nil
}

func (c *Client) heySocksSnapshot() (bool, []byte) {
	c.heySocksMu.RLock()
	defer c.heySocksMu.RUnlock()

	if c.heySocksH == nil {
		return c.heySocksE, nil
	}

	h := make([]byte, len(c.heySocksH))
	copy(h, c.heySocksH)

	return c.heySocksE, h
}

func (c *Client) setHeySocksH(h []byte) {
	copyH := make([]byte, len(h))
	copy(copyH, h)

	c.heySocksMu.Lock()
	c.heySocksH = copyH
	c.heySocksMu.Unlock()
}

// StreamConn return a Conn with net.Conn and DstAddr
func (c *Client) StreamConn(conn net.Conn, dst *DstAddr) (net.Conn, error) {
	return newConn(conn, c, dst)
}

func (c *Client) PacketConn(conn net.Conn, rAddr net.Addr) net.PacketConn {
	return &PacketConn{conn, rAddr}
}

// NewClient return Client instance
func NewClient(uuidStr string, addons *Addons) (*Client, error) {
	uid := utils.UUIDMap(uuidStr)

	return &Client{
		uuid:   uid,
		Addons: addons,
	}, nil
}
