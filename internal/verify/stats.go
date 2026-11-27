package verify

import (
	"net"
	"sync/atomic"
)

// dialFunc adapts a closure to proxy.Dialer so the SOCKS5 handshake can use a
// cancellable forward dialer.
type dialFunc func(network, addr string) (net.Conn, error)

func (f dialFunc) Dial(network, addr string) (net.Conn, error) { return f(network, addr) }

var (
	verifyDialInflight  atomic.Int64
	verifyDialLeaks     atomic.Int64
	verifyDialHarvested atomic.Int64
)

// DialStats reports the socks5 dial lifecycle: currently in-flight dials,
// dials abandoned because the caller's context/timeout fired, and sockets that
// were successfully closed after such an abandonment.
func DialStats() (inflight, abandoned, harvested int64) {
	return verifyDialInflight.Load(), verifyDialLeaks.Load(), verifyDialHarvested.Load()
}
