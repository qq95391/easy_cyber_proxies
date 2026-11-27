package verify

import (
	"context"
	"io"
	"net"
	"net/url"
	"testing"
	"time"
)

// TestSocksDialCancelClosesUnderlyingSocket reproduces the leak: a SOCKS5
// handshake that never answers must not leave the TCP socket ESTABLISHED after
// the caller's context expires.
func TestSocksDialCancelClosesUnderlyingSocket(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	peerClosed := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			peerClosed <- err
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 3)
		if _, err := io.ReadFull(conn, buf); err != nil {
			peerClosed <- err
			return
		}
		// Never answer the greeting; wait for the client to close.
		_, err = conn.Read(buf)
		peerClosed <- err
	}()

	target, _ := url.Parse("socks5://" + listener.Addr().String())
	transport, err := buildTransport(target, 300*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	if _, err := transport.DialContext(ctx, "tcp", "example.com:80"); err == nil {
		t.Fatal("dial must fail once the context expires")
	}

	select {
	case err := <-peerClosed:
		if err == nil {
			t.Fatal("expected the socket to be closed after cancellation")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("underlying socket was not closed; leak reproduced")
	}

	if _, abandoned, _ := DialStats(); abandoned < 1 {
		t.Fatalf("abandoned dial counter = %d, want >= 1", abandoned)
	}
}
