package dns

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/buf"
	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/tls"
	D "github.com/miekg/dns"
)

type client struct {
	port           string
	host           string
	dialer         *dnsDialer
	transport      *plainTransport // for TCP and TLS
	schema         string
	skipCertVerify bool
}

var _ dnsClient = (*client)(nil)

// Address implements dnsClient
func (c *client) Address() string {
	return fmt.Sprintf("%s://%s", c.schema, net.JoinHostPort(c.host, c.port))
}

func (c *client) ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	switch c.schema {
	case "tcp", "tls":
		return c.transport.ExchangeContext(ctx, m)
	default: // "udp"
		return c.exchangeContextWithUDP(ctx, m)
	}
}

func (c *client) exchangeContextWithUDP(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	conn, err := c.dialContext(ctx, "udp")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// miekg/dns ExchangeContext doesn't respond to context cancel.
	// this is a workaround
	ch := make(chan result, 1)
	go func() {
		dClient := &D.Client{
			UDPSize: 4096,
			Timeout: 5 * time.Second,
		}
		dConn := &D.Conn{
			Conn:    conn,
			UDPSize: dClient.UDPSize,
		}

		msg, _, err := dClient.ExchangeWithConn(m, dConn)

		// Resolvers MUST resend queries over TCP if they receive a truncated UDP response (with TC=1 set)!
		if msg != nil && msg.Truncated {
			log.Debugln("[DNS] Truncated reply from %s:%s for %s over UDP, retrying over TCP", c.host, c.port, m.Question[0].String())
			var tcpConn net.Conn
			tcpConn, err = c.dialContext(ctx, "tcp")
			if err != nil {
				ch <- result{msg, err}
				return
			}
			defer tcpConn.Close()
			dConn.Conn = tcpConn
			msg, _, err = dClient.ExchangeWithConn(m, dConn)
		}

		ch <- result{msg, err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case ret := <-ch:
		return ret.Msg, ret.Error
	}
}

func (c *client) dialContext(ctx context.Context, network string) (net.Conn, error) {
	conn, err := c.dialer.DialContext(ctx, network, net.JoinHostPort(c.host, c.port))
	if err != nil {
		return nil, err
	}

	if c.schema == "tls" {
		tlsConfig, err := ca.GetTLSConfig(ca.Option{
			TLSConfig: &tls.Config{
				ServerName:         c.host,
				InsecureSkipVerify: c.skipCertVerify,
			},
		})
		if err != nil {
			return nil, err
		}
		tlsConn := tls.Client(conn, tlsConfig)
		if err = tlsConn.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		conn = tlsConn
	}

	return conn, nil
}

func (c *client) ResetConnection() {
	if c.transport != nil {
		c.transport.Close()
	}
}

func (c *client) createTransport() {
	c.transport = &plainTransport{
		client:  c,
		queries: make(map[uint16]chan<- result),
	}
}

type plainTransport struct {
	access     sync.Mutex
	sendAccess sync.Mutex
	client     *client
	queries    map[uint16]chan<- result
	conn       net.Conn
}

func (t *plainTransport) loopRead() {
	t.access.Lock()
	conn := t.conn
	t.access.Unlock()
	if conn == nil {
		return
	}
	dnsConn := &D.Conn{
		Conn: conn,
	}
	for {
		msg, err := dnsConn.ReadMsg()
		if msg != nil {
			t.access.Lock()
			receiver, loaded := t.queries[msg.Id]
			if loaded {
				delete(t.queries, msg.Id)
			}
			t.access.Unlock()
			if loaded {
				receiver <- result{msg, err}
				close(receiver)
			}
		} else if err != nil { // assume network failure
			log.Debugln("[DNS] Plain transport [%s] read loop error: %v", t.client.Address(), err)
			t.access.Lock()
			t.unsafeCloseWithError(err)
			t.access.Unlock()
			return
		}
	}
}

func (t *plainTransport) ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	buffer := buf.NewPacket()
	buffer.Advance(2)
	packed, err := m.PackBuffer(buffer.FreeBytes())
	if err != nil {
		buffer.Release()
		return nil, err
	}
	buffer.Truncate(len(packed))
	binary.BigEndian.PutUint16(buffer.ExtendHeader(2), uint16(len(packed)))

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	channel := make(chan result, 1)

	t.access.Lock()
	conn := t.conn
	if conn == nil {
		log.Debugln("[DNS] Plain transport dialing new connection to [%s]", t.client.Address())
		conn, err = t.client.dialContext(ctx, "tcp")
		if err != nil {
			t.access.Unlock()
			buffer.Release()
			return nil, err
		}
		t.conn = conn
		go t.loopRead()
	}
	t.queries[m.Id] = channel
	t.access.Unlock()

	t.sendAccess.Lock()
	_, err = conn.Write(buffer.Bytes())
	t.sendAccess.Unlock()
	buffer.Release()
	if err != nil {
		t.access.Lock()
		delete(t.queries, m.Id)
		t.access.Unlock()
		return nil, err
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r, ok := <-channel:
		if !ok { // should not happen. We should always send a result before abandoning a channel.
			return nil, context.Canceled
		}
		return r.Msg, r.Error
	}
}

// unsafeCloseWithReason closes the current connection (if connected), responds error to all
// ongoing queries and clear the query list.
//
// IMPORTANT: This is not concurrent-safe. Guard this with access lock.
func (t *plainTransport) unsafeCloseWithError(err error) {
	if t.conn != nil {
		t.conn.Close()
		t.conn = nil
	}
	for k, v := range t.queries {
		delete(t.queries, k)
		v <- result{nil, err}
		close(v)
	}
}

func (t *plainTransport) Close() error {
	t.access.Lock()
	t.unsafeCloseWithError(context.Canceled)
	t.access.Unlock()
	return nil
}

func newClient(addr string, resolver *Resolver, netType string, params map[string]string, proxyAdapter C.ProxyAdapter, proxyName string) *client {
	host, port, _ := net.SplitHostPort(addr)
	c := &client{
		port:   port,
		host:   host,
		dialer: newDNSDialer(resolver, proxyAdapter, proxyName),
		schema: "udp",
	}
	if strings.HasPrefix(netType, "tcp") {
		c.schema = "tcp"
		if strings.HasSuffix(netType, "tls") {
			c.schema = "tls"
			if params["skip-cert-verify"] == "true" {
				c.skipCertVerify = true
			}
		}
		c.createTransport()
	}
	return c
}
