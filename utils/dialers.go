package utils

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/nadoo/glider/proxy"
)

var (
	baseDialerOnce sync.Once
	baseDialer     proxy.Dialer
	baseDialerErr  error

	dialerMu sync.Mutex
)

func createBaseDialer() (proxy.Dialer, error) {
	dialTimeout := 8 * time.Second
	if Timeout > 0 {
		dialTimeout = time.Duration(Timeout) * time.Second
	}
	relayTimeout := dialTimeout + 2*time.Second
	direct, err := proxy.NewDirect("", dialTimeout, relayTimeout)
	if err != nil {
		return nil, err
	}
	return direct, nil
}

func ensureBaseDialer() (proxy.Dialer, error) {
	baseDialerOnce.Do(func() {
		baseDialer, baseDialerErr = createBaseDialer()
	})
	return baseDialer, baseDialerErr
}

func ensureEndpointDialer(ep *Endpoint) error {
	if ep == nil {
		return fmt.Errorf("endpoint is nil")
	}
	if ep.Dialer != nil {
		return nil
	}
	dialerMu.Lock()
	defer dialerMu.Unlock()
	// double-check now that we hold the lock
	if ep.Dialer != nil {
		return nil
	}
	base, err := ensureBaseDialer()
	if err != nil {
		return fmt.Errorf("初始化基础连接器失败: %w", err)
	}
	dialer, err := proxy.DialerFromURL(ep.URL.String(), base)
	if err != nil {
		return fmt.Errorf("构建代理 %s 的拨号器失败: %w", ep.Raw, err)
	}
	ep.Dialer = dialer
	return nil
}

type dialResult struct {
	conn net.Conn
	err  error
}

func dialEndpoint(ctx context.Context, ep Endpoint, network, addr string, timeout time.Duration) (net.Conn, error) {
	if ep.Dialer == nil {
		return nil, fmt.Errorf("endpoint %s 缺少拨号器", ep.Raw)
	}
	resCh := make(chan dialResult, 1)
	done := make(chan struct{})
	go func() {
		conn, err := ep.Dialer.Dial(network, addr)
		select {
		case resCh <- dialResult{conn: conn, err: err}:
		case <-done:
			if conn != nil {
				conn.Close()
			}
		}
	}()
	defer close(done)

	if timeout <= 0 {
		timeout = time.Duration(Timeout) * time.Second
		if timeout <= 0 {
			timeout = 10 * time.Second
		}
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case res := <-resCh:
		if res.err == nil && timeout > 0 {
			_ = res.conn.SetDeadline(time.Now().Add(timeout))
		}
		return res.conn, res.err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, fmt.Errorf("dial %s via %s 超时(%v)", addr, ep.Raw, timeout)
	}
}
