package utils

import (
	"fmt"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
)

// GliderConnector represents a glider child process that listens on a local
// socks5 port and forwards traffic to a specific upstream Endpoint.
type GliderConnector struct {
	Endpoint Endpoint
	Port     int
	Cmd      *exec.Cmd
	closed   atomic.Bool
}

var (
	connMu     sync.Mutex
	connectors = make(map[string]*GliderConnector) // key: Endpoint.Raw
)

func (c *GliderConnector) IsClosed() bool {
	return c.closed.Load()
}

func (c *GliderConnector) markClosed() {
	c.closed.Store(true)
}

// Close terminates the glider process and releases its port.
func (c *GliderConnector) Close() error {
	if c == nil || c.IsClosed() {
		return nil
	}
	if c.Cmd != nil && c.Cmd.Process != nil {
		_ = c.Cmd.Process.Kill()
	}
	releasePort(c.Port)
	c.markClosed()
	return nil
}

// GetOrCreateConnector returns an existing connector for the given endpoint
// or starts a new glider child process if needed.
func GetOrCreateConnector(ep Endpoint) (*GliderConnector, error) {
	if ep.Kind == ProtoSocks5 {
		return nil, fmt.Errorf("socks5 endpoint does not need a glider connector")
	}
	if !IsGliderEnabled() {
		return nil, fmt.Errorf("glider 未启用或 glider 二进制不存在，无法处理非 socks5 协议: %s", ep.Raw)
	}

	key := ep.Raw

	connMu.Lock()
	defer connMu.Unlock()

	if c, ok := connectors[key]; ok && !c.IsClosed() {
		return c, nil
	}

	port, err := allocatePort()
	if err != nil {
		return nil, fmt.Errorf("分配本地端口失败: %w", err)
	}

	listenAddr := fmt.Sprintf("socks5://127.0.0.1:%d", port)
	forward := ep.URL.String()

	args := []string{
		"-listen", listenAddr,
		"-forward", forward,
	}
	if gliderCfg.Verbose {
		args = append(args, "-verbose")
	}

	cmd := exec.Command(gliderBinPath, args...)
	// 直接输出到标准输出/错误，便于排查问题；后续可考虑按需降噪
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		releasePort(port)
		return nil, fmt.Errorf("启动 glider 进程失败: %w", err)
	}

	c := &GliderConnector{
		Endpoint: ep,
		Port:     port,
		Cmd:      cmd,
	}

	// 监控子进程退出，自动释放资源
	go func() {
		if err := cmd.Wait(); err != nil {
			fmt.Printf("glider 进程退出（%s）: %v\n", ep.Raw, err)
		}
		c.markClosed()
		releasePort(port)
	}()

	connectors[key] = c
	return c, nil
}

// CleanupConnectors terminates all running glider connectors. It should be
// called on graceful program shutdown.
func CleanupConnectors() {
	connMu.Lock()
	defer connMu.Unlock()
	for key, c := range connectors {
		_ = c.Close()
		delete(connectors, key)
	}
}

