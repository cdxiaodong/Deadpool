package utils

import (
	"fmt"
	"net"
	"sync"
)

// Simple in-process TCP port pool for glider connectors. It prefers ports
// in the configured [LocalPortStart, LocalPortEnd] range and ensures the
// port is currently free by trying to Listen() before returning it.

var (
	portMu   sync.Mutex
	usedPort = make(map[int]struct{})
)

// allocatePort finds a free TCP port on 127.0.0.1 within the configured range.
func allocatePort() (int, error) {
	portMu.Lock()
	defer portMu.Unlock()

	start := gliderCfg.LocalPortStart
	end := gliderCfg.LocalPortEnd
	if start <= 0 || end <= 0 || end < start {
		return 0, fmt.Errorf("invalid glider local port range: %d-%d", start, end)
	}

	for p := start; p <= end; p++ {
		if _, used := usedPort[p]; used {
			continue
		}
		addr := fmt.Sprintf("127.0.0.1:%d", p)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			continue
		}
		ln.Close()
		usedPort[p] = struct{}{}
		return p, nil
	}
	return 0, fmt.Errorf("no available ports in range %d-%d", start, end)
}

func releasePort(p int) {
	portMu.Lock()
	defer portMu.Unlock()
	delete(usedPort, p)
}

