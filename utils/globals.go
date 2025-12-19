package utils

import (
	"net/url"
	"sync"

	"github.com/nadoo/glider/proxy"
)

// ProtoKind represents supported proxy protocol types.
type ProtoKind string

const (
	ProtoSocks5 ProtoKind = "socks5"
	ProtoHTTP   ProtoKind = "http"
	ProtoHTTPS  ProtoKind = "https"
	ProtoSS     ProtoKind = "ss"
	ProtoTrojan ProtoKind = "trojan"
	ProtoVLESS  ProtoKind = "vless"
	ProtoVMess  ProtoKind = "vmess"
)

// Endpoint is a normalized representation of a proxy entry from lastData.txt
// or remote discovery (FOFA/HUNTER/QUAKE).
type Endpoint struct {
	Raw    string    // original line as in lastData.txt (used for write-back and logging)
	Kind   ProtoKind // parsed protocol type
	URL    *url.URL  // normalized URL form
	Dialer proxy.Dialer
}

var (
	// SocksList keeps the raw entries collected from file/FOFA/QUAKE/HUNTER.
	SocksList []string

	// EffectiveList is kept for backward-compatible display and write-back,
	// it stores the Raw value of EffectiveEndpoints.
	EffectiveList []string

	// Endpoints holds all parsed endpoints from SocksList.
	Endpoints []Endpoint
	// EffectiveEndpoints holds endpoints that passed health checks.
	EffectiveEndpoints []Endpoint

	proxyIndex   int
	Timeout      int
	LastDataFile = "lastData.txt"
	Wg           sync.WaitGroup
	mu           sync.Mutex
	semaphore    chan struct{}

	// FailoverMode 故障切换模式：只有当前代理失败时才切换到下一个
	FailoverMode = false
)

// GetCurrentProxyIndex 获取当前代理索引
func GetCurrentProxyIndex() int {
	mu.Lock()
	defer mu.Unlock()
	return proxyIndex
}

// SetNextProxyIndex 设置下一个代理索引
func SetNextProxyIndex() {
	mu.Lock()
	defer mu.Unlock()
	if len(EffectiveList) > 0 {
		proxyIndex = (proxyIndex + 1) % len(EffectiveList)
	}
}

func Banner() {
	banner := `
   ____                        __                          ___      
  /\ $_$\                     /\ \                        /\_ \     
  \ \ \/\ \     __     __     \_\ \  _____     ___     ___\//\ \    
   \ \ \ \ \  /@__@\ /^__^\   />_< \/\ -__-\  /*__*\  /'__'\\ \ \   
    \ \ \_\ \/\  __//\ \_\.\_/\ \-\ \ \ \_\ \/\ \-\ \/\ \_\ \\-\ \_ 
     \ \____/\ \____\ \__/.\_\ \___,_\ \ ,__/\ \____/\ \____//\____\
      \/___/  \/____/\/__/\/_/\/__,_ /\ \ \/  \/___/  \/___/ \/____/
                                       \ \_\                        
                                        \/_/                        
`
	print(banner)
}
