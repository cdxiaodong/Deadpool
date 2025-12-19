package utils

import (
	"fmt"
	"os/exec"
	"sync"
)

var (
	gliderCfg       GliderConfig
	gliderBinPath   string
	gliderAvailable bool
	gliderOnce      sync.Once
)

// InitGlider initializes global glider configuration and detects whether
// the external "glider" binary is available. It is safe to call multiple
// times; the first non-zero config will be kept.
func InitGlider(cfg GliderConfig) {
	gliderOnce.Do(func() {
		gliderCfg = cfg

		// Basic sane defaults if config is partially omitted.
		if gliderCfg.LocalPortStart == 0 {
			gliderCfg.LocalPortStart = 55000
		}
		if gliderCfg.LocalPortEnd == 0 {
			gliderCfg.LocalPortEnd = 59999
		}
		if gliderCfg.MaxConnectors == 0 {
			gliderCfg.MaxConnectors = 128
		}
		if gliderCfg.StartTimeoutSec == 0 {
			gliderCfg.StartTimeoutSec = 5
		}
		if gliderCfg.MaxBackoffSec == 0 {
			gliderCfg.MaxBackoffSec = 30
		}

		// Resolve glider binary.
		if gliderCfg.Bin != "" {
			gliderBinPath = gliderCfg.Bin
			gliderAvailable = true
			return
		}

		path, err := exec.LookPath("glider")
		if err != nil {
			fmt.Println("未检测到 glider 可执行文件，非 socks5 协议将被跳过（仅使用纯 socks5 模式）")
			gliderAvailable = false
			return
		}
		gliderBinPath = path
		gliderAvailable = true
	})
}

// IsGliderEnabled returns whether glider integration is available.
func IsGliderEnabled() bool {
	return gliderAvailable
}

