package utils

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// 防止goroutine 异步处理问题
var addSocksMu sync.Mutex

func addSocks(socks5 string) {
	addSocksMu.Lock()
	SocksList = append(SocksList, socks5)
	addSocksMu.Unlock()
}
func fetchContent(baseURL string, method string, timeout int, urlParams map[string]string, headers map[string]string, jsonBody string) (string, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: time.Duration(timeout) * time.Second,
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	if urlParams != nil {
		q := u.Query()
		for key, value := range urlParams {
			q.Set(key, value)
		}
		u.RawQuery = q.Encode()
	}

	var req *http.Request
	if jsonBody != "" {
		req, err = http.NewRequest(method, u.String(), bytes.NewBufferString(jsonBody))
	} else {
		req, err = http.NewRequest(method, u.String(), nil)
	}

	if err != nil {
		return "", err
	}
	req.Header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36 Edg/112.0.1722.17")
	if len(headers) != 0 {
		for key, value := range headers {
			req.Header.Add(key, value)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func RemoveDuplicates(list *[]string) {
	seen := make(map[string]struct{})
	var result []string
	for _, sock := range *list {
		if _, ok := seen[sock]; !ok {
			result = append(result, sock)
			seen[sock] = struct{}{}
		}
	}

	*list = result
}

// CheckSocks performs health checks for the given raw proxy list. It now
// supports multi-protocol URLs via Endpoint parsing. For non-socks5 protocols
// it relies on a local glider connector (when available).
func CheckSocks(checkSocks CheckSocksConfig, socksListParam []string) {
	startTime := time.Now()
	maxConcurrentReq := checkSocks.MaxConcurrentReq
	timeout := checkSocks.Timeout
	semaphore = make(chan struct{}, maxConcurrentReq)

	checkRspKeywords := checkSocks.CheckRspKeywords
	checkGeolocateConfig := checkSocks.CheckGeolocate
	checkGeolocateSwitch := checkGeolocateConfig.Switch
	isOpenGeolocateSwitch := false
	reqUrl := checkSocks.CheckURL
	if checkGeolocateSwitch == "open" {
		isOpenGeolocateSwitch = true
		reqUrl = checkGeolocateConfig.CheckURL
	}
	fmt.Printf("时间:[ %v ] 并发:[ %v ],超时标准:[ %vs ]\n", time.Now().Format("2006-01-02 15:04:05"), maxConcurrentReq, timeout)

	// Build Endpoint slice from raw list.
	endpoints := BuildEndpointsFromRaw(socksListParam)

	var num int
	total := len(endpoints)
	var tmpEffectiveList []string
	var tmpEffectiveEndpoints []Endpoint
	var tmpMu sync.Mutex
	for _, ep := range endpoints {

		Wg.Add(1)
		semaphore <- struct{}{}
		go func(ep Endpoint) {
			tmpMu.Lock()
			num++
			fmt.Printf("\r正检测第 [ %v/%v ] 个代理,异步处理中...                    ", num, total)
			tmpMu.Unlock()
			defer Wg.Done()
			defer func() {
				<-semaphore

			}()

			// Determine which socks5 endpoint to use for health checking.
			var proxyAddr string
			if ep.Kind == ProtoSocks5 {
				proxyAddr = ep.URL.Host
			} else {
				if !IsGliderEnabled() {
					// glider is not available, skip non-socks endpoints.
					return
				}
				connector, err := GetOrCreateConnector(ep)
				if err != nil {
					fmt.Printf("创建 glider connector 失败，跳过端点 %s: %v\n", ep.Raw, err)
					return
				}
				proxyAddr = fmt.Sprintf("127.0.0.1:%d", connector.Port)
			}

			socksProxy := "socks5://" + proxyAddr
			proxyFn := func(_ *http.Request) (*url.URL, error) {
				return url.Parse(socksProxy)
			}
			tr := &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				Proxy:           proxyFn,
			}
			client := &http.Client{
				Transport: tr,
				Timeout:   time.Duration(timeout) * time.Second,
			}
			req, err := http.NewRequest("GET", reqUrl, nil)
			if err != nil {
				return
			}
			req.Header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36 Edg/112.0.1722.17")
			req.Header.Add("referer", "https://www.baidu.com/s?ie=utf-8&f=8&rsv_bp=1&rsv_idx=1&tn=baidu&wd=ip&fenlei=256&rsv_pq=0xc23dafcc00076e78&rsv_t=6743gNBuwGYWrgBnSC7Yl62e52x3CKQWYiI10NeKs73cFjFpwmqJH%2FOI%2FSRG&rqlang=en&rsv_dl=tb&rsv_enter=1&rsv_sug3=5&rsv_sug1=5&rsv_sug7=101&rsv_sug2=0&rsv_btype=i&prefixsug=ip&rsp=4&inputT=2165&rsv_sug4=2719")
			resp, err := client.Do(req)
			if err != nil {
				// fmt.Printf("%v: %v\n", proxyAddr, err)
				// fmt.Printf("+++++++代理不可用：%v+++++++\n", proxyAddr)
				return
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				// fmt.Printf("%v: %v\n", proxyAddr, err)
				return
			}
			stringBody := string(body)
			if !isOpenGeolocateSwitch {
				if !strings.Contains(stringBody, checkRspKeywords) {
					return
				}
			} else {
				//直接循环要排除的关键字，任一命中就返回
				for _, keyword := range checkGeolocateConfig.ExcludeKeywords {
					if strings.Contains(stringBody, keyword) {
						// fmt.Println("忽略：" + proxyAddr + "包含：" + keyword.(string))
						return
					}
				}
				//直接循环要必须包含的关键字，任一未命中就返回
				for _, keyword := range checkGeolocateConfig.IncludeKeywords {
					if !strings.Contains(stringBody, keyword) {
						// fmt.Println("忽略：" + proxyAddr + "未包含：" + keyword.(string))
						return
					}
				}

			}
			tmpMu.Lock()
			tmpEffectiveList = append(tmpEffectiveList, ep.Raw)
			tmpEffectiveEndpoints = append(tmpEffectiveEndpoints, ep)
			tmpMu.Unlock()
		}(ep)
	}
	Wg.Wait()
	mu.Lock()
	EffectiveList = make([]string, len(tmpEffectiveList))
	copy(EffectiveList, tmpEffectiveList)
	EffectiveEndpoints = make([]Endpoint, len(tmpEffectiveEndpoints))
	copy(EffectiveEndpoints, tmpEffectiveEndpoints)
	proxyIndex = 0
	mu.Unlock()
	sec := int(time.Since(startTime).Seconds())
	if sec == 0 {
		sec = 1
	}
	fmt.Printf("\n根据配置规则检测完成,用时 [ %vs ] ,共发现 [ %v ] 个可用\n", sec, len(tmpEffectiveList))
}

func WriteLinesToFile() error {
	file, err := os.Create(LastDataFile)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	mu.Lock()
	defer mu.Unlock()
	for _, ep := range EffectiveEndpoints {
		line := ep.Raw
		if strings.TrimSpace(line) == "" {
			continue
		}
		if _, err := writer.WriteString(line + "\n"); err != nil {
			return err
		}
	}

	return writer.Flush()
}

func DefineDial(ctx context.Context, network, address string) (net.Conn, error) {

	return transmitReqFromClient(network, address)
}

func transmitReqFromClient(network string, address string) (net.Conn, error) {
	// 限制递归深度，避免无限递归
	const maxRetries = 10
	return transmitReqFromClientWithRetry(network, address, maxRetries)
}

func transmitReqFromClientWithRetry(network string, address string, retriesLeft int) (net.Conn, error) {
	if retriesLeft <= 0 {
		return nil, fmt.Errorf("所有代理都无效，无法建立连接")
	}

	ep := getNextEndpoint()
	if ep.Raw == "" && ep.URL == nil {
		return nil, fmt.Errorf("已无可用代理，请重新运行程序")
	}

	display := ep.Raw
	if display == "" && ep.URL != nil {
		display = ep.URL.String()
	}
	fmt.Println(time.Now().Format("2006-01-02 15:04:05") + "\t" + display)
	// 超时时间设置为 5 秒
	timeout := time.Duration(Timeout) * time.Second

	dialer := &net.Dialer{
		Timeout: timeout,
	}

	// Decide which socks5 we dial: direct upstream or local glider connector.
	var targetSocksAddr string
	if ep.Kind == ProtoSocks5 {
		targetSocksAddr = ep.URL.Host
	} else {
		connector, err := GetOrCreateConnector(ep)
		if err != nil {
			delInvalidEndpoint(ep)
			fmt.Printf("glider connector 错误: %v，自动切换下一个......\n", err)
			return transmitReqFromClientWithRetry(network, address, retriesLeft-1)
		}
		targetSocksAddr = fmt.Sprintf("127.0.0.1:%d", connector.Port)
	}

	dialect, _ := proxy.SOCKS5(network, targetSocksAddr, nil, dialer)
	conn, err := dialect.Dial(network, address)
	if err != nil {
		delInvalidEndpoint(ep)
		fmt.Printf("%s 无效，自动切换下一个......\n", display)
		return transmitReqFromClientWithRetry(network, address, retriesLeft-1)
	}

	return conn, nil
}

// getNextEndpoint returns the next effective endpoint in a round-robin fashion.
// It falls back to an "empty" Endpoint when the list is exhausted.
func getNextEndpoint() Endpoint {
	mu.Lock()
	defer mu.Unlock()
	if len(EffectiveList) == 0 {
		fmt.Println("***已无可用代理，请重新运行程序***")
		return Endpoint{}
	}
	if len(EffectiveList) <= 2 {
		fmt.Printf("***可用代理已仅剩%v个,%v，***\n", len(EffectiveList), EffectiveList)
	}
	if proxyIndex >= len(EffectiveList) {
		proxyIndex = 0 // 重置索引防止越界
	}
	// EffectiveList 与 EffectiveEndpoints 保持一一对应
	ep := EffectiveEndpoints[proxyIndex]
	proxyIndex = (proxyIndex + 1) % len(EffectiveList) // 循环访问
	return ep
}

// 使用过程中删除无效的代理
func delInvalidEndpoint(ep Endpoint) {
	mu.Lock()
	defer mu.Unlock()

	for i, raw := range EffectiveList {
		if raw == ep.Raw {
			EffectiveList = append(EffectiveList[:i], EffectiveList[i+1:]...)
			if i < len(EffectiveEndpoints) {
				EffectiveEndpoints = append(EffectiveEndpoints[:i], EffectiveEndpoints[i+1:]...)
			}
			// 调整 proxyIndex 以避免越界
			if i < proxyIndex {
				proxyIndex--
			} else if i == proxyIndex && proxyIndex >= len(EffectiveList) {
				proxyIndex = 0
			}
			break
		}
	}

	// 再次确保 proxyIndex 不越界
	if len(EffectiveList) > 0 && proxyIndex >= len(EffectiveList) {
		proxyIndex = proxyIndex % len(EffectiveList)
	}
}

func GetSocks(config Config) {
	GetSocksFromFile(LastDataFile)
	//从fofa获取
	Wg.Add(1)
	go GetSocksFromFofa(config.FOFA)
	//从hunter获取
	Wg.Add(1)
	go GetSocksFromHunter(config.HUNTER)
	//从quake中取
	Wg.Add(1)
	go GetSocksFromQuake(config.QUAKE)
	Wg.Wait()
	//根据IP:PORT去重，此步骤会存在同IP不同端口的情况，这种情况不再单独过滤，这种情况，最终的出口IP可能不一样
	RemoveDuplicates(&SocksList)
	// 建立 Endpoint 抽象，支持多协议 URL（vmess/vless/ss/trojan/http/https 等）
	BuildEndpointsFromRaw(SocksList)
}
