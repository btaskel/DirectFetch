package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ProgressWriter struct {
	writer         io.Writer
	total          int64
	written        int64
	newlyWritten   int64
	startTime      time.Time
	lastUpdateTime time.Time
	lock           sync.Mutex
	filename       string
}

// NewProgressWriter 创建一个新的 ProgressWriter
// initialWritten 是续传前文件已存在的大小
func NewProgressWriter(w io.Writer, total int64, initialWritten int64, filename string) *ProgressWriter {
	return &ProgressWriter{
		writer:    w,
		total:     total,
		written:   initialWritten, // 从已存在的大小开始
		startTime: time.Now(),
		filename:  filename,
	}
}

// Write 实现 io.Writer 接口
func (pw *ProgressWriter) Write(p []byte) (n int, err error) {
	n, err = pw.writer.Write(p) // 写入底层 Writer
	if err == nil {
		pw.lock.Lock()
		pw.written += int64(n)      // 更新总写入量
		pw.newlyWritten += int64(n) // 更新本次新写入量
		now := time.Now()
		// 每秒更新一次进度，或者在最后一次写入时更新
		// 或者数据量很小的时候立刻更新
		if now.Sub(pw.lastUpdateTime) > time.Second || (pw.total > 0 && pw.written == pw.total) || pw.newlyWritten < 1024*10 {
			pw.printProgress()
			pw.lastUpdateTime = now
		}
		pw.lock.Unlock()
	}
	return n, err
}

// printProgress 打印当前的下载进度
func (pw *ProgressWriter) printProgress() {
	percentage := float64(0)
	// 只有在 total 已知时才计算百分比
	if pw.total > 0 {
		percentage = float64(pw.written) / float64(pw.total) * 100
	} else if pw.written > 0 {

		percentage = -1
	}

	elapsed := time.Since(pw.startTime).Seconds()
	speed := float64(0)

	if elapsed > 0 && pw.newlyWritten > 0 {
		speed = float64(pw.newlyWritten) / elapsed // Bytes per second
	}

	progressStr := fmt.Sprintf("\r下载 %s: %s / %s",
		pw.filename,
		formatBytes(pw.written),
		formatBytes(pw.total),
	)
	if percentage >= 0 {
		progressStr += fmt.Sprintf(" (%.2f%%)", percentage)
	} else {
		progressStr += " (?%)"
	}
	progressStr += fmt.Sprintf(" @ %s/s", formatBytes(int64(speed))) // 速度

	fmt.Print(progressStr + "        ")

	if pw.total > 0 && pw.written >= pw.total {
		fmt.Println()
	}
}

func formatBytes(bytes int64) string {
	if bytes < 0 {
		return "N/A"
	}
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

type Config struct {
	SNI       string `json:"sni"` // 注意：此字段仍需在 DialTLSContext 中正确使用 hostname
	TargetURL string `json:"target_url"`
}

var config = Config{}

func initConfig() {
	_config := Config{
		SNI:       "cn.bing.com",
		TargetURL: "https://example.com",
	}
	configBuf, err := json.Marshal(_config)
	if err != nil {
		panic(err)
	}
	f, err := os.Create("config.json")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	_, err = f.Write(configBuf)
	if err != nil {
		panic(err)
	}
}

func readConfig() error {
	file, err := os.Open("config.json")
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("提示：config.json 文件不存在，将仅使用命令行参数指定的 URL。")
			initConfig()
			return nil
		}
		return fmt.Errorf("打开 config.json 失败: %w", err)
	}
	defer file.Close()
	buf, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("读取 config.json 失败: %w", err)
	}
	err = json.Unmarshal(buf, &config)
	if err != nil {
		return fmt.Errorf("解析 config.json 失败: %w", err)
	}
	fmt.Println("从 config.json 加载配置成功。")
	return nil
}

func setArgs() error {
	args := os.Args
	if len(args) > 1 {
		fmt.Printf("从命令行参数获取目标 URL：%s\n", args[1])
		config.TargetURL = args[1]
		return nil
	} else if config.TargetURL == "" {
		return fmt.Errorf("错误：需要指定下载 URL。可以通过 config.json 或命令行参数提供")
	}
	fmt.Printf("使用配置文件中的目标 URL：%s\n", config.TargetURL)
	return nil
}

// --- 辅助函数：解析 Content-Range ---
// 示例: "bytes 21010-47021/47022" -> start=21010, end=47021, total=47022
func parseContentRange(rangeHeader string) (start, end, total int64, err error) {
	const errPrefix = "解析 Content-Range 失败"
	// 移除 "bytes " 前缀
	if !strings.HasPrefix(rangeHeader, "bytes ") {
		return -1, -1, -1, fmt.Errorf("%s: 缺少 'bytes ' 前缀", errPrefix)
	}
	rangePart := strings.TrimPrefix(rangeHeader, "bytes ")

	// 分割范围和总大小 "21010-47021/47022"
	parts := strings.Split(rangePart, "/")
	if len(parts) != 2 {
		return -1, -1, -1, fmt.Errorf("%s: 无法分割范围和总大小", errPrefix)
	}

	// 解析总大小
	total, err = strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return -1, -1, -1, fmt.Errorf("%s: 解析总大小 '%s' 失败: %w", errPrefix, parts[1], err)
	}

	// 解析范围 "21010-47021"
	rangeParts := strings.Split(parts[0], "-")
	if len(rangeParts) != 2 {
		return -1, -1, total, fmt.Errorf("%s: 无法分割起始和结束字节", errPrefix)
	}

	start, err = strconv.ParseInt(rangeParts[0], 10, 64)
	if err != nil {
		return -1, -1, total, fmt.Errorf("%s: 解析起始字节 '%s' 失败: %w", errPrefix, rangeParts[0], err)
	}
	end, err = strconv.ParseInt(rangeParts[1], 10, 64)
	if err != nil {
		return -1, end, total, fmt.Errorf("%s: 解析结束字节 '%s' 失败: %w", errPrefix, rangeParts[1], err)
	}

	return start, end, total, nil
}

// --- 主下载逻辑 (添加断点续传) ---
func downloadFileWithProgress() error {
	// 1. 解析 URL (保持不变)
	parsedURL, err := url.Parse(config.TargetURL)
	if err != nil {
		return fmt.Errorf("错误：无法解析 URL '%s': %v", config.TargetURL, err)
	}

	hostname := parsedURL.Hostname()
	port := "443"

	// *** 新增：提前确定文件名 ***
	_, filename := filepath.Split(parsedURL.Path)
	decodedFilename, err := url.PathUnescape(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "警告：无法解码文件名 '%s': %v，将使用原始名称\n", filename, err)
		decodedFilename = filename
	}
	if decodedFilename == "" || strings.HasSuffix(decodedFilename, "/") {
		decodedFilename = "downloaded_file"
	}
	fmt.Printf("目标文件名：%s\n", decodedFilename)

	// *** 新增：检查本地文件状态 ***
	var existingSize int64 = 0
	fileInfo, err := os.Stat(decodedFilename)
	if err == nil {
		// 文件存在
		existingSize = fileInfo.Size()
		fmt.Printf("找到本地文件 '%s'，大小：%s\n", decodedFilename, formatBytes(existingSize))
	} else if !errors.Is(err, os.ErrNotExist) {
		// 其他 Stat 错误 (权限等)
		return fmt.Errorf("错误：检查本地文件 '%s' 状态失败: %v", decodedFilename, err)
	} // 如果是 os.ErrNotExist，则 existingSize 保持为 0

	// 2. 解析 IP 地址 (保持不变)
	fmt.Printf("正在解析主机名 %s 的 IP 地址...\n", hostname)
	ips, err := net.LookupIP(hostname)
	if err != nil || len(ips) == 0 {
		return fmt.Errorf("错误：无法解析主机 %s 的 IP 地址: %v", hostname, err)
	}
	var targetIP string
	for _, ip := range ips {
		if ip.To4() != nil {
			targetIP = ip.String()
			break
		}
	}
	if targetIP == "" {
		targetIP = ips[0].String()
	}
	fmt.Printf("找到 IP 地址：%s\n", targetIP)

	// 3. 创建自定义 Transport (注意 SNI)
	transport := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			ipAddr := net.JoinHostPort(targetIP, port)
			// fmt.Printf("尝试直接连接到 IP 地址：%s\n", ipAddr)

			dialer := &net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}
			tcpConn, err := dialer.DialContext(ctx, "tcp", ipAddr)
			if err != nil {
				return nil, fmt.Errorf("无法建立 TCP 连接到 %s: %w", ipAddr, err)
			}

			// !! 关键：ServerName 应为目标网站的主机名，用于 SNI 和证书验证
			// !! 如果 config.SNI 有效且需要覆盖，可以用 config.SNI，否则用 hostname
			sniHost := hostname
			if config.SNI != "" {
				fmt.Printf("警告：使用配置文件中的 SNI: %s 覆盖从 URL 解析的主机名: %s\n", config.SNI, hostname)
				sniHost = config.SNI
			}
			tlsConfig := &tls.Config{
				ServerName:         sniHost, // 正确设置 SNI
				MinVersion:         tls.VersionTLS12,
				InsecureSkipVerify: true, // 保持注释，除非明确需要
			}

			// fmt.Printf("正在与 %s (SNI: %s) 进行 TLS 握手...\n", ipAddr, sniHost)
			tlsConn := tls.Client(tcpConn, tlsConfig)
			err = tlsConn.HandshakeContext(ctx)
			if err != nil {
				tcpConn.Close()
				return nil, fmt.Errorf("TLS 握手失败: %w", err)
			}
			// fmt.Println("TLS 握手成功！")
			return tlsConn, nil
		},
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	// 4. 创建 HTTP 客户端 (保持不变)
	client := &http.Client{
		Transport: transport,
		Timeout:   0,
	}

	// 5. 创建 HTTP 请求 (添加 Range Header)
	req, err := http.NewRequestWithContext(context.Background(), "GET", config.TargetURL, nil)
	if err != nil {
		return fmt.Errorf("错误：无法创建 HTTP 请求: %v", err)
	}

	req.Host = hostname // Host 头仍然是原始主机名
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Connection", "keep-alive")

	// *** 新增：添加 Range 请求头 ***
	if existingSize > 0 {
		rangeHeader := fmt.Sprintf("bytes=%d-", existingSize)
		req.Header.Set("Range", rangeHeader)
		fmt.Printf("添加 Range 请求头：%s\n", rangeHeader)
	}

	// 6. 发送请求
	fmt.Println("正在发送 HTTP GET 请求...")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("错误：发送 HTTP 请求失败: %v", err)
	}
	defer resp.Body.Close()

	fmt.Printf("收到响应状态：%s\n", resp.Status)

	// *** 新增：处理不同的响应状态码 ***
	var totalSize int64 = -1 // 初始化为未知
	var outputFlags int      // 文件打开标志

	switch resp.StatusCode {
	case http.StatusOK: // 200 OK
		fmt.Println("服务器返回 200 OK。")
		if existingSize > 0 {
			// 服务器不支持 Range 或忽略了 Range 请求，从头开始下载
			fmt.Println("警告：服务器不支持 Range 请求或已忽略。将重新从头下载文件。")
			existingSize = 0                                     // 重置 existingSize，表示从头开始
			outputFlags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC // 覆盖模式
		} else {
			// 正常从头开始下载
			outputFlags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC // 覆盖模式
		}
		// 尝试从 Content-Length 获取总大小
		totalSizeStr := resp.Header.Get("Content-Length")
		parsedSize, parseErr := strconv.ParseInt(totalSizeStr, 10, 64)
		if parseErr == nil && parsedSize > 0 {
			totalSize = parsedSize
		} else {
			fmt.Println("警告：无法从 Content-Length 获取有效文件总大小。")
			totalSize = -1
		}

	case http.StatusPartialContent: // 206 Partial Content
		fmt.Println("服务器返回 206 Partial Content，支持断点续传。")
		if existingSize == 0 {
			// 服务器返回 206 但我们没有请求 Range? 这很奇怪，按从头下载处理
			fmt.Println("警告：收到 206 但未请求 Range，将尝试从头下载。")
			outputFlags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC // 覆盖模式
		} else {
			// 正常的断点续传响应
			outputFlags = os.O_WRONLY | os.O_CREATE | os.O_APPEND // 追加模式
		}
		// 从 Content-Range 获取总大小
		contentRange := resp.Header.Get("Content-Range")
		if contentRange == "" {
			return fmt.Errorf("错误：收到 206 但缺少 Content-Range 响应头")
		}
		_, _, parsedTotal, parseErr := parseContentRange(contentRange)
		if parseErr != nil {
			return fmt.Errorf("错误：解析 Content-Range ('%s') 失败: %v", contentRange, parseErr)
		}
		totalSize = parsedTotal
		// 可以在这里添加对 range start 的校验，看是否等于 existingSize

	case http.StatusRequestedRangeNotSatisfiable: // 416 Range Not Satisfiable
		fmt.Println("服务器返回 416 Range Not Satisfiable。")
		if existingSize > 0 {
			// 这通常意味着本地文件已经等于或超过服务器文件大小
			// 我们可以尝试获取文件信息来确认
			headReq, headErr := http.NewRequest("HEAD", config.TargetURL, nil)
			if headErr == nil {
				headReq.Host = hostname // Set Host header for HEAD request too
				headResp, headDoErr := client.Do(headReq)
				if headDoErr == nil {
					defer headResp.Body.Close()
					serverSizeStr := headResp.Header.Get("Content-Length")
					serverSize, _ := strconv.ParseInt(serverSizeStr, 10, 64)
					if serverSize > 0 && existingSize >= serverSize {
						fmt.Printf("本地文件大小 (%s) 已达到或超过服务器文件大小 (%s)。认为下载已完成。\n", formatBytes(existingSize), formatBytes(serverSize))
						return nil // 认为成功完成
					}
				}
			}
			// 如果 HEAD 请求失败或大小不匹配，可能情况复杂，暂时报错
			return fmt.Errorf("错误：请求的范围无效，本地文件大小 %d 可能与服务器不符或已损坏", existingSize)
		} else {
			// 没有请求 Range 却收到 416? 异常情况
			return fmt.Errorf("错误：服务器返回 416 但未请求 Range")
		}

	default: // 其他错误状态码
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("错误：服务器返回非预期状态: %s\n响应体片段:\n%s", resp.Status, string(bodyBytes))
	}

	// 打印最终确定的文件总大小
	if totalSize > 0 {
		fmt.Printf("文件总大小：%s\n", formatBytes(totalSize))
		// 如果本地文件已等于或大于总大小，且是续传开始时确定的，认为已完成
		if existingSize > 0 && existingSize >= totalSize && outputFlags&os.O_APPEND != 0 {
			fmt.Printf("本地文件大小 (%s) 已达到或超过服务器报告的总大小 (%s)。认为下载已完成。\n", formatBytes(existingSize), formatBytes(totalSize))
			return nil // 成功退出
		}
	} else {
		fmt.Println("警告：无法确定文件总大小，进度百分比将不可用。")
	}

	// 9. *** 修改：使用正确的标志打开文件 ***
	outFile, err := os.OpenFile(decodedFilename, outputFlags, 0644)
	if err != nil {
		return fmt.Errorf("错误：无法打开输出文件 %s: %v", decodedFilename, err)
	}
	defer outFile.Close()

	// 如果是追加模式，确保文件指针在末尾 (OpenFile 应该能保证，但 Seek 可以更明确)
	// if outputFlags&os.O_APPEND != 0 {
	// 	_, err = outFile.Seek(0, io.SeekEnd) // 定位到文件末尾
	// 	if err != nil {
	// 		return fmt.Errorf("错误: 无法定位到文件 %s 的末尾: %v", decodedFilename, err)
	// 	}
	// }

	// 10. *** 修改：创建 ProgressWriter 时传入 existingSize ***
	progressWriter := NewProgressWriter(outFile, totalSize, existingSize, decodedFilename)
	if existingSize > 0 {
		fmt.Println("开始从断点续传...")
	} else {
		fmt.Println("开始下载文件...")
	}
	startTime := time.Now() // 记录开始时间

	// 使用 io.Copy 将响应体 (Reader) 复制到 ProgressWriter
	writtenBytes, err := io.Copy(progressWriter, resp.Body)
	// 手动触发一次最终的进度打印，确保显示 100% 或最终状态
	progressWriter.lock.Lock()
	progressWriter.printProgress()
	progressWriter.lock.Unlock()
	fmt.Println() // 确保进度条后有换行符

	if err != nil {
		// io.Copy 出错
		return fmt.Errorf("错误：下载文件时出错: %v (已写入 %d 字节)", err, writtenBytes)
	}

	// 检查写入的字节数 + 续传前的大小 是否等于 总大小 (如果总大小已知)
	finalWritten := existingSize + writtenBytes
	if totalSize > 0 && finalWritten < totalSize {
		fmt.Printf("\n警告：下载似乎提前结束。总写入 %s，但预期总大小为 %s。\n", formatBytes(finalWritten), formatBytes(totalSize))
		// 不一定返回错误，可能网络问题导致提前中断，部分文件已保存
	} else {
		fmt.Printf("\n下载操作完成！\n")
	}

	// 打印最终统计信息
	duration := time.Since(startTime)
	avgSpeed := float64(0)
	if duration.Seconds() > 0 {
		avgSpeed = float64(writtenBytes) / duration.Seconds() // 速度基于本次新写入的数据
	}
	fmt.Printf("本次写入：%s\n", formatBytes(writtenBytes))
	fmt.Printf("文件总大小：%s\n", formatBytes(progressWriter.written)) // progressWriter.written 是最终的总大小
	fmt.Printf("耗时：%s\n", duration.Round(time.Millisecond))
	fmt.Printf("平均速度：%s/s\n", formatBytes(int64(avgSpeed)))

	return nil
}

func main() {
	err := readConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
	}

	err = setArgs()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		fmt.Println("用法: go run your_program.go [下载链接]")
		os.Exit(1)
	}

	err = downloadFileWithProgress()
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n下载过程中发生错误: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n程序执行完毕。")
}
