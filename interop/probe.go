// 互操作探针（e2e 用，独立二进制，不参与主程序编译）
//
// 用自包含的协议栈完成一次完整会话：
//  1. TLS（跳过验证）连到 --addr 指定的服务端
//  2. 发送 HandshakeReq（含 enc_algo=2 / fec_group 请求）
//  3. 解析 HandshakeResp，打印协商结果
//  4. 用协商出的加密器发 N 个加密数据帧
//  5. 每 500ms 发一个心跳，从服务端收帧（校验帧/数据帧/心跳）并统计
//  6. 收到 --expect-frames 帧或超时后退出 0；任何一步失败退出非 0
//
// 由 -tags interop 控制编译：go build -tags interop -o probe.exe ./cmd/probe
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// ---- 协议常量（与 tlsvpn/frame.go 一致） ----
const (
	encAlgoGCM   = 2
	encAlgoGCMV2 = 3
	encSaltSize  = 8
	gcmTagSize   = 16
	fecMagic     = byte(0xFE)
	pskHashConst = "probe_psk"
)

type HandshakeReq struct {
	ClientID string `json:"client_id"`
	PSK      string `json:"psk"`
	MAC      string `json:"mac,omitempty"`
	IPv4     string `json:"ipv4,omitempty"`
	IPv6     string `json:"ipv6,omitempty"`
	Padding  string `json:"padding,omitempty"`
	BrutalTx uint64 `json:"brutal_tx,omitempty"`
	BrutalRx uint64 `json:"brutal_rx,omitempty"`
	FEC      bool   `json:"fec,omitempty"`
	FecGroup int    `json:"fec_group,omitempty"`
	Encrypt  bool   `json:"encrypt,omitempty"`
	EncAlgo  int    `json:"enc_algo,omitempty"`
}

type HandshakeResp struct {
	Success   bool   `json:"success"`
	Message   string `json:"message"`
	SessionID string `json:"session_id,omitempty"`
	ClientID  string `json:"client_id"`
	IPv4      string `json:"ipv4"`
	IPv6      string `json:"ipv6"`
	GwV4      string `json:"gw_v4,omitempty"`
	GwV6      string `json:"gw_v6,omitempty"`
	BrutalTx  uint64 `json:"brutal_tx,omitempty"`
	BrutalRx  uint64 `json:"brutal_rx,omitempty"`
	FEC       bool   `json:"fec,omitempty"`
	FecGroup  int    `json:"fec_group,omitempty"`
	Encrypt   bool   `json:"encrypt,omitempty"`
	EncAlgo   int    `json:"enc_algo,omitempty"`
	EncSalt   string `json:"enc_salt,omitempty"`
	EncSalt2  string `json:"enc_salt2,omitempty"`
}

func appendPaddedFrame(buf []byte, seq uint32, data []byte, ic *interopCipher) []byte {
	dataLen := 0
	if data != nil {
		dataLen = len(data)
	}
	encTag := 0
	if ic != nil && seq != 0 && dataLen > 0 {
		encTag = gcmTagSize
	}
	padLen := 100 // 固定填充即可
	needed := 10 + dataLen + encTag + padLen
	start := len(buf)
	if cap(buf)-start < needed {
		grown := make([]byte, start, start+needed+64)
		copy(grown, buf)
		buf = grown
	}
	buf = buf[:start+needed]
	bin.PutUint32(buf[start:start+4], uint32(dataLen+encTag))
	bin.PutUint16(buf[start+4:start+6], uint16(padLen))
	bin.PutUint32(buf[start+6:start+10], seq)
	if dataLen > 0 {
		copy(buf[start+10:start+10+dataLen], data)
		if ic != nil && seq != 0 {
			ic.seal(buf[start+10:start+10+dataLen+encTag], dataLen, seq, uint32(dataLen+encTag))
		}
	}
	for i := 0; i < padLen; i++ {
		buf[start+10+dataLen+encTag+i] = byte(i)
	}
	return buf
}

type interopCipher struct {
	aead cipher.AEAD
	salt [encSaltSize]byte
}

// newInteropCipher 按协商出的算法值（2 = GCM-v1，3 = GCM-v2）构造内层加密器。
// 二者仅密钥派生标签不同：v2 用 _enc_key_gcm_v2 实现 GCM/CTR 密钥分离
// （对齐 Go gcmKeyLabel）。
func newInteropCipher(psk string, salt []byte, algo int) (*interopCipher, error) {
	if len(salt) != encSaltSize {
		return nil, fmt.Errorf("bad salt len %d", len(salt))
	}
	label := "_enc_key"
	if algo == encAlgoGCMV2 {
		label = "_enc_key_gcm_v2"
	}
	keyHash := sha256.Sum256([]byte(psk + label))
	block, err := aes.NewCipher(keyHash[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ic := &interopCipher{aead: aead}
	copy(ic.salt[:], salt)
	return ic, nil
}

func (ic *interopCipher) nonce(seq uint32) []byte {
	n := make([]byte, 12)
	bin.PutUint32(n[0:4], seq)
	copy(n[4:], ic.salt[:])
	return n
}

func (ic *interopCipher) aad(wireLen, seq uint32) []byte {
	a := make([]byte, 8)
	bin.PutUint32(a[0:4], wireLen)
	bin.PutUint32(a[4:8], seq)
	return a
}

func (ic *interopCipher) seal(region []byte, ptLen int, seq, wireLen uint32) {
	out := ic.aead.Seal(region[:0], ic.nonce(seq), region[:ptLen], ic.aad(wireLen, seq))
	_ = out
}

func (ic *interopCipher) open(data []byte, seq, wireLen uint32) ([]byte, error) {
	return ic.aead.Open(data[:0], ic.nonce(seq), data, ic.aad(wireLen, seq))
}

var bin = binary.BigEndian

func readFrame(conn io.Reader, timeout time.Duration) ([]byte, uint32, error) {
	hdr := make([]byte, 10)
	if err := readFull(conn, hdr, timeout); err != nil {
		return nil, 0, err
	}
	dataLen := int(bin.Uint32(hdr[0:4]))
	padLen := int(bin.Uint16(hdr[4:6]))
	seq := bin.Uint32(hdr[6:10])
	var body []byte
	if dataLen > 0 {
		body = make([]byte, dataLen)
		if err := readFull(conn, body, timeout); err != nil {
			return nil, 0, err
		}
	}
	// 必须消费填充字节，否则流会错位（对齐协议 [hdr][data][pad]）
	if padLen > 0 {
		pad := make([]byte, padLen)
		if err := readFull(conn, pad, timeout); err != nil {
			return nil, 0, err
		}
	}
	return body, seq, nil
}

func readFull(conn io.Reader, buf []byte, timeout time.Duration) error {
	type deadline interface{ SetReadDeadline(time.Time) error }
	d, ok := conn.(deadline)
	if ok {
		d.SetReadDeadline(time.Now().Add(timeout))
	}
	got := 0
	for got < len(buf) {
		n, err := conn.Read(buf[got:])
		got += n
		if err != nil {
			return err
		}
	}
	return nil
}

func main() {
	addr := flag.String("addr", "127.0.0.1:4400", "server address")
	psk := flag.String("psk", "e2e_secret", "PSK")
	encrypt := flag.Bool("encrypt", true, "request inner encryption")
	fec := flag.Bool("fec", false, "request XOR FEC")
	fecGroup := flag.Int("fec-group", 0, "FEC group size (0 = omit)")
	frames := flag.Int("send", 8, "number of encrypted data frames to send")
	expectFrames := flag.Int("expect-frames", 1, "frames to receive before exit")
	socks5Addr := flag.String("socks5", "", "route through SOCKS5 proxy")
	timeoutSec := flag.Int("timeout", 10, "overall seconds")
	mac := flag.String("mac", "aa:bb:cc:dd:ee:ff", "client MAC (unique per probe)")
	staySec := flag.Int("stay", 0, "stay connected N seconds receiving frames (2-client test)")
	bcast := flag.Bool("bcast", false, "send one broadcast ethernet frame before staying")
	parityTest := flag.Bool("parity-test", false, "send K-1 broadcast frames + data frames so parity frames appear on wire (FEC cross-check)")
	encAlgo := flag.Int("enc-algo", encAlgoGCM, "inner cipher capability to declare: 0 = legacy CTR, 2 = GCM-v1, 3 = GCM-v2, 9 = 未知算法（min_enc 下限测试用）")
	flag.Parse()

	target := *addr
	var conn net.Conn
	var err error
	if *socks5Addr != "" {
		d, derr := proxy.SOCKS5("tcp", *socks5Addr, nil, proxy.Direct)
		if derr != nil {
			fmt.Println("FAIL: socks5 dialer:", derr)
			os.Exit(1)
		}
		conn, err = d.Dial("tcp", target)
	} else {
		conn, err = net.DialTimeout("tcp", target, 5*time.Second)
	}
	if err != nil {
		fmt.Println("FAIL: dial:", err)
		os.Exit(1)
	}
	defer conn.Close()
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}

	// 1. TLS 握手（InsecureSkipVerify 只用于测试）
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}})
	tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		fmt.Println("FAIL: tls handshake:", err)
		os.Exit(1)
	}
	tlsConn.SetDeadline(time.Time{})

	idHash := sha256.Sum256([]byte(*mac + *psk))
	// 服务端把 ClientID 校验为 UUID 形态（8-4-4-4-12），探针派生同样的形状；
	// 由 mac+psk 确定，保证同一身份重连时 ID 恒定
	h := hex.EncodeToString(idHash[:16])
	clientID := fmt.Sprintf(
		"%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])

	// 2. 握手请求
	req := HandshakeReq{
		ClientID: clientID,
		PSK:      hashPSK(*psk),
		MAC:      *mac,
		IPv4:     "10.7.0.66",
		Padding:  "probe",
		FEC:      *fec,
		FecGroup: *fecGroup,
		Encrypt:  *encrypt,
		EncAlgo:  *encAlgo,
	}
	reqJSON, _ := json.Marshal(req)
	buf := appendPaddedFrame(nil, 0, reqJSON, nil)
	if _, err := tlsConn.Write(buf); err != nil {
		fmt.Println("FAIL: write req:", err)
		os.Exit(1)
	}

	// 3. 握手响应
	respData, _, err := readFrame(tlsConn, 5*time.Second)
	if err != nil {
		fmt.Println("FAIL: read resp:", err)
		os.Exit(1)
	}
	var resp HandshakeResp
	if err := json.Unmarshal(respData, &resp); err != nil {
		fmt.Println("FAIL: bad resp json:", err, string(respData))
		os.Exit(1)
	}
	if !resp.Success {
		fmt.Println("FAIL: handshake rejected:", resp.Message)
		os.Exit(1)
	}
	fmt.Printf("RESP: success=%v enc_algo=%d enc_salt=%s enc_salt2=%s fec_group=%d session=%s ipv4=%s\n",
		resp.Success, resp.EncAlgo, resp.EncSalt, resp.EncSalt2, resp.FecGroup, resp.SessionID, resp.IPv4)

	// 4. 协商一致性校验
	if resp.Encrypt != *encrypt {
		fmt.Printf("FAIL: server encrypt mismatch: got %v want %v\n", resp.Encrypt, *encrypt)
		os.Exit(1)
	}
	var icTx, icRx *interopCipher
	if *encrypt {
		// 精确比较而非 >=：未知算法 ID 不得被当成 GCM（见 encAlgoSupported）。
		// 算法 3（GCM-v2）与 2（GCM-v1）都是合格协商结果：服务端按本端声明的
		// 能力（-enc-algo）精确匹配后回哪个，哪个就是对的。
		if resp.EncAlgo == encAlgoGCM || resp.EncAlgo == encAlgoGCMV2 {
			saltTx, e1 := hex.DecodeString(resp.EncSalt)
			saltRx, e2 := hex.DecodeString(resp.EncSalt2)
			if e1 != nil || e2 != nil || len(saltTx) != encSaltSize || len(saltRx) != encSaltSize {
				fmt.Println("FAIL: bad enc salts from server")
				os.Exit(1)
			}
			icTx, err = newInteropCipher(*psk, saltTx, resp.EncAlgo)
			if err != nil {
				fmt.Println("FAIL:", err)
				os.Exit(1)
			}
			icRx, err = newInteropCipher(*psk, saltRx, resp.EncAlgo)
			if err != nil {
				fmt.Println("FAIL:", err)
				os.Exit(1)
			}
			if resp.EncAlgo == encAlgoGCMV2 {
				fmt.Println("NEGOTIATED: GCM-v2 (per-session salts, independent key label)")
			} else {
				fmt.Println("NEGOTIATED: GCM (per-session bidirectional salts)")
			}
		} else {
			fmt.Println("NEGOTIATED: legacy CTR (server lacks GCM or below min_enc)")
			fmt.Println("FAIL: expected GCM negotiation with modern server")
			os.Exit(1)
		}
	}
	if *fec {
		if resp.FecGroup >= 2 {
			fmt.Printf("NEGOTIATED: XOR FEC K=%d\n", resp.FecGroup)
		} else {
			fmt.Println("NEGOTIATED: dup fallback (server lacks XOR FEC)")
			if *fecGroup >= 2 {
				fmt.Println("FAIL: expected XOR FEC negotiation")
				os.Exit(1)
			}
		}
	}

	// 5. 发送加密数据帧（每帧独立 seq；parity-test 模式跳过，由 bcast 块发送等长帧）
	if !*parityTest {
		go func() {
			for i := 0; i < *frames; i++ {
				payload := []byte(fmt.Sprintf("PROBE-DATA-%04d:%s", i, time.Now().Format("15:04:05.000")))
				fb := appendPaddedFrame(nil, uint32(i+1), payload, icTx)
				if _, err := tlsConn.Write(fb); err != nil {
					return
				}
				time.Sleep(20 * time.Millisecond)
			}
		}()
	}

	// 双客户端模式：发一个广播帧后驻留接收（验证 c2s+s2c 全双工）
	if *staySec > 0 {
		if *parityTest || *bcast {
			// 发送 K*2 个广播帧（K=4 时 8 帧 → 服务端产出 2 个校验帧广播）
			for i := 0; i < *frames; i++ {
				frame := make([]byte, 80)
				for j := 0; j < 6; j++ {
					frame[j] = 0xff
				}
				copy(frame[6:12], mustMAC(*mac))
				copy(frame[12:], []byte(fmt.Sprintf("PT-%s-%04d", *mac, i)))
				fb := appendPaddedFrame(nil, uint32(1+i), frame, icTx)
				if _, err := tlsConn.Write(fb); err != nil {
					fmt.Println("FAIL: write pt:", err)
					os.Exit(1)
				}
				time.Sleep(30 * time.Millisecond)
			}
			fmt.Printf("SENT: %d broadcast frames for FEC parity test\n", *frames)
		} else if *bcast {
			frame := make([]byte, 60)
			for i := 0; i < 6; i++ {
				frame[i] = 0xff
			}
			copy(frame[6:12], mustMAC(*mac))
			copy(frame[12:], []byte(fmt.Sprintf("BCAST-FROM-%s-idx%d", *mac, time.Now().UnixMilli()%10000)))
			fb := appendPaddedFrame(nil, uint32(*frames+100), frame, icTx)
			if _, err := tlsConn.Write(fb); err != nil {
				fmt.Println("FAIL: write bcast:", err)
				os.Exit(1)
			}
			fmt.Println("SENT: broadcast frame")
		}
		deadline := time.Now().Add(time.Duration(*staySec) * time.Second)
		lastKA := time.Now()
		rxCount := 0
		parityOK := false
		wantParity := *fec
		for time.Now().Before(deadline) {
			tlsConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			body, seq, err := readFrame(tlsConn, 500*time.Millisecond)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					if time.Since(lastKA) > 2*time.Second {
						tlsConn.Write(appendPaddedFrame(nil, 0, nil, nil))
						lastKA = time.Now()
					}
					continue
				}
				fmt.Println("FAIL: stay read:", err)
				os.Exit(1)
			}
			if seq == 0 {
				if len(body) >= 7 && body[0] == fecMagic {
					start := binary.BigEndian.Uint32(body[1:5])
					k := int(body[5])
					descLen := 6 + 4*k
					tagLen := 0
					if icRx != nil {
						tagLen = gcmTagSize
					}
					maxLen := 0
					for i := 0; i < k; i++ {
						l := int(binary.BigEndian.Uint32(body[6+4*i : 10+4*i]))
						if l > maxLen {
							maxLen = l
						}
					}
					ok := "BAD"
					if icRx != nil && len(body) >= descLen+tagLen {
						region := make([]byte, maxLen+tagLen)
						copy(region, body[descLen:descLen+maxLen+tagLen])
						if _, err := icRx.open(region, start, uint32(maxLen+tagLen)); err == nil {
							ok = "OK"
						}
					}
					fmt.Printf("RX-PARITY-%s: start=%d K=%d len=%d\n", ok, start, k, len(body))
					parityOK = ok == "OK"
				}
				continue
			}
			if icRx != nil {
				plain, derr := icRx.open(body, seq, uint32(len(body)))
				if derr != nil {
					fmt.Printf("RX: GCM OPEN FAILED (seq=%d)\n", seq)
					os.Exit(1)
				}
				n := len(plain)
				if n > 60 {
					n = 60
				}
				fmt.Printf("RX-DECRYPTED: seq=%d %q\n", seq, plain[:n])
			} else {
				fmt.Printf("RX: seq=%d len=%d\n", seq, len(body))
			}
			rxCount++
		}
		fmt.Printf("SUMMARY: stay-frames=%d parity-ok=%v\n", rxCount, parityOK)
		if wantParity && !parityOK {
			fmt.Println("FAIL: expected a verifiable parity frame (did receiver negotiate --fec?)")
			os.Exit(1)
		}
		fmt.Println("PASS")
		return
	}

	// 6. 收帧循环：单客户端模式下只要收到任一心跳即证明下行链路存活
	deadline := time.Now().Add(time.Duration(*timeoutSec) * time.Second)
	gotFrames := 0
	gotParity := 0
	heartbeatSeen := 0
	for (gotFrames < *expectFrames || heartbeatSeen < 1) && time.Now().Before(deadline) {
		tlsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		body, seq, err := readFrame(tlsConn, 2*time.Second)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				// 心跳保活
				kb := appendPaddedFrame(nil, 0, nil, nil)
				tlsConn.Write(kb)
				continue
			}
			fmt.Println("FAIL: read loop:", err)
			os.Exit(1)
		}
		if seq == 0 {
			if len(body) >= 7 && body[0] == fecMagic {
				gotParity++
				fmt.Printf("RX: parity frame (len=%d)\n", len(body))
				continue
			}
			if len(body) == 0 {
				heartbeatSeen++
				continue // 心跳：证明服务端下行链路存活
			}
			fmt.Printf("RX: control frame (len=%d)\n", len(body))
			continue
		}
		if icRx != nil {
			plain, derr := icRx.open(body, seq, uint32(len(body)))
			if derr != nil {
				fmt.Printf("RX: GCM OPEN FAILED (seq=%d): %v\n", seq, derr)
				os.Exit(1)
			}
			fmt.Printf("RX: seq=%d plain=%q\n", seq, plain[:min(len(plain), 40)])
		} else {
			fmt.Printf("RX: seq=%d len=%d\n", seq, len(body))
		}
		gotFrames++
	}
	fmt.Printf("SUMMARY: frames=%d parity=%d heartbeats=%d\n", gotFrames, gotParity, heartbeatSeen)
	// 单客户端模式：收到心跳即证明下行链路存活（服务端不回显数据帧）
	if gotFrames < *expectFrames && heartbeatSeen == 0 {
		fmt.Println("FAIL: expected more frames")
		os.Exit(1)
	}
	fmt.Println("PASS")
}

func mustMAC(s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, ":", ""))
	if err != nil || len(b) != 6 {
		panic("bad mac")
	}
	return b
}

func hashPSK(psk string) string {
	h := sha256.Sum256([]byte(psk))
	return hex.EncodeToString(h[:])
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
