package tunnel

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
)

// ─── SOCKS5 / HTTP 代理认证（RFC 1929 用户名/口令子协商）────────────────────
//
// 认证发生在**服务端 SOCKS5 监听器**上（internal/common/tunnel.SOCKS5Server）：
// 植入端只是原始 TCP 中继（internal/server/builder/implant/tunnel.go 只处理
// OpSync/OpWrite/OpClose/OpAck），不解析 SOCKS5 协议，因此认证配置不需要下发到
// 植入端，也不存在"老植入端不支持认证"的版本兼容问题。
//
// 同一监听端口还兼容 HTTP CONNECT / 绝对 URI 正向代理（浏览器系统代理默认走
// HTTP）。启用认证时必须一并校验 HTTP 的 Proxy-Authorization，否则 HTTP 路径
// 会绕过认证 —— 这是 fail-closed 的关键。

// AuthConfig 代理入口的可选用户名/口令认证。
// nil 或空值 = 不启用认证（保持历史行为：SOCKS5 0x00 无认证）。
type AuthConfig struct {
	Username string
	Password string
}

// minAuthLen / maxAuthLen 对应 RFC 1929 的 ULEN/PLEN（1~255 字节）。
const (
	minAuthLen = 1
	maxAuthLen = 255
)

// Enabled 是否启用了认证：用户名或口令任一非空即视为"打算启用"，
// 由 Validate 兜住"只填了一半"的配置错误。
func (a *AuthConfig) Enabled() bool {
	return a != nil && (a.Username != "" || a.Password != "")
}

// Validate 校验认证字段（服务端在创建代理前调用；失败直接 400）。
//   - 长度：用户名/口令按**字节**计 1~255（UTF-8 中文按 3 字节算），超长拒绝；
//   - 字符：不允许控制字符（<0x20 或 0x7f），避免日志注入与协议歧义；
//   - 成对：启用认证时用户名与口令都不能为空。
//
// 这里只校验、不回显内容；错误文案绝不包含口令原文。
func (a *AuthConfig) Validate() error {
	if a == nil || !a.Enabled() {
		return nil
	}
	if a.Username == "" {
		return fmt.Errorf("auth_user is required when auth_pass is set")
	}
	if a.Password == "" {
		return fmt.Errorf("auth_pass is required when auth_user is set")
	}
	if n := len(a.Username); n < minAuthLen || n > maxAuthLen {
		return fmt.Errorf("auth_user length must be %d-%d bytes (got %d)", minAuthLen, maxAuthLen, n)
	}
	if n := len(a.Password); n < minAuthLen || n > maxAuthLen {
		return fmt.Errorf("auth_pass length must be %d-%d bytes (got %d)", minAuthLen, maxAuthLen, n)
	}
	if err := checkNoControlChars(a.Username); err != nil {
		return fmt.Errorf("auth_user contains invalid character: %w", err)
	}
	if err := checkNoControlChars(a.Password); err != nil {
		// 绝不回显口令：只说明含非法字符，不回显是哪个字符
		return fmt.Errorf("auth_pass contains invalid control character")
	}
	return nil
}

func checkNoControlChars(s string) error {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("control character U+%04X", r)
		}
	}
	return nil
}

// SetAuth 设置代理认证信息；空值自动关闭认证（兼容老调用方）。
func (s *SOCKS5Server) SetAuth(user, pass string) {
	if user == "" && pass == "" {
		s.auth = nil
		return
	}
	s.auth = &AuthConfig{Username: user, Password: pass}
}

// AuthEnabled 返回该代理是否启用了认证（用于列表回显，绝不回显口令）。
func (s *SOCKS5Server) AuthEnabled() bool { return s.auth.Enabled() }

// hasMethod 判断客户端方法列表里是否包含某个认证方法。
func hasMethod(methods []byte, want byte) bool {
	for _, m := range methods {
		if m == want {
			return true
		}
	}
	return false
}

// socks5Subnegotiate 执行 RFC 1929 用户名/口令子协商。
// 流程：服务端已回 [0x05, 0x02] → 客户端发 [0x01, ULEN, UNAME, PLEN, PASSWD]
// → 服务端回 [0x01, 0x00] 成功 / [0x01, 0x01] 失败。
//
// 失败时必须先把 0x01 0x01 写给客户端再返回错误（调用方只负责关连接），
// 否则部分客户端会把它当成协议错误而不是"口令不对"。
func socks5Subnegotiate(reader io.Reader, conn net.Conn, auth *AuthConfig) error {
	head := make([]byte, 2)
	if _, err := io.ReadFull(reader, head); err != nil {
		return fmt.Errorf("read auth version/ulen: %w", err)
	}
	if head[0] != 0x01 {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return fmt.Errorf("unsupported auth version: %d", head[0])
	}
	ulen := int(head[1])
	if ulen < minAuthLen || ulen > maxAuthLen {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return fmt.Errorf("invalid username length: %d", ulen)
	}

	uname := make([]byte, ulen)
	if _, err := io.ReadFull(reader, uname); err != nil {
		return fmt.Errorf("read username: %w", err)
	}

	plenBuf := make([]byte, 1)
	if _, err := io.ReadFull(reader, plenBuf); err != nil {
		return fmt.Errorf("read password length: %w", err)
	}
	plen := int(plenBuf[0])
	if plen < minAuthLen || plen > maxAuthLen {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return fmt.Errorf("invalid password length: %d", plen)
	}
	pass := make([]byte, plen)
	if _, err := io.ReadFull(reader, pass); err != nil {
		return fmt.Errorf("read password: %w", err)
	}

	userOK := subtle.ConstantTimeCompare(uname, []byte(auth.Username)) == 1
	passOK := subtle.ConstantTimeCompare(pass, []byte(auth.Password)) == 1
	if !userOK || !passOK {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return fmt.Errorf("socks5 authentication failed")
	}
	if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
		return fmt.Errorf("write auth success: %w", err)
	}
	return nil
}

// httpProxyAuthOK 校验 HTTP 代理的 Proxy-Authorization: Basic base64(user:pass)。
// 未启用认证时直接放行（保持历史行为）；启用认证时缺失/错误一律拒绝。
func httpProxyAuthOK(headerLines []string, auth *AuthConfig) bool {
	if !auth.Enabled() {
		return true
	}
	for _, line := range headerLines {
		name, value, ok := strings.Cut(line, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(name), "proxy-authorization") {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) < len("basic ") || !strings.EqualFold(value[:len("basic ")], "basic ") {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value[len("basic "):]))
		if err != nil {
			continue
		}
		user, pass, ok := strings.Cut(string(raw), ":")
		if !ok {
			continue
		}
		userOK := subtle.ConstantTimeCompare([]byte(user), []byte(auth.Username)) == 1
		passOK := subtle.ConstantTimeCompare([]byte(pass), []byte(auth.Password)) == 1
		if userOK && passOK {
			return true
		}
	}
	return false
}

// writeHTTPProxyAuthRequired 回 407 并提示使用 Basic 认证（浏览器/curl 会自动重试）。
func writeHTTPProxyAuthRequired(conn net.Conn) {
	_, _ = conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n" +
		"Proxy-Authenticate: Basic realm=\"toshell\"\r\n" +
		"Content-Length: 0\r\n\r\n"))
}
