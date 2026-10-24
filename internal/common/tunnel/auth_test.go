package tunnel

import (
	"bytes"
	"encoding/base64"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeConn 只实现 handshake 用到的 Write/Close；Read 不会被调用
// （reader 通过 io.MultiReader 独立传入，见 socks5Handshake）。
type fakeConn struct {
	written bytes.Buffer
	closed  bool
}

func (c *fakeConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *fakeConn) Write(p []byte) (int, error)      { return c.written.Write(p) }
func (c *fakeConn) Close() error                     { c.closed = true; return nil }
func (c *fakeConn) LocalAddr() net.Addr              { return nil }
func (c *fakeConn) RemoteAddr() net.Addr             { return nil }
func (c *fakeConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }

// socks5Request 构造 "VER=5 CMD=1 RSV=0 ATYP=3 domain:port" 请求。
func socks5Request(host string, port uint16) []byte {
	b := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	b = append(b, host...)
	b = append(b, byte(port>>8), byte(port))
	return b
}

func TestAuthConfigValidate(t *testing.T) {
	cases := []struct {
		name    string
		auth    *AuthConfig
		wantErr bool
	}{
		{"nil", nil, false},
		{"empty", &AuthConfig{}, false},
		{"valid ascii", &AuthConfig{Username: "operator", Password: "s3cr3t!"}, false},
		{"valid utf8", &AuthConfig{Username: "运维", Password: "口令-2026"}, false},
		{"only user", &AuthConfig{Username: "operator"}, true},
		{"only pass", &AuthConfig{Password: "s3cr3t"}, true},
		{"user too long", &AuthConfig{Username: strings.Repeat("a", 256), Password: "p"}, true},
		{"pass too long", &AuthConfig{Username: "u", Password: strings.Repeat("p", 256)}, true},
		{"user control char", &AuthConfig{Username: "op\x00erator", Password: "p"}, true},
		{"pass newline", &AuthConfig{Username: "u", Password: "p\nw"}, true},
		{"pass del", &AuthConfig{Username: "u", Password: "p\x7fw"}, true},
		{"max length", &AuthConfig{Username: strings.Repeat("u", 255), Password: strings.Repeat("p", 255)}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.auth.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate() err = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

// TestAuthConfigValidateNeverEchoesPassword 口令不得出现在错误文案里。
func TestAuthConfigValidateNeverEchoesPassword(t *testing.T) {
	const secret = "SuperSecret!42"
	auth := &AuthConfig{Username: "u", Password: secret + "\n"}
	err := auth.Validate()
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error message leaks password: %v", err)
	}
}

func TestSocks5HandshakeNoAuthUnchanged(t *testing.T) {
	req := socks5Request("example.com", 443)
	var in bytes.Buffer
	in.Write([]byte{0x05, 0x01, 0x00})
	in.Write(req)

	conn := &fakeConn{}
	host, port, err := socks5Handshake(&in, conn, nil)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if host != "example.com" || port != 443 {
		t.Fatalf("target = %s:%d, want example.com:443", host, port)
	}
	if got := conn.written.Bytes(); !bytes.Equal(got, []byte{0x05, 0x00}) {
		t.Fatalf("method reply = %x, want 0500", got)
	}
}

func TestSocks5HandshakeNoAuthRejectsUserPassOnly(t *testing.T) {
	var in bytes.Buffer
	in.Write([]byte{0x05, 0x01, 0x02}) // 客户端只支持用户名/口令，但服务端未启用认证

	conn := &fakeConn{}
	if _, _, err := socks5Handshake(&in, conn, nil); err == nil {
		t.Fatal("expected error")
	}
	if got := conn.written.Bytes(); !bytes.Equal(got, []byte{0x05, 0xff}) {
		t.Fatalf("reply = %x, want 05ff", got)
	}
}

func TestSocks5HandshakeAuthSuccess(t *testing.T) {
	auth := &AuthConfig{Username: "operator", Password: "s3cr3t"}
	var in bytes.Buffer
	in.Write([]byte{0x05, 0x02, 0x00, 0x02}) // 同时提供无认证与用户/口令
	in.Write([]byte{0x01, byte(len(auth.Username))})
	in.WriteString(auth.Username)
	in.Write([]byte{byte(len(auth.Password))})
	in.WriteString(auth.Password)
	in.Write(socks5Request("10.0.0.5", 8080))

	conn := &fakeConn{}
	host, port, err := socks5Handshake(&in, conn, auth)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if host != "10.0.0.5" || port != 8080 {
		t.Fatalf("target = %s:%d, want 10.0.0.5:8080", host, port)
	}
	want := []byte{0x05, 0x02, 0x01, 0x00}
	got := conn.written.Bytes()
	if len(got) < len(want) || !bytes.Equal(got[:len(want)], want) {
		t.Fatalf("replies = %x, want prefix %x", got, want)
	}
}

func TestSocks5HandshakeAuthWrongPassword(t *testing.T) {
	auth := &AuthConfig{Username: "operator", Password: "right"}
	var in bytes.Buffer
	in.Write([]byte{0x05, 0x01, 0x02})
	in.Write([]byte{0x01, byte(len("operator"))})
	in.WriteString("operator")
	in.Write([]byte{byte(len("wrong"))})
	in.WriteString("wrong")

	conn := &fakeConn{}
	if _, _, err := socks5Handshake(&in, conn, auth); err == nil {
		t.Fatal("expected auth failure")
	}
	got := conn.written.Bytes()
	if !bytes.Equal(got[:4], []byte{0x05, 0x02, 0x01, 0x01}) {
		t.Fatalf("replies = %x, want prefix 05020101 (auth failed)", got)
	}
}

func TestSocks5HandshakeAuthRequiredButOnlyNoAuthOffered(t *testing.T) {
	auth := &AuthConfig{Username: "u", Password: "p"}
	var in bytes.Buffer
	in.Write([]byte{0x05, 0x01, 0x00})

	conn := &fakeConn{}
	if _, _, err := socks5Handshake(&in, conn, auth); err == nil {
		t.Fatal("expected 'no acceptable auth method'")
	}
	// 不能静默降级为无认证：必须明确 0xFF
	if got := conn.written.Bytes(); !bytes.Equal(got, []byte{0x05, 0xff}) {
		t.Fatalf("reply = %x, want 05ff", got)
	}
}

func TestHTTPConnectAuth(t *testing.T) {
	auth := &AuthConfig{Username: "operator", Password: "s3cr3t"}
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("operator:s3cr3t"))

	t.Run("missing credentials -> 407", func(t *testing.T) {
		in := strings.NewReader("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n")
		conn := &fakeConn{}
		if _, _, _, _, err := httpConnectHandshake(in, conn, auth); err == nil {
			t.Fatal("expected proxy auth required")
		}
		if !strings.Contains(conn.written.String(), "407 Proxy Authentication Required") {
			t.Fatalf("response = %q, want 407", conn.written.String())
		}
	})

	t.Run("wrong credentials -> 407", func(t *testing.T) {
		in := strings.NewReader("CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic " +
			base64.StdEncoding.EncodeToString([]byte("operator:nope")) + "\r\n\r\n")
		conn := &fakeConn{}
		if _, _, _, _, err := httpConnectHandshake(in, conn, auth); err == nil {
			t.Fatal("expected proxy auth required")
		}
		if !strings.Contains(conn.written.String(), "407") {
			t.Fatalf("response = %q, want 407", conn.written.String())
		}
	})

	t.Run("valid credentials -> 200", func(t *testing.T) {
		in := strings.NewReader("CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: " + basic + "\r\n\r\n")
		conn := &fakeConn{}
		host, port, _, _, err := httpConnectHandshake(in, conn, auth)
		if err != nil {
			t.Fatalf("handshake: %v", err)
		}
		if host != "example.com" || port != 443 {
			t.Fatalf("target = %s:%d", host, port)
		}
		if !strings.Contains(conn.written.String(), "200 Connection Established") {
			t.Fatalf("response = %q, want 200", conn.written.String())
		}
	})

	t.Run("no auth configured still open", func(t *testing.T) {
		in := strings.NewReader("CONNECT example.com:443 HTTP/1.1\r\n\r\n")
		conn := &fakeConn{}
		if _, _, _, _, err := httpConnectHandshake(in, conn, nil); err != nil {
			t.Fatalf("handshake: %v", err)
		}
		if !strings.Contains(conn.written.String(), "200 Connection Established") {
			t.Fatalf("response = %q", conn.written.String())
		}
	})
}

// TestAuthEnabledToggle 认证开关与 SetAuth 语义（空值 = 关闭，兼容老调用方）。
func TestAuthEnabledToggle(t *testing.T) {
	s := NewSOCKS5Server(0)
	if s.AuthEnabled() {
		t.Fatal("new server must default to no auth")
	}
	s.SetAuth("u", "")
	if !s.AuthEnabled() {
		t.Fatal("SetAuth with user should enable auth")
	}
	s.SetAuth("", "")
	if s.AuthEnabled() {
		t.Fatal("SetAuth with empty values should disable auth")
	}
}
