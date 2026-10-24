package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"toshell/internal/common/tunnel"
	"toshell/internal/server/logging"
)

func (s *Server) listTunnelsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	sessionID := r.URL.Query().Get("session_id")

	s.socks5Mu.RLock()
	fmt.Printf("[DEBUG] [api] listTunnelsHandler: sessionID=%s, socks5Servers count=%d\n", sessionID, len(s.socks5Servers))
	defer s.socks5Mu.RUnlock()

	if sessionID != "" {
		if socks5, exists := s.socks5Servers[sessionID]; exists {
			tunnels := socks5.GetTunnelManager().ListTunnels()
			result := make([]map[string]interface{}, 0)
			for _, t := range tunnels {
				result = append(result, map[string]interface{}{
					"id":          t.ID,
					"target_addr": t.TargetAddr,
					"target_port": t.TargetPort,
					"active":      t.Active,
					"created_at":  t.CreatedAt.Format(time.RFC3339),
					"bytes_in":    t.BytesIn.Load(),
					"bytes_out":   t.BytesOut.Load(),
				})
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"tunnels":      result,
				"count":        len(result),
				"local_port":   socks5.GetPort(),
				"auth_enabled": socks5.AuthEnabled(),
			})
			return
		}
	}

	result := make([]map[string]interface{}, 0)
	for sessID, socks5 := range s.socks5Servers {
		tunnels := socks5.GetTunnelManager().ListTunnels()
		fmt.Printf("[DEBUG] [api] Session %s has %d tunnels\n", sessID, len(tunnels))

		tunnelList := make([]map[string]interface{}, 0)
		for _, t := range tunnels {
			tunnelList = append(tunnelList, map[string]interface{}{
				"id":          t.ID,
				"target_addr": t.TargetAddr,
				"target_port": t.TargetPort,
				"active":      t.Active,
				"created_at":  t.CreatedAt.Format(time.RFC3339),
				"bytes_in":    t.BytesIn.Load(),
				"bytes_out":   t.BytesOut.Load(),
			})
		}

		result = append(result, map[string]interface{}{
			"session_id":   sessID,
			"local_port":   socks5.GetPort(),
			"tunnels":      tunnelList,
			"auth_enabled": socks5.AuthEnabled(),
		})
	}

	fmt.Printf("[DEBUG] [api] Returning %d SOCKS5 servers\n", len(result))
	json.NewEncoder(w).Encode(map[string]interface{}{
		"servers": result,
		"count":   len(result),
	})
}

func (s *Server) createTunnelHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// auth_user / auth_pass 可选：留空 = 保持历史行为（无认证）。
	// 口令只用于配置代理监听器，绝不写日志、绝不在响应里回显。
	var req struct {
		SessionID string `json:"session_id"`
		LocalPort int    `json:"local_port"`
		AuthUser  string `json:"auth_user"`
		AuthPass  string `json:"auth_pass"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}
	if req.SessionID == "" {
		writeJSONError(w, http.StatusBadRequest, "session_id is required")
		return
	}

	auth := &tunnel.AuthConfig{Username: req.AuthUser, Password: req.AuthPass}
	if err := auth.Validate(); err != nil {
		// 只返回校验结论，不回显口令/用户名内容
		writeJSONError(w, http.StatusBadRequest, "invalid proxy auth: "+err.Error())
		return
	}

	port, err := s.startSOCKS5(req.SessionID, req.LocalPort, auth)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":    true,
		"session_id": req.SessionID,
		"local_port": port,
		// 只回显"是否启用认证"，口令绝不回传（连用户名也不回传）
		"auth_enabled": auth.Enabled(),
		"message":      "SOCKS5 proxy started successfully",
	})
}

// startSOCKS5 为指定会话启动一个 SOCKS5 隧道代理（HTTP handler 与 MCP 工具共用）。
// auth 可为 nil 或空值：此时代理不启用认证（老调用方行为不变）。
func (s *Server) startSOCKS5(sessionID string, localPort int, auth *tunnel.AuthConfig) (int, error) {
	if auth == nil {
		auth = &tunnel.AuthConfig{}
	}
	if err := auth.Validate(); err != nil {
		return 0, err
	}
	if localPort <= 0 {
		localPort = 1080
	}
	s.socks5Mu.Lock()
	defer s.socks5Mu.Unlock()

	if _, exists := s.socks5Servers[sessionID]; exists {
		return 0, fmt.Errorf("SOCKS5 server already running for this session")
	}
	// 检查端口是否已被其他 session 占用（Windows 上 net.Listen 默认 SO_REUSEADDR，
	// 同端口二次绑定不报错，会导致连接错误分发/隧道串流）。
	for sid, other := range s.socks5Servers {
		if other.GetPort() == localPort {
			return 0, fmt.Errorf("port %d already in use by session %s", localPort, sid)
		}
	}

	socks5 := tunnel.NewSOCKS5Server(localPort)
	socks5.SetSessionID(sessionID)
	socks5.SetSendToImplant(s.sendTunnelPacket)
	socks5.SetAuth(auth.Username, auth.Password)
	if sess, err := s.sessionMgr.Get(sessionID); err == nil && sess != nil {
		sess.SetTunnelHandler(func(p *tunnel.TunnelPacket) { socks5.HandleTunnelData(p) })
	}
	if err := socks5.Start(); err != nil {
		return 0, err
	}
	s.socks5Servers[sessionID] = socks5
	// 安全边界：日志只记录"是否启用认证"，绝不打印用户名/口令。
	logging.Info("api", "SOCKS5 proxy started for session %s on port %d (auth_enabled=%v)", sessionID, socks5.GetPort(), auth.Enabled())
	return socks5.GetPort(), nil
}

// stopSOCKS5 停止指定会话的隧道代理。
func (s *Server) stopSOCKS5(sessionID string) {
	s.socks5Mu.Lock()
	defer s.socks5Mu.Unlock()
	if socks5, ok := s.socks5Servers[sessionID]; ok {
		socks5.Stop()
		delete(s.socks5Servers, sessionID)
	}
}

func (s *Server) closeTunnelHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	sessionID := vars["id"]
	s.stopSOCKS5(sessionID)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "SOCKS5 proxy stopped",
	})
}

func (s *Server) sendTunnelPacket(sessionID string, packet []byte) error {
	if s.listener == nil {
		return fmt.Errorf("no listener available")
	}
	return s.listener.SendTunnelRaw(sessionID, packet)
}
