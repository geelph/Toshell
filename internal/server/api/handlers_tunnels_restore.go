package api

import (
	"fmt"
	"net"
	"strings"

	"toshell/internal/common/tunnel"
	"toshell/internal/server/logging"
	"toshell/internal/server/tunnelstore"
)

// ─── 重启恢复（v1.4.1）──────────────────────────────────────────────────────
//
// 服务端启动时（cmd/server/main.go 初始化 API server 之后）调用 RestoreTunnels：
// 读 tunnels 表，逐条尝试重新监听。
//
// 硬性约束：
//   - 单条失败**绝不**导致进程退出：标记该行 status=error + last_error=原因，
//     继续恢复其它行，最后打一条汇总日志；
//   - 端口被占用是最常见的失败原因（上次没退干净 / 别的程序占了），必须能降级；
//   - 带认证的代理若口令解密失败，**不重建**（否则等于把带认证的入口静默降级成裸代理），
//     同样标记 error；
//   - 恢复出来的代理此时还没有会话（植入端要等一会儿才回连），回包通道由
//     main.go 的会话上线回调调用 RebindTunnelHandler 绑定。

// RestoreTunnels 按库重建全部代理监听，返回（成功数，失败数）。
//
// 恢复过程日志形如：
//
//	[INFO] [tunnel] restored 3/4 (1 failed: port 11090 in use)
func (s *Server) RestoreTunnels() (restored, failed int) {
	if s.tunnelStore == nil {
		// 无库（或库不可用）：没有可恢复的期望状态，静默返回（调用方已打过降级日志）。
		return 0, 0
	}
	rows, err := s.tunnelStore.List()
	if err != nil {
		logging.Warn("tunnel", "读取 tunnels 表失败，本次不做隧道恢复：%v", err)
		return 0, 0
	}
	total := len(rows)
	if total == 0 {
		return 0, 0
	}

	failures := make([]string, 0, total)
	for _, row := range rows {
		if s.tunnelRunning(row.ID) {
			// 防御：同一次启动里被恢复过两次（不应发生），直接算成功，别再起第二份监听。
			restored++
			continue
		}

		auth := &tunnel.AuthConfig{}
		if row.AuthEnabled {
			pass, derr := s.tunnelStore.DecryptPassword(row.ID)
			if derr != nil {
				reason := "代理口令解密失败，为避免降级为无认证代理，本次不恢复: " + derr.Error()
				s.markTunnelRestoreError(row, reason)
				logging.Warn("tunnel", "恢复失败（session=%s, port=%d）：%s", row.ID, row.LocalPort, reason)
				failures = append(failures, fmt.Sprintf("port %d auth pass decrypt failed", row.LocalPort))
				failed++
				continue
			}
			auth = &tunnel.AuthConfig{Username: row.AuthUser, Password: pass}
		}

		// 先探测端口：SOCKS5Server.Start 是"双栈尽力而为"（tcp4 被占还能用 tcp6 起来），
		// 而恢复语义要求"端口被占用 = 明确失败"，否则会留下一个只在 IPv6 可达的半死代理。
		if perr := probeTunnelPort(row.LocalPort); perr != nil {
			s.markTunnelRestoreError(row, "端口不可用（可能被其它进程占用）: "+perr.Error())
			logging.Warn("tunnel", "恢复失败（session=%s, port=%d）：端口不可用: %v（该行已标记 error，其余隧道继续恢复）",
				row.ID, row.LocalPort, perr)
			failures = append(failures, tunnelFailureSummary(row.LocalPort, perr))
			failed++
			continue
		}

		port, serr := s.startSOCKS5(row.ID, row.LocalPort, auth)
		if serr != nil {
			s.markTunnelRestoreError(row, serr.Error())
			logging.Warn("tunnel", "恢复失败（session=%s, port=%d）：%v（该行已标记 error，其余隧道继续恢复）",
				row.ID, row.LocalPort, serr)
			failures = append(failures, tunnelFailureSummary(row.LocalPort, serr))
			failed++
			continue
		}
		if merr := s.tunnelStore.MarkRestored(row.ID); merr != nil {
			// 监听已经起来了，运行态是成功的；只是"已恢复"标记没写进去，不需要回滚。
			logging.Warn("tunnel", "隧道已恢复但写入 restored 标记失败（%s）：%v", row.ID, merr)
		}
		logging.Info("tunnel", "已恢复代理：session=%s 端口=%d（auth_enabled=%v）", row.ID, port, row.AuthEnabled)
		restored++
	}

	switch {
	case failed == 0:
		logging.Info("tunnel", "restored %d/%d", restored, total)
	default:
		logging.Info("tunnel", "restored %d/%d (%d failed: %s)", restored, total, failed, strings.Join(failures, "; "))
	}
	return restored, failed
}

// tunnelRunning 判断某代理当前是否真的有运行实例（恢复前查一次，避免重复监听）。
func (s *Server) tunnelRunning(id string) bool {
	s.socks5Mu.RLock()
	defer s.socks5Mu.RUnlock()
	_, ok := s.socks5Servers[id]
	return ok
}

// markTunnelRestoreError 把一条恢复失败的记录标记为 error 并留下原因。
// 写库失败只记日志：状态没写进去也不该阻断其它隧道的恢复。
func (s *Server) markTunnelRestoreError(row *tunnelstore.Tunnel, reason string) {
	if s.tunnelStore == nil || row == nil {
		return
	}
	if err := s.tunnelStore.SetStatus(row.ID, tunnelstore.StatusError, reason); err != nil {
		logging.Warn("tunnel", "写入恢复失败状态失败（%s）：%v", row.ID, err)
	}
}

// tunnelFailureSummary 把恢复失败原因压成一行，供汇总日志使用（形如 "port 11090 in use"）。
//
// 端口占用的错误文案各平台不同（Windows: "Only one usage of each socket address..."；
// Linux: "address already in use"），这里按关键字归类——只用于人读的日志摘要，
// 不参与任何控制流，也不回显口令相关内容。
func tunnelFailureSummary(port int, err error) string {
	if err == nil {
		return fmt.Sprintf("port %d failed", port)
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "already in use by session"):
		// startSOCKS5 的进程内端口去重（两条记录抢同一端口）
		return fmt.Sprintf("port %d in use", port)
	case strings.Contains(msg, "already running for this session"):
		return fmt.Sprintf("port %d already running", port)
	case isAddrInUse(err):
		return fmt.Sprintf("port %d in use", port)
	}
	return fmt.Sprintf("port %d: %v", port, err)
}

// probeTunnelPort 在重建监听前探测端口是否可用（恢复路径专用）。
//
// 为什么不能只依赖 SOCKS5Server.Start 的返回值：
// Start 会依次尝试 tcp4 0.0.0.0 与 tcp6 [::]，只要**一个**成功就算成功。
// 实测（Windows）0.0.0.0 被别的进程占住时，[::] 仍能绑定成功 →
// 代理"启动成功"却只在 IPv6 可达，操作员用 127.0.0.1 连就是不通。
// 恢复语义要的是"端口被占用 = 明确失败并标记 error"，所以这里先探测：
//   - IPv4 全接口：任何绑定失败都算占用（与 Start 的首选监听一致）；
//   - IPv6：只有"错误表明是占用"才算失败——有些环境根本没开 IPv6，
//     "地址族不支持"不能当成端口被占，否则会把所有隧道误标 error。
//
// 探测完立即关闭，理论上与随后的 Start 之间存在极小竞态窗口（被别的进程抢走），
// 那种情况 Start 会再失败一次并由调用方兜底标记 error，不会静默半死。
func probeTunnelPort(port int) error {
	ln4, err4 := net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", port))
	if err4 != nil {
		return err4
	}
	_ = ln4.Close()

	ln6, err6 := net.Listen("tcp6", fmt.Sprintf("[::]:%d", port))
	if err6 == nil {
		_ = ln6.Close()
		return nil
	}
	if isAddrInUse(err6) {
		return err6
	}
	return nil
}

// isAddrInUse 判断错误是否表示"端口已被占用"。
// 各平台文案不同（Windows: "Only one usage of each socket address..."；
// Linux: "address already in use"），故按关键字归类——只用于日志归类与端口探测，
// 不参与其它控制流。
func isAddrInUse(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "in use") || strings.Contains(msg, "only one usage")
}
