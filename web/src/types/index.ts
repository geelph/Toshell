export interface Session {
  id: string
  hostname: string
  username: string
  os: string
  arch: string
  pid: number
  process_name: string
  process_path: string
  ip_addresses: string[]
  mac_addresses: string[]
  domain: string
  first_seen: string
  last_seen: string
  status: string
  listener: string
  remote_addr: string
  parent_relay?: string
  comment?: string
}


export interface Task {
  id: number
  session_id: string
  command: string
  args: string[]
  execute_type: string
  status: string
  created_at: string
  sent_at?: string
  completed_at?: string
  output?: string
  error?: string
  exit_code?: number
  timeout: number
}

export interface TaskStats {
  total: number
  completed: number
  failed: number
  timeout: number
  pending: number
  running: number
}

export interface LogEntry {
  id: number
  timestamp: string
  level: string
  component: string
  message: string
  session_id?: string
  task_id?: number
  source_ip?: string
}


export interface TaskRequest {
  session_id: string
  command: string
  args?: string[]
  execute_type?: string
  timeout?: number
}

/**
 * PE 版本资源 / 图标 / 公司信息 / 时间戳（v1.4.0 S3 第二批）—— 构建请求里的可选字段。
 *
 * 契约（见服务端 `internal/server/api/api.go` 的 BuildRequest 与
 * `internal/server/builder/patch_resources.go` 的 shouldPatchResources）：
 *   - **全空 = 什么都不注入**，产物与不带这些字段时逐字节一致；
 *   - 只对 **Windows** 的 `exe` / `bin` / `dll` 生效，`shellcode*` / `raw` / `so`、
 *     非 Windows 目标、`language=c`（mingw 管线）都会被服务端跳过；
 *   - `resource_icon_path` 是**服务端本地** `.ico` 路径，不是上传字节；
 *   - `resource_preset` 只认 `GET /api/v1/builders` 的 `evasion.resource_presets` 里出现过的值，
 *     语义是"只填操作员没显式给的字段"（显式字段永远优先），**名字拼错会让构建失败**。
 */
export interface PeResourceRequest {
  /** 一键套用资源预设（当前只认 "neutral"）；留空/不发送 = 不用预设 */
  resource_preset?: string
  /** 服务端本地 .ico 文件路径；留空 = 用设置里的 implant.icon_path */
  resource_icon_path?: string
  resource_company_name?: string
  resource_product_name?: string
  resource_file_description?: string
  /** 形如 1.4.0.0；留空 → 服务端用 1.0.0.0 */
  resource_file_version?: string
  resource_product_version?: string
  resource_legal_copyright?: string
  resource_original_filename?: string
  resource_internal_name?: string
  /** COFF 时间戳策略：""（不发送）/ keep（不改）/ fixed（配 resource_timestamp）/ random */
  resource_timestamp_mode?: string
  /** fixed 策略的 RFC3339 取值；留空 → 服务端内置 2024-03-15T09:00:00Z */
  resource_timestamp?: string
}

export interface ListenerInfo {
  id: string
  name: string
  type: string
  protocol: string
  bind_addr: string
  bind_port: number
  public_addr?: string
  status: string
  connections: number
  created_at: number
  options?: string
}

/**
 * 批量任务下发（POST /api/v1/tasks/bulk，v1.4.1）。
 *
 * 字段与单会话下发（TaskRequest / sessionApi.interact）同一套命名与语义：
 * task_type / command / args / execute_type / timeout —— 只是把单个 session_id
 * 换成 session_ids。服务端逐项返回结果（不是事务）：一个会话失败不影响其它会话。
 */
export interface BulkTaskRequest {
  session_ids: string[]
  /** 任务类型；留空 = command。仅允许侦察类（command/shell/sysinfo/netstat/service_list/process_list/screenshot/av_detect） */
  task_type?: string
  command?: string
  args?: string[]
  execute_type?: string
  timeout?: number
}

/** 单台会话的下发结果：ok=true 时带 task_id；失败时 error 是服务端原文。 */
export interface BulkTaskItem {
  session_id: string
  ok: boolean
  task_id?: number
  error?: string
}

/** 批量下发汇总：total == succeeded + failed == items.length。 */
export interface BulkTaskResponse {
  total: number
  succeeded: number
  failed: number
  items: BulkTaskItem[]
}
