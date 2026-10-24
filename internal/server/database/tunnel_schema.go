package database

// TunnelSchemaStatements 是 v1.4.1 新增的「隧道/代理持久化」建表语句。
//
// 背景（真实缺陷）：v1.4.0 及之前，SOCKS5 代理只存在服务端内存里
// （api.Server.socks5Servers），进程一重启所有代理全丢，操作员必须手工重建。
// 这里把「期望存在哪些代理」落库，启动时按库逐条重建监听。
//
// 设计要点（与 agent_schema.go 同一风格）：
//   - 全部 `CREATE TABLE/INDEX IF NOT EXISTS`：对既有库幂等，不动任何既有表、
//     不做破坏性 DDL，老库直接升级，回滚也只是多一张没人查的空表；
//   - 表由 database.initTables 统一创建（单一来源），tunnelstore 包只做 CRUD。
//
// 字段说明：
//   - id / session_id：当前实现是「每个会话最多一个代理」，DELETE /api/v1/tunnels/{id}
//     在 v1.4.1 之前就把 {id} 当 session id 用，所以这里 id 与 session_id 同值，
//     保留两列是为了自解释与将来「一个会话多个代理」的扩展（id 变成真正资源 id）；
//   - local_port：代理监听端口（重启后按它重新监听）；
//   - target_addr / mode：当前是 SOCKS5 动态代理（目标由客户端每条连接自己指定），
//     target_addr 暂为空、mode='dynamic'；预留给将来的静态端口转发，不参与恢复逻辑；
//   - protocol：监听器协议（socks5；同一端口同时兼容 HTTP CONNECT 正向代理）；
//   - auth_enabled / auth_user / auth_pass_enc：代理认证。**口令绝不明文落库**：
//     auth_pass_enc 存的是 internal/common/crypto 的 AES-256-GCM 密文（nonce||密文 的
//     base64），密钥来自配置里的 listener.encryption_key；口令/用户名也绝不通过 API 回传，
//     API 只回 auth_enabled；
//   - status：running（应在监听）/ error（上次恢复或创建失败，last_error 给原因）；
//   - restored：0/1，本次启动是否由「重启恢复」重建（API 回 restored，供前端标注）；
//   - created_at / updated_at：Unix 秒，与 database.go 既有表一致。
var TunnelSchemaStatements = []string{
	`CREATE TABLE IF NOT EXISTS tunnels (
		id            TEXT PRIMARY KEY,
		session_id    TEXT NOT NULL,
		local_port    INTEGER NOT NULL,
		target_addr   TEXT NOT NULL DEFAULT '',
		protocol      TEXT NOT NULL DEFAULT 'socks5',
		mode          TEXT NOT NULL DEFAULT 'dynamic',
		auth_enabled  INTEGER NOT NULL DEFAULT 0,
		auth_user     TEXT NOT NULL DEFAULT '',
		auth_pass_enc TEXT NOT NULL DEFAULT '',
		remark        TEXT NOT NULL DEFAULT '',
		status        TEXT NOT NULL,
		last_error    TEXT NOT NULL DEFAULT '',
		restored      INTEGER NOT NULL DEFAULT 0,
		created_at    INTEGER NOT NULL,
		updated_at    INTEGER NOT NULL
	)`,
	`CREATE INDEX IF NOT EXISTS idx_tunnels_status  ON tunnels(status)`,
	`CREATE INDEX IF NOT EXISTS idx_tunnels_session ON tunnels(session_id)`,
}
