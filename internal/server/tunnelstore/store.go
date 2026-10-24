// Package tunnelstore 持久化「隧道/代理」资源：SOCKS5 代理监听器落库，
// 服务端重启后按库逐条重建（v1.4.1）。
//
// 为什么需要它：v1.4.0 及之前，代理只活在 api.Server.socks5Servers 这个内存 map 里，
// 进程重启 = 所有代理凭空消失，操作员必须手工重建（真实可运营性缺陷）。
// 现在「期望存在的代理」是库里的行，重启恢复只是按行重新监听。
//
// 表结构由 `internal/server/database` 的 TunnelSchemaStatements 统一创建（单一来源），
// 本包只做 CRUD，不建表、不做迁移。时间戳统一用 **Unix 秒**，与 database.go 既有做法一致。
//
// 安全边界（重要）：
//   - 代理口令**绝不明文落库**：auth_pass_enc 存 `v1:` + base64(AES-256-GCM(nonce||密文))，
//     密钥来自配置 listener.encryption_key（经 internal/common/crypto 构造）；
//   - 未配置可用密钥时，带认证的代理**拒绝落库**（fail-closed），而不是默默存明文；
//   - 本包只提供 DecryptPassword 给恢复流程用，任何 HTTP 响应都不得调用它回显口令。
package tunnelstore

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"toshell/internal/common/crypto"
)

// 隧道状态取值（写库的是字符串，便于人工排查）。
const (
	// StatusRunning 代理应处于监听状态（创建成功 / 重启恢复成功）。
	StatusRunning = "running"
	// StatusError 上次创建或恢复失败，last_error 里是原因（端口占用等）。
	// 该状态的行**留库不删**：下次重启仍会重试，且操作员能在列表里看到失败原因。
	StatusError = "error"
)

// cipherPrefix 密文版本前缀。带版本是为了将来换算法/换密钥时能识别老数据。
const cipherPrefix = "v1:"

// ErrNotFound 目标记录不存在。
var ErrNotFound = errors.New("tunnelstore: record not found")

// ErrNoKey 未配置可用的加密密钥，无法安全保存代理口令。
var ErrNoKey = errors.New("tunnelstore: 未配置可用的加密密钥（listener.encryption_key），拒绝保存代理口令")

// Tunnel 一个持久化的隧道/代理资源。
//
// 注意：本结构体是**库模型**，不含口令明文；口令只在 Upsert / DecryptPassword
// 的参数/返回值里出现，不进入结构体字段，避免它被随手 JSON 序列化出去。
type Tunnel struct {
	ID        string
	SessionID string
	LocalPort int
	// TargetAddr 静态转发的目标地址；SOCKS5 动态代理（当前实现）为空。
	TargetAddr string
	// Protocol 监听器协议：socks5（同端口兼容 HTTP CONNECT）。
	Protocol string
	// Mode dynamic（目标由客户端每条连接指定）/ static（预留）。
	Mode        string
	AuthEnabled bool
	AuthUser    string
	Remark      string
	Status      string
	LastError   string
	// Restored 本次启动是否由「重启恢复」重建（供 API/前端标注，不影响恢复判定）。
	Restored  bool
	CreatedAt int64
	UpdatedAt int64
}

// Store 是 sqlite 上的一层薄 CRUD（不持有连接池生命周期）。
type Store struct {
	db *sql.DB
	// enc 代理口令的 AES-GCM 加密器；nil = 密钥不可用（此时只允许无认证隧道落库）。
	enc *crypto.Encryptor
	// keyErr 密钥不可用的原因（只在日志/错误里出现，不含密钥内容）。
	keyErr error
}

// New 包装一个已初始化的连接（来自 database.Get().SQL()）与加密密钥。
//
// key 应为 16/24/32 字节（AES-128/192/256）。**密钥非法不返回错误**：
// Store 仍可正常保存/恢复「无认证」隧道，只有需要口令的写入与解密返回 ErrNoKey
// （fail-closed，绝不退化成明文存储）。这样一次密钥长度配错不会让所有代理
// 都失去重启恢复能力——那属于过度降级。
func New(db *sql.DB, key []byte) (*Store, error) {
	if db == nil {
		return nil, errors.New("tunnelstore: nil database handle")
	}
	st := &Store{db: db}
	enc, err := crypto.NewAESEncryptor(key)
	if err != nil {
		st.keyErr = err
	} else {
		st.enc = enc
	}
	return st, nil
}

// AuthEncryptionAvailable 报告代理口令加密是否可用（供启动日志提示，不影响无认证隧道）。
func (s *Store) AuthEncryptionAvailable() bool {
	return s != nil && s.enc != nil
}

// Upsert 插入或更新一条隧道记录（创建路径）。
//
// authPass 只在 auth_enabled=true 时有意义：加密后写 auth_pass_enc；
// 未启用认证时该列写空串（旧的空口令不会残留）。
// 更新已有行时保留原 created_at（创建时间只由第一次插入决定）。
func (s *Store) Upsert(t *Tunnel, authPass string) error {
	if t == nil {
		return errors.New("tunnelstore: nil tunnel")
	}
	if t.ID == "" {
		return errors.New("tunnelstore: id is required")
	}
	if t.SessionID == "" {
		t.SessionID = t.ID
	}
	if t.Protocol == "" {
		t.Protocol = "socks5"
	}
	if t.Mode == "" {
		t.Mode = "dynamic"
	}
	if t.Status == "" {
		t.Status = StatusRunning
	}

	passEnc, err := s.encryptPass(t.AuthEnabled, authPass)
	if err != nil {
		return err
	}

	now := time.Now().Unix()
	if t.CreatedAt == 0 {
		t.CreatedAt = now
	}
	t.UpdatedAt = now

	_, err = s.db.Exec(`
		INSERT INTO tunnels (id, session_id, local_port, target_addr, protocol, mode,
			auth_enabled, auth_user, auth_pass_enc, remark, status, last_error, restored,
			created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			session_id    = excluded.session_id,
			local_port    = excluded.local_port,
			target_addr   = excluded.target_addr,
			protocol      = excluded.protocol,
			mode          = excluded.mode,
			auth_enabled  = excluded.auth_enabled,
			auth_user     = excluded.auth_user,
			auth_pass_enc = excluded.auth_pass_enc,
			remark        = excluded.remark,
			status        = excluded.status,
			last_error    = excluded.last_error,
			restored      = excluded.restored,
			updated_at    = excluded.updated_at
	`, t.ID, t.SessionID, t.LocalPort, t.TargetAddr, t.Protocol, t.Mode,
		boolToInt(t.AuthEnabled), t.AuthUser, passEnc, t.Remark, t.Status, t.LastError,
		boolToInt(t.Restored), t.CreatedAt, t.UpdatedAt)
	return err
}

// Get 按 id 取一条；不存在返回 ErrNotFound。
func (s *Store) Get(id string) (*Tunnel, error) {
	row := s.db.QueryRow(`
		SELECT id, session_id, local_port, target_addr, protocol, mode,
			auth_enabled, auth_user, remark, status, last_error, restored, created_at, updated_at
		FROM tunnels WHERE id = ?`, id)
	return scanTunnel(row)
}

// List 返回全部隧道记录（按创建时间升序：稳定顺序，恢复按创建顺序重建监听）。
func (s *Store) List() ([]*Tunnel, error) {
	rows, err := s.db.Query(`
		SELECT id, session_id, local_port, target_addr, protocol, mode,
			auth_enabled, auth_user, remark, status, last_error, restored, created_at, updated_at
		FROM tunnels ORDER BY created_at ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*Tunnel
	for rows.Next() {
		t, serr := scanTunnel(rows)
		if serr != nil {
			return nil, serr
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Delete 硬删除一条隧道记录。
//
// 为什么选「删库」而不是「标记 closed 再在列表里过滤」：
//   - 行语义是「期望存在的代理」，closed 行不再期望存在，留着只会越积越多；
//   - 过滤会让**每个**读取路径（列表/恢复/统计）都必须记得跳过 closed，
//     漏一处就是幽灵代理；硬删只有一处真相，且 DELETE 天然幂等（删两次都成功）；
//   - 审计不靠这张表：创建/关闭都会写 logging（见 handlers_tunnels.go）。
func (s *Store) Delete(id string) error {
	_, err := s.db.Exec(`DELETE FROM tunnels WHERE id = ?`, id)
	return err
}

// SetStatus 更新状态与失败原因（恢复失败标记 error 用；恢复成功用 MarkRestored）。
// lastError 传空串表示清除旧错误。
//
// 同时把 restored 归零：本次启动并没有真的重建监听，不能因为"上一次启动恢复过"
// 就让列表同时显示"已恢复"和"恢复失败"（前端两个角标会自相矛盾）。
func (s *Store) SetStatus(id, status, lastError string) error {
	_, err := s.db.Exec(`UPDATE tunnels SET status = ?, last_error = ?, restored = 0, updated_at = ? WHERE id = ?`,
		status, lastError, time.Now().Unix(), id)
	return err
}

// MarkRestored 标记「本次启动已由重启恢复重建」并清掉旧错误。
func (s *Store) MarkRestored(id string) error {
	now := time.Now().Unix()
	_, err := s.db.Exec(`UPDATE tunnels SET status = ?, last_error = '', restored = 1, updated_at = ? WHERE id = ?`,
		StatusRunning, now, id)
	return err
}

// DecryptPassword 解出代理口令（只给恢复流程用；任何 API 响应都不许调用）。
//
// 解密失败一律返回错误：调用方必须**拒绝**以「无认证」方式重建该代理
// （否则一次密钥变更就会把带认证的入口静默降级成裸代理）。
func (s *Store) DecryptPassword(id string) (string, error) {
	var enabled int
	var encPass string
	err := s.db.QueryRow(`SELECT auth_enabled, auth_pass_enc FROM tunnels WHERE id = ?`, id).
		Scan(&enabled, &encPass)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", err
	}
	if enabled == 0 {
		return "", nil
	}
	if encPass == "" {
		return "", errors.New("tunnelstore: 记录要求认证但库里没有口令密文（旧数据/被清空）")
	}
	if s.enc == nil {
		if s.keyErr != nil {
			return "", fmt.Errorf("%w: %v", ErrNoKey, s.keyErr)
		}
		return "", ErrNoKey
	}
	if !strings.HasPrefix(encPass, cipherPrefix) {
		return "", fmt.Errorf("tunnelstore: 未知的口令密文格式（缺少 %q 前缀）", cipherPrefix)
	}
	raw, derr := base64.StdEncoding.DecodeString(strings.TrimPrefix(encPass, cipherPrefix))
	if derr != nil {
		return "", fmt.Errorf("tunnelstore: 口令密文 base64 解码失败: %w", derr)
	}
	plain, oerr := s.enc.Decrypt(raw)
	if oerr != nil {
		return "", fmt.Errorf("tunnelstore: 口令密文解密失败（加密密钥可能已变更）: %w", oerr)
	}
	return string(plain), nil
}

// encryptPass 加密代理口令；未启用认证时返回空串。
func (s *Store) encryptPass(enabled bool, pass string) (string, error) {
	if !enabled || pass == "" {
		return "", nil
	}
	if s.enc == nil {
		if s.keyErr != nil {
			return "", fmt.Errorf("%w: %v", ErrNoKey, s.keyErr)
		}
		return "", ErrNoKey
	}
	ct, err := s.enc.Encrypt([]byte(pass))
	if err != nil {
		return "", fmt.Errorf("tunnelstore: 口令加密失败: %w", err)
	}
	return cipherPrefix + base64.StdEncoding.EncodeToString(ct), nil
}

// rowScanner 抽象 *sql.Row / *sql.Rows 的 Scan（两者签名一致）。
type rowScanner interface {
	Scan(dest ...interface{}) error
}

func scanTunnel(r rowScanner) (*Tunnel, error) {
	var t Tunnel
	var authEnabled, restored int
	err := r.Scan(&t.ID, &t.SessionID, &t.LocalPort, &t.TargetAddr, &t.Protocol, &t.Mode,
		&authEnabled, &t.AuthUser, &t.Remark, &t.Status, &t.LastError, &restored,
		&t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	t.AuthEnabled = authEnabled != 0
	t.Restored = restored != 0
	return &t, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
