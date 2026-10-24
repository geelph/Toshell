package tunnelstore

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"toshell/internal/server/database"
)

// testKey 32 字节 = AES-256（与 server 配置 listener.encryption_key 的实际长度一致）。
const testKey = "0123456789abcdef0123456789abcdef"

type testEnv struct {
	db *database.Database
	st *Store
}

// newTestEnv 用真实 schema（database.TunnelSchemaStatements）建一个临时库：
// 测试同时验证 DDL 本身可用——schema 只有一处定义，不会与生产漂移。
//
// 必须在 Cleanup 里关库：Windows 上 SQLite 文件被占用时 t.TempDir 的 RemoveAll 会失败，
// 用例本身全绿却整体 FAIL（agentstore 的测试注释里记过同一个坑）。
func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "tunnelstore.db")
	d, err := database.New("sqlite", dbPath)
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	st, err := New(d.SQL(), []byte(testKey))
	if err != nil {
		t.Fatalf("tunnelstore.New: %v", err)
	}
	return &testEnv{db: d, st: st}
}

// TestSchemaIsIdempotent 覆盖「DDL 幂等」：同一个库初始化两次都不报错，且表/列齐全。
func TestSchemaIsIdempotent(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "schema.db")
	d, err := database.New("sqlite", dbPath)
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	defer d.Close()

	var name string
	if err := d.SQL().QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='tunnels'`).Scan(&name); err != nil {
		t.Fatalf("tunnels 表未创建：%v", err)
	}

	// 老库升级路径：对同一个文件再初始化一次，全部 CREATE ... IF NOT EXISTS 必须幂等。
	d2, err := database.New("sqlite", dbPath)
	if err != nil {
		t.Fatalf("重复初始化应幂等（老库升级路径）：%v", err)
	}
	defer d2.Close()

	wantCols := []string{
		"id", "session_id", "local_port", "target_addr", "protocol", "mode",
		"auth_enabled", "auth_user", "auth_pass_enc", "remark", "status",
		"last_error", "restored", "created_at", "updated_at",
	}
	rows, err := d2.SQL().Query(`PRAGMA table_info(tunnels)`)
	if err != nil {
		t.Fatalf("PRAGMA table_info(tunnels): %v", err)
	}
	defer rows.Close()
	got := make(map[string]bool, len(wantCols))
	for rows.Next() {
		var cid int
		var colName, colType string
		var notNull, pk int
		var dflt interface{}
		if err := rows.Scan(&cid, &colName, &colType, &notNull, &dflt, &pk); err != nil {
			t.Fatalf("scan table_info: %v", err)
		}
		got[colName] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows.Err: %v", err)
	}
	for _, c := range wantCols {
		if !got[c] {
			t.Errorf("tunnels 缺少列 %q", c)
		}
	}
}

// TestUpsertGetListDelete 覆盖 CRUD 基本盘（含 created_at 在更新时保持不变）。
func TestUpsertGetListDelete(t *testing.T) {
	env := newTestEnv(t)
	st := env.st

	row := &Tunnel{
		ID: "sess-a", SessionID: "sess-a", LocalPort: 11190,
		Protocol: "socks5", Mode: "dynamic", Status: StatusRunning,
	}
	if err := st.Upsert(row, ""); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	got, err := st.Get("sess-a")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.LocalPort != 11190 || got.Status != StatusRunning || got.AuthEnabled || got.Restored {
		t.Fatalf("Get 结果不符：%+v", got)
	}
	if got.CreatedAt == 0 || got.UpdatedAt == 0 {
		t.Fatalf("时间戳未写入：%+v", got)
	}

	// 二次 Upsert（同 id）应更新而非报错，且保留 created_at。
	created := got.CreatedAt
	row.LocalPort = 11191
	row.Remark = "备注"
	if err := st.Upsert(row, ""); err != nil {
		t.Fatalf("二次 Upsert: %v", err)
	}
	got2, err := st.Get("sess-a")
	if err != nil {
		t.Fatalf("Get after update: %v", err)
	}
	if got2.LocalPort != 11191 || got2.Remark != "备注" {
		t.Fatalf("更新未生效：%+v", got2)
	}
	if got2.CreatedAt != created {
		t.Fatalf("更新不应改 created_at：%d → %d", created, got2.CreatedAt)
	}

	list, err := st.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 || list[0].ID != "sess-a" {
		t.Fatalf("List 结果不符：%+v", list)
	}

	if err := st.Delete("sess-a"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := st.Get("sess-a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("删除后 Get 应返回 ErrNotFound，实际：%v", err)
	}
	// 幂等：删除不存在的记录也成功（HTTP DELETE 语义）。
	if err := st.Delete("sess-a"); err != nil {
		t.Fatalf("重复 Delete 应幂等：%v", err)
	}
}

// TestPasswordEncryptedAtRest 覆盖安全要求：口令绝不明文落库，且能解密回原值。
func TestPasswordEncryptedAtRest(t *testing.T) {
	env := newTestEnv(t)
	const pass = "s3cret-pass-9"
	if err := env.st.Upsert(&Tunnel{
		ID: "sess-auth", SessionID: "sess-auth", LocalPort: 11192,
		AuthEnabled: true, AuthUser: "operator-x", Status: StatusRunning,
	}, pass); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	// 直接读原始列：必须是 v1: 前缀的密文，且不含口令明文。
	var raw string
	if err := env.db.SQL().QueryRow(`SELECT auth_pass_enc FROM tunnels WHERE id = ?`, "sess-auth").Scan(&raw); err != nil {
		t.Fatalf("读 auth_pass_enc: %v", err)
	}
	if raw == "" || !strings.HasPrefix(raw, cipherPrefix) {
		t.Fatalf("auth_pass_enc 不是预期的密文格式：%q", raw)
	}
	if strings.Contains(raw, pass) {
		t.Fatalf("口令明文出现在库里：%q", raw)
	}

	// 解密回原值（恢复流程用），且列表模型不含口令字段。
	plain, err := env.st.DecryptPassword("sess-auth")
	if err != nil {
		t.Fatalf("DecryptPassword: %v", err)
	}
	if plain != pass {
		t.Fatalf("解密结果不符：%q", plain)
	}
	// 未启用认证时，密文列为空、解密返回空串。
	if err := env.st.Upsert(&Tunnel{ID: "sess-noauth", LocalPort: 11193, Status: StatusRunning}, ""); err != nil {
		t.Fatalf("Upsert(no auth): %v", err)
	}
	if p, err := env.st.DecryptPassword("sess-noauth"); err != nil || p != "" {
		t.Fatalf("无认证记录应解出空口令，实际 (%q, %v)", p, err)
	}
}

// TestDecryptPasswordFailsClosedAfterKeyRotation 覆盖「换密钥后解密失败」：
// 必须返回错误，好让恢复流程拒绝以"无认证"方式重建（否则等于静默降级为裸代理）。
func TestDecryptPasswordFailsClosedAfterKeyRotation(t *testing.T) {
	env := newTestEnv(t)
	if err := env.st.Upsert(&Tunnel{
		ID: "sess-rot", SessionID: "sess-rot", LocalPort: 11194,
		AuthEnabled: true, AuthUser: "u", Status: StatusRunning,
	}, "pass-1"); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	other, err := New(env.db.SQL(), []byte("ffffffffffffffffffffffffffffffff"))
	if err != nil {
		t.Fatalf("New(other key): %v", err)
	}
	if _, err := other.DecryptPassword("sess-rot"); err == nil {
		t.Fatal("换了密钥后解密必须失败（否则会静默降级为无认证代理）")
	}
	// 不存在的记录 → ErrNotFound。
	if _, err := env.st.DecryptPassword("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("不存在记录应返回 ErrNotFound，实际：%v", err)
	}
}

// TestInvalidKeyDegradesAuthOnly 覆盖"密钥长度配错"的降级：
// 无认证隧道照常落库/恢复，带认证的写入与解密 fail-closed（绝不存明文）。
func TestInvalidKeyDegradesAuthOnly(t *testing.T) {
	env := newTestEnv(t)
	bad, err := New(env.db.SQL(), []byte("short-key"))
	if err != nil {
		t.Fatalf("密钥非法不应让 Store 构造失败：%v", err)
	}
	if bad.AuthEncryptionAvailable() {
		t.Fatal("非法密钥不应报告加密可用")
	}
	if _, err := bad.DecryptPassword("nope"); err == nil || !errors.Is(err, ErrNotFound) {
		t.Fatalf("不存在的记录应返回 ErrNotFound，实际：%v", err)
	}
	// 无认证：正常落库。
	if err := bad.Upsert(&Tunnel{ID: "sess-plain", LocalPort: 11196, Status: StatusRunning}, ""); err != nil {
		t.Fatalf("无认证隧道不应受密钥影响：%v", err)
	}
	// 带认证：拒绝写入（不许明文落库）。
	err = bad.Upsert(&Tunnel{
		ID: "sess-auth2", SessionID: "sess-auth2", LocalPort: 11197,
		AuthEnabled: true, AuthUser: "u", Status: StatusRunning,
	}, "p")
	if !errors.Is(err, ErrNoKey) {
		t.Fatalf("带认证写入应返回 ErrNoKey，实际：%v", err)
	}
}

// TestSetStatusAndMarkRestored 覆盖重启恢复要写的两个状态位。
func TestSetStatusAndMarkRestored(t *testing.T) {
	env := newTestEnv(t)
	if err := env.st.Upsert(&Tunnel{ID: "sess-s", LocalPort: 11195, Status: StatusRunning}, ""); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	// 先恢复成功一次（restored=1），再失败：失败要同时清掉"已恢复"标记，
	// 否则列表会同时显示"已恢复"和"恢复失败"。
	if err := env.st.MarkRestored("sess-s"); err != nil {
		t.Fatalf("MarkRestored: %v", err)
	}
	if err := env.st.SetStatus("sess-s", StatusError, "port 11195 in use"); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}
	got, err := env.st.Get("sess-s")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != StatusError || !strings.Contains(got.LastError, "in use") {
		t.Fatalf("error 状态未落库：%+v", got)
	}
	if got.Restored {
		t.Fatalf("恢复失败时应清掉 restored 标记：%+v", got)
	}
	if err := env.st.MarkRestored("sess-s"); err != nil {
		t.Fatalf("MarkRestored: %v", err)
	}
	got2, err := env.st.Get("sess-s")
	if err != nil {
		t.Fatalf("Get after MarkRestored: %v", err)
	}
	if !got2.Restored || got2.Status != StatusRunning || got2.LastError != "" {
		t.Fatalf("MarkRestored 结果不符：%+v", got2)
	}
}
