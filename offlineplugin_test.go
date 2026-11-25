package offlineplugin

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTestEnv 构造一个含 2 个独立签发者 + 1 个挂名代理的临时仓库。
func newTestEnv(t *testing.T) (*Store, *Registry, map[string]*Signer) {
	t.Helper()
	root := t.TempDir()
	st, err := NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	specs := []struct {
		id        string
		kind      IssuerKind
		principal string
	}{
		{"ia", KindIndependent, ""},
		{"ib", KindIndependent, ""},
		{"pa", KindProxy, "ia"},
	}
	reg := &Registry{}
	signers := make(map[string]*Signer)
	for _, sp := range specs {
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		is := Issuer{ID: sp.id, Kind: sp.kind, PublicKey: pub, PrincipalID: sp.principal}
		reg.Issuers = append(reg.Issuers, is)
		signers[sp.id] = NewSigner(is, priv)
	}
	reg.index()
	return st, reg, signers
}

func writeDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func sign(t *testing.T, signers map[string]*Signer, c Codename, d Digest, ids ...string) []SignedApproval {
	t.Helper()
	var out []SignedApproval
	for _, id := range ids {
		a, sig, err := signers[id].SignApproval(c, d, 3600)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, SignedApproval{Approval: a, Signature: sig})
	}
	return out
}

func digest(t *testing.T, src string, c Codename) Digest {
	t.Helper()
	m, err := BuildManifest(src, c)
	if err != nil {
		t.Fatal(err)
	}
	d, err := DigestManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// reopen 用新句柄重新打开同一仓库，模拟“重启后只凭磁盘恢复”。
func reopen(st *Store) *Store {
	s2, err := NewStore(st.Root)
	if err != nil {
		panic(err)
	}
	return s2
}

// 摘要确定性：同样内容、不同临时路径，摘要必须一致；改一个字节摘要必变。
func TestManifestDigestDeterministic(t *testing.T) {
	c := Codename("x")
	d1 := digest(t, writeDir(t, map[string]string{"a/b.txt": "hello", "c.txt": "world"}), c)
	d2 := digest(t, writeDir(t, map[string]string{"c.txt": "world", "a/b.txt": "hello"}), c)
	if d1 != d2 {
		t.Fatalf("同内容目录摘要不一致: %s vs %s", d1, d2)
	}
	d3 := digest(t, writeDir(t, map[string]string{"a/b.txt": "hellX", "c.txt": "world"}), c)
	if d3 == d1 {
		t.Fatal("改一个字节后摘要应当变化")
	}
}

// 挂名代理与本人合计只算一票；两个独立签发者才达标。
func TestProxyDoesNotCountAsTwo(t *testing.T) {
	_, reg, signers := newTestEnv(t)
	c, d := Codename("p"), Digest("deadbeef")
	bundles := sign(t, signers, c, d, "ia", "pa")
	n, err := CountIndependentApprovals(reg, c, d,
		approvalsOf(bundles), sigsOf(bundles))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("本人+代理应只算 1 个真实签发者，实际 %d", n)
	}
	bundles2 := sign(t, signers, c, d, "ia", "pa", "ib")
	n2, err := CountIndependentApprovals(reg, c, d, approvalsOf(bundles2), sigsOf(bundles2))
	if err != nil {
		t.Fatal(err)
	}
	if n2 != 2 {
		t.Fatalf("加入第二个独立签发者后应为 2 票，实际 %d", n2)
	}
}

// 批准覆盖异摘要必须被拒绝。
func TestApprovalDigestBinding(t *testing.T) {
	_, reg, signers := newTestEnv(t)
	c := Codename("p")
	bundles := sign(t, signers, c, Digest("aaaa"), "ia")
	bundles = append(bundles, sign(t, signers, c, Digest("bbbb"), "ib")...)
	if _, err := CountIndependentApprovals(reg, c, Digest("aaaa"),
		approvalsOf(bundles), sigsOf(bundles)); err == nil {
		t.Fatal("异摘要批准应当报错")
	}
}

// 篡改批准的一个字节后验签必须失败。
func TestTamperedApprovalRejected(t *testing.T) {
	_, reg, signers := newTestEnv(t)
	c, d := Codename("p"), Digest("aaaa")
	a, sig, err := signers["ia"].SignApproval(c, d, 3600)
	if err != nil {
		t.Fatal(err)
	}
	a.Serial++
	if err := VerifyApproval(reg, a, sig); err == nil {
		t.Fatal("被篡改的批准应当验签失败")
	}
}

// 完整往返：合法发布后，全新 Verifier 只凭磁盘判定健康。
func TestPublishAndIndependentVerify(t *testing.T) {
	st, reg, signers := newTestEnv(t)
	c := Codename("plug")
	src := writeDir(t, map[string]string{"app.exe": "v1"})
	d := digest(t, src, c)
	pub := NewPublisher(st, reg)
	if _, err := pub.Publish(src, c, sign(t, signers, c, d, "ia", "ib"), Hooks{}); err != nil {
		t.Fatal(err)
	}
	v := NewVerifier(reopen(st), reg) // 新 Store、新 Verifier，只信磁盘
	check, err := v.CheckPointer(c)
	if err != nil {
		t.Fatal(err)
	}
	if !check.Healthy || check.Pointer.Digest != string(d) {
		t.Fatalf("独立验证未通过: %+v", check.Problems)
	}
}

// 三个崩溃点各自的恢复结果。硬化协议中回执先于指针：
// 前两个崩溃点下指针从未离开旧版，结果是“保留当前合法版本”；
// 半成品目录仍会被隔离。真正的回退由“指针引用了不可用版本”触发（见下例）。
func TestCrashPointsRecovery(t *testing.T) {
	cases := []struct {
		name       string
		crash      CrashPoint
		wantNew    bool // 恢复后指针是否应指向新版本 d2；false 表示留在旧版 d1
		quarantine int
	}{
		{"回执前崩溃", CrashAfterStage, false, 1},
		{"回执后指针前崩溃", CrashAfterReceipt, false, 0},
		{"指针后崩溃", CrashAfterPointer, true, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st, reg, signers := newTestEnv(t)
			c := Codename("plug")
			pub := NewPublisher(st, reg)
			v1 := writeDir(t, map[string]string{"a.txt": "one"})
			d1 := digest(t, v1, c)
			if _, err := pub.Publish(v1, c, sign(t, signers, c, d1, "ia", "ib"), Hooks{}); err != nil {
				t.Fatal(err)
			}
			v2 := writeDir(t, map[string]string{"a.txt": "two"})
			d2 := digest(t, v2, c)
			if _, err := pub.Publish(v2, c, sign(t, signers, c, d2, "ia", "ib"),
				Hooks{Crash: tc.crash}); !errors.Is(err, ErrInjectedCrash) {
				t.Fatalf("期望注入崩溃，实际 %v", err)
			}
			rep, err := NewVerifier(reopen(st), reg).Recover(c)
			if err != nil {
				t.Fatal(err)
			}
			wantDigest := d1
			if tc.wantNew {
				wantDigest = d2
			}
			if rep.Outcome != OutcomeKeptCurrent || rep.PointerAfter != string(wantDigest) {
				t.Fatalf("应保留版本 %s，实际 outcome=%s after=%s", short(string(wantDigest)), rep.Outcome, short(rep.PointerAfter))
			}
			if len(rep.Quarantined) != tc.quarantine {
				t.Fatalf("隔离目录数 = %d，期望 %d", len(rep.Quarantined), tc.quarantine)
			}
		})
	}
}

// 指针已指向某版本后该版本被撤销：恢复必须沿承诺历史回退到旧版。
func TestRevokedPointerRollsBack(t *testing.T) {
	st, reg, signers := newTestEnv(t)
	c := Codename("plug")
	pub := NewPublisher(st, reg)
	v1 := writeDir(t, map[string]string{"a.txt": "one"})
	d1 := digest(t, v1, c)
	if _, err := pub.Publish(v1, c, sign(t, signers, c, d1, "ia", "ib"), Hooks{}); err != nil {
		t.Fatal(err)
	}
	v2 := writeDir(t, map[string]string{"a.txt": "two"})
	d2 := digest(t, v2, c)
	if _, err := pub.Publish(v2, c, sign(t, signers, c, d2, "ia", "ib"), Hooks{}); err != nil {
		t.Fatal(err)
	}
	if _, err := pub.Revoke(signers["ib"], d2, "召回", CrashAfterRevocation); !errors.Is(err, ErrInjectedCrash) {
		t.Fatalf("期望撤销落盘后崩溃")
	}
	rep, err := NewVerifier(reopen(st), reg).Recover(c)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Outcome != OutcomeRolledBack || rep.PointerAfter != string(d1) || rep.Fallback != d1 {
		t.Fatalf("应回退旧版 d1，实际 %+v", rep)
	}
	if len(rep.Revoked) != 1 || rep.Revoked[0] != d2 {
		t.Fatalf("d2 应原地冻结为已撤销，实际 %+v", rep.Revoked)
	}
}

// 撤销落盘后，同摘要再发布必须被拒绝；恢复只保留旧版。
func TestRevocationBlocksRepublish(t *testing.T) {
	st, reg, signers := newTestEnv(t)
	c := Codename("plug")
	pub := NewPublisher(st, reg)
	v1 := writeDir(t, map[string]string{"a.txt": "one"})
	d1 := digest(t, v1, c)
	if _, err := pub.Publish(v1, c, sign(t, signers, c, d1, "ia", "ib"), Hooks{}); err != nil {
		t.Fatal(err)
	}
	v2 := writeDir(t, map[string]string{"a.txt": "two"})
	d2 := digest(t, v2, c)
	// 先完整发布 d2（指针已切换），再撤销它：恢复时必须回退到 d1。
	if _, err := pub.Publish(v2, c, sign(t, signers, c, d2, "ia", "ib"), Hooks{}); err != nil {
		t.Fatal(err)
	}
	if _, err := pub.Revoke(signers["ib"], d2, "召回", CrashNone); err != nil {
		t.Fatal(err)
	}
	_, err := pub.Publish(v2, c, sign(t, signers, c, d2, "ia", "ib"), Hooks{})
	var revoked *RevokedError
	if !errors.As(err, &revoked) {
		t.Fatalf("期望 RevokedError，实际 %v", err)
	}
	rep, err := NewVerifier(reopen(st), reg).Recover(c)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Outcome != OutcomeRolledBack || rep.PointerAfter != string(d1) {
		t.Fatalf("应回退旧版，实际 %+v", rep)
	}
}

// 两个发布者竞争：后写者 CAS 失败，先写者的指针不动。
func TestPointerCASContention(t *testing.T) {
	st, reg, signers := newTestEnv(t)
	c := Codename("plug")
	pubA, pubB := NewPublisher(st, reg), NewPublisher(reopen(st), reg)
	srcA := writeDir(t, map[string]string{"a.txt": "A"})
	srcB := writeDir(t, map[string]string{"a.txt": "B"})
	dA, dB := digest(t, srcA, c), digest(t, srcB, c)
	if _, err := pubA.Publish(srcA, c, sign(t, signers, c, dA, "ia", "ib"), Hooks{}); err != nil {
		t.Fatal(err)
	}
	// B 基于过期的 expect（空指针）做 CAS，必须冲突。
	err := st.compareAndSwapPointer(c, "", Pointer{Codename: string(c), Digest: string(dB)})
	var casErr *CASConflictError
	if !errors.As(err, &casErr) {
		t.Fatalf("期望 CASConflictError，实际 %v", err)
	}
	// B 走完整协议则正常接力（基于 dA 的 CAS）。
	res, err := pubB.Publish(srcB, c, sign(t, signers, c, dB, "ia", "ib"), Hooks{})
	if err != nil || !res.Switched || res.Previous != dA {
		t.Fatalf("B 接力切换失败: %+v, %v", res, err)
	}
}

// 缓存扫描：局部变更只重读变更文件，且摘要与无缓存口径一致。
func TestCachedScannerReRead(t *testing.T) {
	c := Codename("plug")
	dir := writeDir(t, map[string]string{
		"a.txt": "1", "b.txt": "2", "sub/c.txt": "3",
	})
	cs := NewCachedScanner(c)
	r0, err := cs.Scan(dir, "cold")
	if err != nil {
		t.Fatal(err)
	}
	if r0.Stats.FilesReHashed != 3 {
		t.Fatalf("冷扫描应重读 3 个文件，实际 %d", r0.Stats.FilesReHashed)
	}
	r1, err := cs.Scan(dir, "warm")
	if err != nil {
		t.Fatal(err)
	}
	if r1.Stats.CacheHits != 3 || r1.Stats.BytesReHashed != 0 || r1.Digest != r0.Digest {
		t.Fatalf("热扫描应全部命中且摘要不变: %+v", r1.Stats)
	}
	p := filepath.Join(dir, "b.txt")
	if err := os.WriteFile(p, []byte("22"), 0o644); err != nil {
		t.Fatal(err)
	}
	r2, err := cs.Scan(dir, "partial")
	if err != nil {
		t.Fatal(err)
	}
	if r2.Stats.FilesReHashed != 1 || r2.Stats.CacheHits != 2 {
		t.Fatalf("局部变更应只重读 1 个文件: %+v", r2.Stats)
	}
	// 无缓存重算摘要必须与缓存路径一致。
	m, err := BuildManifest(dir, c)
	if err != nil {
		t.Fatal(err)
	}
	full, err := DigestManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	if full != r2.Digest {
		t.Fatal("缓存扫描摘要与全量重算不一致")
	}
}

// 历史半行在恢复时被截断，完整行仍然有效。
func TestHistoryTornLineRepair(t *testing.T) {
	st, reg, signers := newTestEnv(t)
	c := Codename("plug")
	pub := NewPublisher(st, reg)
	src := writeDir(t, map[string]string{"a.txt": "v"})
	d := digest(t, src, c)
	if _, err := pub.Publish(src, c, sign(t, signers, c, d, "ia", "ib"), Hooks{}); err != nil {
		t.Fatal(err)
	}
	// 追加一条合法行，再追加一段崩溃半行。
	good := HistoryEntry{Codename: string(c), Digest: "bb", Previous: string(d), SwitchedAtUnix: 1}
	line, err := canonicalJSON(good)
	if err != nil {
		t.Fatal(err)
	}
	if err := AppendLine(st.historyPath(c), line); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(st.historyPath(c), os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"codename":"plug","digest":"cc","partia`); err != nil {
		t.Fatal(err)
	}
	f.Close()
	v := NewVerifier(reopen(st), reg)
	n, err := v.repairHistory(c)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("应截断 1 行坏尾部，实际 %d", n)
	}
	hist, err := reopen(st).ReadHistory(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 2 || hist[1].Digest != "bb" {
		t.Fatalf("完整历史行应保留，实际 %+v", hist)
	}
}

// ScanDisk 不带任何调用方参数，独立枚举仓库：健康代号、孤儿版本都要被发现。
func TestScanDiskFindsOrphans(t *testing.T) {
	st, reg, signers := newTestEnv(t)
	c := Codename("plug")
	pub := NewPublisher(st, reg)
	v1 := writeDir(t, map[string]string{"a.txt": "one"})
	d1 := digest(t, v1, c)
	if _, err := pub.Publish(v1, c, sign(t, signers, c, d1, "ia", "ib"), Hooks{}); err != nil {
		t.Fatal(err)
	}
	v2 := writeDir(t, map[string]string{"a.txt": "two"})
	d2 := digest(t, v2, c)
	if _, err := pub.Publish(v2, c, sign(t, signers, c, d2, "ia", "ib"), Hooks{}); err != nil {
		t.Fatal(err)
	}
	rep, err := NewVerifier(reopen(st), reg).ScanDisk()
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Codenames) != 1 || !rep.Codenames[0].Check.Healthy {
		t.Fatalf("应扫出 1 个健康代号，实际 %+v", rep.Codenames)
	}
	if len(rep.Orphans) != 1 || !strings.Contains(rep.Orphans[0], string(d1)[:12]) {
		t.Fatalf("d1 应作为孤儿版本被报告，实际 %v", rep.Orphans)
	}
}

func approvalsOf(b []SignedApproval) []Approval {
	out := make([]Approval, len(b))
	for i, x := range b {
		out[i] = x.Approval
	}
	return out
}

func sigsOf(b []SignedApproval) [][]byte {
	out := make([][]byte, len(b))
	for i, x := range b {
		out[i] = x.Signature
	}
	return out
}
