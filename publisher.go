package offlineplugin

import (
	"errors"
	"fmt"
	"os"
	"sync"
)

// CrashPoint 标识发布/撤销过程中人为注入的崩溃（进程立即中止语义）。
// 注入点之后的所有写动作都不会发生，磁盘精确停在该时刻的状态。
type CrashPoint string

const (
	CrashNone            CrashPoint = ""
	CrashAfterStage      CrashPoint = "after_stage"      // 目录已就位，回执未写：无有效承诺
	CrashAfterReceipt    CrashPoint = "after_receipt"    // 回执已落盘，指针未切换
	CrashAfterPointer    CrashPoint = "after_pointer"    // 指针已落盘（朴素路径下回执可能缺失）
	CrashAfterRevocation CrashPoint = "after_revocation" // 撤销已落盘，切换尚未发生
)

// ErrInjectedCrash 表示演练主动注入的崩溃，磁盘状态即事故现场。
var ErrInjectedCrash = errors.New("已注入崩溃（模拟进程中止）")

// QuorumError 表示独立批准票数不足，附带实际去重后的真实签发者。
type QuorumError struct {
	Need       int
	Got        int
	Principals []string
}

func (e *QuorumError) Error() string {
	return fmt.Sprintf("法定人数不足：需要 %d 个独立签发者，实际 %d 个（%v）", e.Need, e.Got, e.Principals)
}

// RevokedError 表示目标摘要已被撤销，拒绝发布/切换。
type RevokedError struct {
	Digest Digest
	Reason string
}

func (e *RevokedError) Error() string {
	return "摘要 " + short(string(e.Digest)) + " 已被撤销：" + e.Reason
}

// SignedApproval 把一份批准和它的签名绑在一起。
type SignedApproval struct {
	Approval  Approval
	Signature []byte
}

// Hooks 控制一次发布的人为故障与阻塞。
type Hooks struct {
	// Crash 是本次调用要注入的崩溃点；CrashNone 表示不注入。
	Crash CrashPoint
	// BlockBeforeReceipt 在“目录就位之后、写回执之前”被调用。
	// 演练用一个阻塞通道实现“人为卡在写回执前”，可从外部放行。
	BlockBeforeReceipt func(Codename, Digest)
}

// PublishResult 汇报一次硬化发布的结果。
type PublishResult struct {
	Codename  Codename
	Digest    Digest
	Previous  Digest // 切换前指针摘要，可能为空
	Switched  bool   // 本次是否真正推进了指针
	ReceiptAt string
}

// Publisher 是硬化发布协议的执行器。两个真实发布者各自持有一个
// Publisher 实例时，互斥不共享——仲裁完全依赖磁盘上的指针 CAS。
type Publisher struct {
	store    *Store
	registry *Registry
}

// NewPublisher 构造发布器。
func NewPublisher(st *Store, reg *Registry) *Publisher {
	return &Publisher{store: st, registry: reg}
}

// materialize 把源目录内容寻址地落到 releases/<codename>/<digest>。
// 内容寻址意味着相同摘要的并发物化最终收敛到同一个目录。
func (p *Publisher) materialize(src string, c Codename, m Manifest, d Digest) (string, error) {
	target := p.store.releaseDir(c, d)
	if _, err := os.Stat(p.store.manifestPath(c, d)); err == nil {
		// 已有同摘要版本：核对磁盘清单一致后直接复用。
		if _, err := VerifyManifest(p.store.payloadDir(c, d), m); err != nil {
			return "", err
		}
		return target, nil
	}
	nonce := fmt.Sprintf("%d-%s", p.store.now(), short(string(d)))
	staging := p.store.stagingDir(c, nonce)
	if err := os.MkdirAll(staging, 0o755); err != nil {
		return "", err
	}
	// 任何失败都清理自己的 staging，绝不让半成品进入 releases。
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(staging)
		}
	}()
	if err := copyTree(src, join(staging, "payload")); err != nil {
		return "", err
	}
	if err := AtomicWriteJSON(join(staging, "manifest.json"), m); err != nil {
		return "", err
	}
	// 重命名前最后核对一次，防止与并发物化者撞车。
	if err := os.MkdirAll(p.store.releaseBase(c), 0o755); err != nil {
		return "", err
	}
	if err := os.Rename(staging, target); err != nil {
		if os.IsExist(err) {
			// 别人先物化了同摘要目录：核对后复用。
			if _, verr := VerifyManifest(p.store.payloadDir(c, d), m); verr != nil {
				return "", verr
			}
			ok = true
			return target, nil
		}
		return "", err
	}
	if err := syncDir(p.store.releaseBase(c)); err != nil {
		return "", err
	}
	ok = true
	return target, nil
}

// Publish 执行硬化发布协议。
func (p *Publisher) Publish(src string, c Codename, bundles []SignedApproval, hooks Hooks) (PublishResult, error) {
	res := PublishResult{Codename: c}

	// 1) 扫描源目录，求规范化清单与摘要。
	m, err := BuildManifest(src, c)
	if err != nil {
		return res, err
	}
	d, err := DigestManifest(m)
	if err != nil {
		return res, err
	}
	res.Digest = d

	// 2) 撤销先于一切：标题问题的答案——已落盘撤销的摘要不得再发布。
	if rev, err := p.store.ReadRevocation(d); err == nil {
		if verr := VerifyRevocation(p.registry, rev); verr != nil {
			return res, fmt.Errorf("撤销记录本身校验失败: %w", verr)
		}
		return res, &RevokedError{Digest: d, Reason: rev.Reason}
	} else if !errors.Is(err, ErrNotFound) {
		return res, err
	}

	// 3) 批准必须全部覆盖同一代号/同一摘要，并按真实独立签发者去重计票。
	approvals := make([]Approval, len(bundles))
	sigs := make([][]byte, len(bundles))
	for i, b := range bundles {
		approvals[i] = b.Approval
		sigs[i] = b.Signature
	}
	principals, err := p.principalSet(c, d, approvals, sigs)
	if err != nil {
		return res, err
	}
	if len(principals) < Quorum {
		return res, &QuorumError{Need: Quorum, Got: len(principals), Principals: sortedKeys(principals)}
	}

	// 3.5) 乐观捕获当前指针摘要作为本次事务的 CAS 期望值。
	// 之后即使长时间阻塞（演练里的“卡在写回执前”），提交时也只认这个值：
	// 期间别的发布者一旦推进指针，本次 CAS 必然冲突，杜绝陈旧覆盖。
	expect, err := p.currentPointerDigest(c)
	if err != nil {
		return res, err
	}

	// 4) 物化发布目录（staging → 内容寻址目录的原子重命名）。
	if _, err := p.materialize(src, c, m, d); err != nil {
		return res, err
	}
	res.ReceiptAt = p.store.receiptPath(c, d)

	// 5) 人为卡在“写回执前”：目录已经改完，但磁盘上还没有任何承诺凭证。
	if hooks.BlockBeforeReceipt != nil {
		hooks.BlockBeforeReceipt(c, d)
	}
	if hooks.Crash == CrashAfterStage {
		return res, ErrInjectedCrash
	}

	// 6) 组回执并先于指针落盘（回执是“有效承诺”的唯一凭证）。
	receipt := Receipt{
		Codename:    string(c),
		Digest:      string(d),
		Approvals:   approvals,
		Signatures:  sigs,
		CreatedUnix: p.store.now(),
	}
	if err := AtomicWriteJSON(p.store.receiptPath(c, d), receipt); err != nil {
		return res, err
	}
	if hooks.Crash == CrashAfterReceipt {
		return res, ErrInjectedCrash
	}

	// 7) 历史先追加、指针再 CAS 切换；CAS 期望值在事务开始时捕获，
	//    持有陈旧视图的发布者不可能覆盖期间已被推进的指针。
	res.Previous = Digest(expect)
	if expect == string(d) {
		// 指针已指向同摘要：幂等成功，不重复写历史。
		res.Switched = false
		return res, nil
	}
	entry := HistoryEntry{
		Codename:       string(c),
		Digest:         string(d),
		Previous:       expect,
		SwitchedAtUnix: p.store.now(),
	}
	line, err := canonicalJSON(entry)
	if err != nil {
		return res, err
	}
	if err := AppendLine(p.store.historyPath(c), line); err != nil {
		return res, err
	}
	next := Pointer{Codename: string(c), Digest: string(d), UpdatedAtUnix: p.store.now()}
	if err := p.store.compareAndSwapPointer(c, expect, next); err != nil {
		// 回执已合法落盘，只是指针被竞争者抢先：撤回自己刚追加的历史行，
		// 历史只保留真正完成的承诺；这是干净的竞争失败，不是损坏。
		_ = p.store.TruncateHistoryLast(c)
		return res, err
	}
	res.Switched = true
	if hooks.Crash == CrashAfterPointer {
		return res, ErrInjectedCrash
	}
	return res, nil
}

// currentPointerDigest 读取当前指针摘要；无指针时返回空串。
func (p *Publisher) currentPointerDigest(c Codename) (string, error) {
	cur, err := p.store.ReadPointer(c)
	if errors.Is(err, ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return cur.Digest, nil
}

// principalSet 验签并返回去重后的真实独立签发者集合。
func (p *Publisher) principalSet(c Codename, d Digest, approvals []Approval, sigs [][]byte) (map[string]struct{}, error) {
	if len(approvals) != len(sigs) {
		return nil, errors.New("批准与签名数量不一致")
	}
	principals := make(map[string]struct{})
	for i, a := range approvals {
		if a.Codename != string(c) {
			return nil, fmt.Errorf("批准代号不匹配: %s != %s", a.Codename, c)
		}
		if a.Digest != string(d) {
			return nil, fmt.Errorf("批准覆盖的摘要与目录实际摘要不一致: %s != %s", short(a.Digest), short(string(d)))
		}
		if err := VerifyApproval(p.registry, a, sigs[i]); err != nil {
			return nil, err
		}
		principal, err := p.registry.Principal(a.IssuerID)
		if err != nil {
			return nil, err
		}
		principals[principal] = struct{}{}
	}
	return principals, nil
}

// PublishNaive 复现事故系统的朴素发布顺序：目录改完就直接切指针，
// 回执/法定人数是“之后再说”的。它无论如何都向上报告成功——
// 这正是演练里“重启前后都成功、摘要却不同”的来源。
// 传入 CrashAfterPointer 可在指针落盘后、回执写之前制造崩溃。
func (p *Publisher) PublishNaive(src string, c Codename, bundles []SignedApproval, hooks Hooks) (PublishResult, error) {
	res := PublishResult{Codename: c}
	m, err := BuildManifest(src, c)
	if err != nil {
		return res, err
	}
	d, err := DigestManifest(m)
	if err != nil {
		return res, err
	}
	res.Digest = d
	if _, err := p.materialize(src, c, m, d); err != nil {
		return res, err
	}
	if hooks.BlockBeforeReceipt != nil {
		hooks.BlockBeforeReceipt(c, d)
	}
	// 朴素系统的致命顺序：先切指针，且不校验法定人数。
	cur, _ := p.store.ReadPointer(c)
	prev := cur.Digest
	next := Pointer{Codename: string(c), Digest: string(d), UpdatedAtUnix: p.store.now()}
	if err := AtomicWriteJSON(p.store.pointerPath(c), next); err != nil {
		return res, err
	}
	res.Previous = Digest(prev)
	res.Switched = true
	if hooks.Crash == CrashAfterPointer {
		return res, ErrInjectedCrash
	}
	// 事后才补回执；票数不够也照写，验证器重启后会识破。
	approvals := make([]Approval, len(bundles))
	sigs := make([][]byte, len(bundles))
	for i, b := range bundles {
		approvals[i] = b.Approval
		sigs[i] = b.Signature
	}
	receipt := Receipt{
		Codename:    string(c),
		Digest:      string(d),
		Approvals:   approvals,
		Signatures:  sigs,
		CreatedUnix: p.store.now(),
	}
	res.ReceiptAt = p.store.receiptPath(c, d)
	_ = AtomicWriteJSON(p.store.receiptPath(c, d), receipt)
	return res, nil
}

// Revoke 签发并落盘一份撤销。crash=CrashAfterRevocation 时，
// 撤销文件已 fsync，函数随即返回注入崩溃——后续切换不会发生。
func (p *Publisher) Revoke(signer *Signer, d Digest, reason string, crash CrashPoint) (Revocation, error) {
	rev, err := signer.SignRevocation(d, reason)
	if err != nil {
		return Revocation{}, err
	}
	if err := VerifyRevocation(p.registry, rev); err != nil {
		return Revocation{}, err
	}
	if err := AtomicWriteJSON(p.store.revocationPath(d), rev); err != nil {
		return Revocation{}, err
	}
	if crash == CrashAfterRevocation {
		return rev, ErrInjectedCrash
	}
	return rev, nil
}

// ManualGate 是一个可从外部放行的阻塞闸门，用于“卡在写回执前”。
type ManualGate struct {
	ch   chan struct{}
	once sync.Once
}

// NewManualGate 创建闸门。
func NewManualGate() *ManualGate { return &ManualGate{ch: make(chan struct{})} }

// Block 阻塞直到 Release 被调用。
func (g *ManualGate) Block(_ Codename, _ Digest) { <-g.ch }

// Release 放行所有阻塞在该闸门上的发布。
func (g *ManualGate) Release() {
	g.once.Do(func() { close(g.ch) })
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// 小集合，简单插入排序即可，避免再引一个 sort 进口头。
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}
