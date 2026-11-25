package offlineplugin

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// RecoveryOutcome 是恢复后该代号所处的明确结果。题面要求区分三种事故现场，
// 恢复结果同样分成三类，并且只允许落在旧版或已合法承诺的新版本上。
type RecoveryOutcome string

const (
	// OutcomeKeptCurrent 指针版本通过全部校验（含未撤销），当前版本保留。
	OutcomeKeptCurrent RecoveryOutcome = "保留当前合法版本"
	// OutcomeRolledBack 指针版本不可用（无有效承诺/被撤销/损坏），
	// 已回退到上一个已合法承诺且未撤销的旧版本。
	OutcomeRolledBack RecoveryOutcome = "回退到旧版本"
	// OutcomeNoValidVersion 没有任何可安全保留的版本，指针被移除，
	// 柜台系统不得把任何目录当作当前插件。
	OutcomeNoValidVersion RecoveryOutcome = "无有效版本可保留"
)

// ReleaseStatus 是恢复器对磁盘上单个发布目录的定性。
type ReleaseStatus string

const (
	StatusCommitted   ReleaseStatus = "已合法承诺" // 回执法定人数达标 + 内容完好 + 未撤销
	StatusRevoked     ReleaseStatus = "已撤销"
	StatusUncommitted ReleaseStatus = "无有效承诺" // 目录改完了，但回执缺失/票数不足
	StatusCorrupt     ReleaseStatus = "内容损坏"  // 磁盘内容与清单不符
)

// ReleaseFinding 记录一个磁盘版本目录的扫描结论。
type ReleaseFinding struct {
	Digest Digest
	Status ReleaseStatus
	Detail string
	Quorum int // 去重后的真实独立签发者票数（无回执为 0）
}

// RecoveryReport 是一次恢复的完整报告，验证器会对恢复后的磁盘再独立复核。
type RecoveryReport struct {
	Codename      Codename
	Outcome       RecoveryOutcome
	PointerBefore string
	PointerAfter  string // 空串表示无指针
	Fallback      Digest // 回退时选中的旧版本
	Findings      []ReleaseFinding
	Quarantined   []Digest // 被移到 quarantine 的无承诺/损坏目录
	Revoked       []Digest // 已撤销的目录（保留在原地，但永不可用）
	HistoryRepair int      // 被截断的损坏历史行数
}

// Recover 对单个代号执行崩溃后恢复。它不相信内存状态，只扫描磁盘。
func (v *Verifier) Recover(c Codename) (RecoveryReport, error) {
	rep := RecoveryReport{Codename: c}

	// 1) 修复可能被崩溃截断的历史日志。
	trimmed, err := v.repairHistory(c)
	if err != nil {
		return rep, err
	}
	rep.HistoryRepair = trimmed

	// 2) 扫描该代号下所有版本目录（含孤儿），逐个定性。
	digests, err := v.store.ListReleases(c)
	if err != nil {
		return rep, err
	}
	for _, d := range digests {
		f := v.classifyRelease(c, d)
		rep.Findings = append(rep.Findings, f)
		if f.Status == StatusRevoked {
			rep.Revoked = append(rep.Revoked, d)
		}
	}

	// 3) 读当前指针（可能不存在、也可能指向一个无承诺目录）。
	var pointerBefore string
	cur, err := v.store.ReadPointer(c)
	switch {
	case errors.Is(err, ErrNotFound):
	case err != nil:
		return rep, err
	default:
		pointerBefore = cur.Digest
	}
	rep.PointerBefore = pointerBefore

	// 4) 决定安全指针：先看当前，再沿历史从近到远找合法承诺版本。
	safe := v.chooseSafePointer(c, pointerBefore, rep.Findings)

	// 5) 落地恢复决策。
	switch {
	case safe != "" && string(safe) == pointerBefore:
		rep.Outcome = OutcomeKeptCurrent
		rep.PointerAfter = string(safe)
	case safe != "":
		rep.Outcome = OutcomeRolledBack
		rep.Fallback = safe
		rep.PointerAfter = string(safe)
		next := Pointer{Codename: string(c), Digest: string(safe), UpdatedAtUnix: v.store.now()}
		if err := AtomicWriteJSON(v.store.pointerPath(c), next); err != nil {
			return rep, err
		}
	default:
		rep.Outcome = OutcomeNoValidVersion
		if err := v.removePointer(c); err != nil {
			return rep, err
		}
	}

	// 6) 无承诺/损坏目录移入 quarantine（撤销目录保留证据、原地冻结）。
	for _, f := range rep.Findings {
		if f.Status == StatusUncommitted || f.Status == StatusCorrupt {
			if err := v.quarantine(c, f.Digest); err != nil {
				return rep, err
			}
			rep.Quarantined = append(rep.Quarantined, f.Digest)
		}
	}
	return rep, nil
}

// classifyRelease 只凭磁盘证据给单个版本目录定性。
func (v *Verifier) classifyRelease(c Codename, d Digest) ReleaseFinding {
	f := ReleaseFinding{Digest: d}

	// 撤销优先：撤销文件按摘要命名且需独立签发者签名，撤销一旦成立即永久冻结。
	if rev, err := v.store.ReadRevocation(d); err == nil {
		if verr := VerifyRevocation(v.registry, rev); verr != nil {
			f.Status = StatusCorrupt
			f.Detail = "撤销记录验签失败: " + verr.Error()
			return f
		}
		f.Status = StatusRevoked
		f.Detail = "撤销原因: " + rev.Reason
	}

	// 重算 payload 摘要，与清单核对。
	m, err := v.store.ReadManifest(c, d)
	if err != nil {
		f.Status = StatusCorrupt
		f.Detail = "清单缺失或不可读: " + err.Error()
		return f
	}
	actual, err := VerifyManifest(v.store.payloadDir(c, d), m)
	if err != nil {
		f.Status = StatusCorrupt
		f.Detail = err.Error()
		return f
	}
	if actual != d {
		f.Status = StatusCorrupt
		f.Detail = fmt.Sprintf("目录名摘要 %s 与重算摘要 %s 不符", short(string(d)), short(string(actual)))
		return f
	}

	// 回执：法定人数、独立签发者、同摘要覆盖、逐签名重验。
	receipt, err := v.store.ReadReceipt(c, d)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			f.Status = StatusUncommitted
			f.Detail = "目录已物化但回执缺失（目录改完却未形成有效承诺）"
			return f
		}
		f.Status = StatusCorrupt
		f.Detail = "回执不可读: " + err.Error()
		return f
	}
	n, err := ValidateReceipt(v.registry, c, d, receipt)
	if err != nil {
		f.Status = StatusUncommitted
		f.Detail = "回执不构成有效承诺: " + err.Error()
		return f
	}
	f.Quorum = n
	if f.Status == StatusRevoked {
		return f // 内容与回执都没问题，但撤销生效，维持“已撤销”。
	}
	f.Status = StatusCommitted
	f.Detail = fmt.Sprintf("%d 个真实独立签发者批准（门槛 %d）", n, Quorum)
	return f
}

// chooseSafePointer 按“当前指针 → 历史由近及远”的顺序找第一个
// 已合法承诺且未撤销的版本；历史里没有就放弃，绝不临时承诺新版本。
func (v *Verifier) chooseSafePointer(c Codename, current string, findings []ReleaseFinding) Digest {
	index := make(map[Digest]ReleaseStatus, len(findings))
	for _, f := range findings {
		index[f.Digest] = f.Status
	}
	good := func(d string) bool { return d != "" && index[Digest(d)] == StatusCommitted }

	if good(current) {
		return Digest(current)
	}
	hist, err := v.store.ReadHistory(c)
	if err != nil {
		return ""
	}
	for i := len(hist) - 1; i >= 0; i-- {
		if good(hist[i].Digest) {
			return Digest(hist[i].Digest)
		}
	}
	return ""
}

// repairHistory 截断无法解析的历史尾部（崩溃半行），返回截断的行数。
func (v *Verifier) repairHistory(c Codename) (int, error) {
	p := v.store.historyPath(c)
	data, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	lines := strings.Split(string(data), "\n")
	good := 0
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var h HistoryEntry
		if jsonUnmarshalOK(line, &h) {
			good++
			continue
		}
		break // 第一条坏行之后全部视为崩溃尾部
	}
	var kept strings.Builder
	written := 0
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var h HistoryEntry
		if !jsonUnmarshalOK(line, &h) {
			break
		}
		kept.WriteString(line)
		kept.WriteByte('\n')
		written++
		if written == good {
			break
		}
	}
	trimmed := 0
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		trimmed++
	}
	trimmed -= good
	if trimmed <= 0 {
		return 0, nil
	}
	return trimmed, AtomicWrite(p, []byte(kept.String()))
}

func (v *Verifier) removePointer(c Codename) error {
	p := v.store.pointerPath(c)
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDir(filepath.Dir(p))
}

// quarantine 把不可用目录原子移到 releases/_quarantine/<codename>/<digest>，
// 保留证据但使其永远不可能被指针引用。
func (v *Verifier) quarantine(c Codename, d Digest) error {
	src := v.store.releaseDir(c, d)
	if _, err := os.Stat(src); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil // 已被移动过
		}
		return err
	}
	dst := join(v.store.Root, "releases", "_quarantine", string(c), string(d))
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	if err := os.Rename(src, dst); err != nil {
		if os.IsExist(err) {
			return os.RemoveAll(src)
		}
		return err
	}
	return syncDir(filepath.Dir(dst))
}
