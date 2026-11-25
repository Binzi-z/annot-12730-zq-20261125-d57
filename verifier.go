package offlineplugin

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// Verifier 是独立的磁盘验证器：它不接收任何内存中的“发布成功”结论，
// 全部判断都来自直接扫描磁盘并重算/重验。
type Verifier struct {
	store    *Store
	registry *Registry
}

// NewVerifier 构造磁盘验证器。
func NewVerifier(st *Store, reg *Registry) *Verifier {
	return &Verifier{store: st, registry: reg}
}

// ValidateReceipt 重验一份回执：
//   - 回执绑定的代号、摘要必须与目标一致；
//   - 每份批准的 Ed25519 签名都要用注册公钥重验；
//   - 按背后真实独立签发者去重后票数必须达到 Quorum；
//   - 挂名代理与它的本人/同侪代理合计只算一票。
//
// 返回去重后的真实独立签发者数量。
func ValidateReceipt(reg *Registry, c Codename, d Digest, r Receipt) (int, error) {
	if r.Codename != string(c) {
		return 0, fmt.Errorf("回执代号 %s 与目标 %s 不符", r.Codename, c)
	}
	if r.Digest != string(d) {
		return 0, fmt.Errorf("回执摘要 %s 与目录摘要 %s 不符", short(r.Digest), short(string(d)))
	}
	if len(r.Approvals) != len(r.Signatures) {
		return 0, errors.New("回执中批准与签名数量不一致")
	}
	return CountIndependentApprovals(reg, c, d, r.Approvals, r.Signatures)
}

// jsonUnmarshalOK 判断一行 JSON 是否能完整解析（用于历史尾部修复）。
func jsonUnmarshalOK(line string, v any) bool {
	if err := json.Unmarshal([]byte(line), v); err != nil {
		return false
	}
	return true
}

// PointerCheck 是对某个代号当前指针的独立核查结论。
type PointerCheck struct {
	Codename   Codename
	Pointer    Pointer
	HasPointer bool
	Finding    ReleaseFinding
	Healthy    bool
	Problems   []string
}

// CheckPointer 直接扫描磁盘，核查当前指针引用的版本是否可信。
func (v *Verifier) CheckPointer(c Codename) (PointerCheck, error) {
	check := PointerCheck{Codename: c}
	cur, err := v.store.ReadPointer(c)
	switch {
	case errors.Is(err, ErrNotFound):
		check.Problems = append(check.Problems, "代号当前没有指针")
		return check, nil
	case err != nil:
		return check, err
	}
	check.Pointer = cur
	check.HasPointer = true
	check.Finding = v.classifyRelease(c, Digest(cur.Digest))
	if check.Finding.Status != StatusCommitted {
		check.Healthy = false
		check.Problems = append(check.Problems,
			fmt.Sprintf("指针摘要 %s 状态为「%s」：%s", short(cur.Digest), check.Finding.Status, check.Finding.Detail))
		return check, nil
	}
	// 交叉核对历史最后一条：承诺链必须与指针一致。
	hist, err := v.store.ReadHistory(c)
	if err != nil {
		return check, err
	}
	if len(hist) == 0 || hist[len(hist)-1].Digest != cur.Digest {
		check.Problems = append(check.Problems, "指针摘要与承诺历史最后一条不一致")
	}
	check.Healthy = len(check.Problems) == 0
	return check, nil
}

// DiskReport 是对整个仓库的全量磁盘扫描报告。
type DiskReport struct {
	RegistryPath   string
	RegistryOnDisk bool // 信任锚注册表是否在仓库根有落盘副本（缺失时只用内存注册表）
	IssuerCount    int
	Codenames      []CodenameReport
	Orphans        []string // 有目录但未被任何健康指针引用的版本
}

// CodenameReport 是单个代号的扫描结果。
type CodenameReport struct {
	Codename Codename
	Check    PointerCheck
	Findings []ReleaseFinding
}

// ScanDisk 不依赖任何调用方参数，直接从仓库根目录扫描全部证据：
// 注册表、指针、历史、每个版本的 payload/清单/回执、撤销文件。
func (v *Verifier) ScanDisk() (DiskReport, error) {
	report := DiskReport{RegistryPath: v.store.registryPath()}
	// 注册表是启动时加载的信任锚；仓库根里有没有落盘副本不影响扫描，
	// 只在报告里标注，证据枚举仍然完全基于磁盘。
	if _, err := os.Stat(v.store.registryPath()); err == nil {
		report.RegistryOnDisk = true
	}
	report.IssuerCount = len(v.registry.Issuers)

	codenames, err := v.store.ListCodenames()
	if err != nil {
		return report, err
	}
	seen := make(map[Codename]bool)
	for _, c := range codenames {
		seen[c] = true
	}
	// 版本目录可能先于指针出现（崩溃在切指针之前），把这些代号也扫出来。
	releaseDirs, err := os.ReadDir(join(v.store.Root, "releases"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return report, err
	}
	for _, e := range releaseDirs {
		if e.IsDir() && e.Name() != "_quarantine" {
			seen[Codename(e.Name())] = true
		}
	}
	for c := range seen {
		cr := CodenameReport{Codename: c}
		digests, err := v.store.ListReleases(c)
		if err != nil {
			return report, err
		}
		referenced := ""
		for _, d := range digests {
			f := v.classifyRelease(c, d)
			cr.Findings = append(cr.Findings, f)
		}
		check, err := v.CheckPointer(c)
		if err != nil {
			return report, err
		}
		cr.Check = check
		if check.HasPointer {
			referenced = check.Pointer.Digest
		}
		for _, f := range cr.Findings {
			if string(f.Digest) != referenced {
				report.Orphans = append(report.Orphans,
					fmt.Sprintf("%s/%s（%s）", c, short(string(f.Digest)), f.Status))
			}
		}
		report.Codenames = append(report.Codenames, cr)
	}
	return report, nil
}

// VerifyRevocationFiles 扫描 revocations/ 目录，逐个重验撤销签名，
// 返回验签失败的撤销文件列表。
func (v *Verifier) VerifyRevocationFiles() ([]string, error) {
	digests, err := v.store.ListRevocations()
	if err != nil {
		return nil, err
	}
	var bad []string
	for _, d := range digests {
		rev, err := v.store.ReadRevocation(d)
		if err != nil {
			bad = append(bad, string(d)+"（不可读）")
			continue
		}
		if rev.Digest != string(d) {
			bad = append(bad, string(d)+"（文件名与内容摘要不符）")
			continue
		}
		if err := VerifyRevocation(v.registry, rev); err != nil {
			bad = append(bad, string(d)+"（"+err.Error()+"）")
		}
	}
	return bad, nil
}
