// Package main 是离线插件发布/恢复协议的本地演练驱动。
// 所有数据（目录、授权、撤销、密钥）均为运行时合成的模拟数据，
// 运行结束后可在 artifacts/drill-root 下直接检查磁盘证据。
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	op "offlineplugin"
)

func main() {
	if code := runAll(); code != 0 {
		os.Exit(code)
	}
}

// runAll 执行全部演练场景，返回进程退出码（0 = 全部断言通过）。
// 抽成独立函数以便用 go test 在受限环境里驱动同一份演练。
func runAll() int {
	d := &drill{
		baseRoot: filepath.Join(moduleRoot(), "artifacts", "drill-root"),
		passed:   0,
		failed:   0,
	}
	_ = os.RemoveAll(d.baseRoot)
	must(os.MkdirAll(d.baseRoot, 0o755))
	d.setup()

	d.run("S1 事故复盘：朴素系统先切指针后补回执，重启前后都报成功却摘要不同", d.scenarioNaiveAccident)
	d.run("S2 硬化协议-崩溃点A：目录改完、回执未写（无有效承诺）→ 保留旧版，半成品隔离", d.scenarioCrashAfterStage)
	d.run("S3 硬化协议-崩溃点B：回执先落盘、指针未切换（承诺已成立）→ 保留旧版，新版本可补切", d.scenarioCrashAfterReceipt)
	d.run("S4 硬化协议-崩溃点C：指针先落盘且回执齐全（合法承诺）→ 新版本保留", d.scenarioCrashAfterPointer)
	d.run("S5 撤销先落盘：撤销 fsync 后崩溃，指针仍指被撤销版本 → 恢复回退旧版且不可再发布", d.scenarioRevocationFirst)
	d.run("S6 挂名代理不计两票：本人+代理只有一个真实签发者，法定人数不足", d.scenarioProxyVote)
	d.run("S7 任一批准必须覆盖同一摘要：异摘要批准不能凑数", d.scenarioDigestMismatch)
	d.run("S8 两个真实发布者竞争同一代号：CAS 仲裁 + 人为卡在写回执前", d.scenarioContention)
	d.run("S9 磁盘验证器：篡改 payload、伪造撤销均被直接扫盘识破", d.scenarioVerifier)
	d.run("S10 局部变更重读计量：共享内容目录上实测哪些文件被重读", d.scenarioReRead)

	fmt.Println(strings.Repeat("=", 78))
	fmt.Printf("演练结束：通过 %d 项，失败 %d 项\n", d.passed, d.failed)
	d.log(strings.Repeat("=", 78))
	d.logf("演练结束：通过 %d 项，失败 %d 项", d.passed, d.failed)
	reportPath := filepath.Join(d.baseRoot, "run-report.txt")
	if werr := os.WriteFile(reportPath, []byte(d.report.String()), 0o644); werr != nil {
		fmt.Fprintln(os.Stderr, "报告落盘失败:", werr)
	}
	if d.failed != 0 {
		return 1
	}
	return 0
}

// ---- 演练框架 ----

type drill struct {
	baseRoot string
	root     string
	registry *op.Registry
	signers  map[string]*op.Signer
	passed   int
	failed   int
	report   strings.Builder
}

// log 同时写标准输出与演练报告（报告落盘供事后检查）。
func (d *drill) log(line string) {
	fmt.Println(line)
	d.report.WriteString(line + "\n")
}

// logf 是带格式的 log。
func (d *drill) logf(format string, args ...any) {
	d.log(fmt.Sprintf(format, args...))
}

func (d *drill) run(title string, fn func() error) {
	bar := strings.Repeat("=", 78)
	fmt.Println(bar)
	fmt.Println("▶ " + title)
	d.report.WriteString(bar + "\n▶ " + title + "\n")
	if err := fn(); err != nil {
		d.failed++
		fmt.Printf("  ✗ 断言失败：%v\n", err)
		d.logf("  ✗ 断言失败：%v", err)
		return
	}
	d.passed++
	fmt.Println("  ✓ 通过")
	d.report.WriteString("  ✓ 通过\n")
}

func (d *drill) check(cond bool, msg string, args ...any) error {
	if !cond {
		return fmt.Errorf(msg, args...)
	}
	return nil
}

func (d *drill) setup() {
	// 三个真正独立的签发者 + 一个挂在 issuer-a 名下的代理。
	issuers := []struct {
		id        string
		kind      op.IssuerKind
		principal string
		name      string
	}{
		{"issuer-a", op.KindIndependent, "", "甲发行所"},
		{"issuer-b", op.KindIndependent, "", "乙发行所"},
		{"issuer-c", op.KindIndependent, "", "丙发行所"},
		{"proxy-a1", op.KindProxy, "issuer-a", "甲所挂名代理"},
	}
	reg := &op.Registry{}
	d.signers = make(map[string]*op.Signer)
	for _, spec := range issuers {
		pub, priv, err := op.GenerateKey()
		must(err)
		is := op.Issuer{
			ID: spec.id, Kind: spec.kind, PublicKey: pub,
			PrincipalID: spec.principal, DisplayName: spec.name,
		}
		reg.Issuers = append(reg.Issuers, is)
		d.signers[spec.id] = op.NewSigner(is, priv)
	}
	d.registry = reg
	// 注册表与密钥为全演练共享的模拟数据；每个场景另用独立仓库目录。
	must(reg.Save(filepath.Join(d.baseRoot, "registry.json")))
}

// rootFor 为每个场景分配独立的仓库根目录，场景之间互不污染。
func (d *drill) rootFor(tag string) string {
	d.root = filepath.Join(d.baseRoot, tag)
	must(os.MkdirAll(d.root, 0o755))
	// 每个场景根都放一份注册表落盘副本，磁盘证据自洽、可单独检查。
	must(d.registry.Save(filepath.Join(d.root, "registry.json")))
	return d.root
}

func (d *drill) newStore() *op.Store {
	st, err := op.NewStore(d.root)
	must(err)
	return st
}

func (d *drill) verifier() *op.Verifier {
	return op.NewVerifier(d.newStore(), d.registry)
}

func (d *drill) publisher() *op.Publisher {
	return op.NewPublisher(d.newStore(), d.registry)
}

// makePluginDir 在 work 下生成一个插件目录并返回路径。
func (d *drill) makePluginDir(name string, files map[string]string) string {
	dir := filepath.Join(d.root, "work", name)
	must(os.MkdirAll(dir, 0o755))
	for rel, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		must(os.MkdirAll(filepath.Dir(p), 0o755))
		must(os.WriteFile(p, []byte(content), 0o644))
	}
	return dir
}

// approve 让若干签发者对同一目录摘要签发批准。
func (d *drill) approve(c op.Codename, digest op.Digest, ids ...string) []op.SignedApproval {
	var out []op.SignedApproval
	for _, id := range ids {
		a, sig, err := d.signers[id].SignApproval(c, digest, 3600)
		must(err)
		out = append(out, op.SignedApproval{Approval: a, Signature: sig})
	}
	return out
}

func (d *drill) digestOf(src string, c op.Codename) op.Digest {
	m, err := op.BuildManifest(src, c)
	must(err)
	dg, err := op.DigestManifest(m)
	must(err)
	return dg
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func short(d op.Digest) string {
	s := string(d)
	if len(s) > 12 {
		return s[:12] + "…"
	}
	return s
}

func isInjectedCrash(err error) bool { return errors.Is(err, op.ErrInjectedCrash) }

// moduleRoot 从当前工作目录向上找含 go.mod 的目录，
// 保证无论从仓库根 `go run` 还是从包目录 `go test` 启动，
// 演练产物都固定落在仓库根的 artifacts/ 下。
func moduleRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		return "."
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "."
		}
		dir = parent
	}
}
