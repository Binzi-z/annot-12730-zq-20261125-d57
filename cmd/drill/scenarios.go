package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	op "offlineplugin"
)

const cn = op.Codename("teller-plugin")

// S1 事故复盘：朴素系统先切指针、回执后补；崩溃后重启，
// 两次“成功”的调用对应两个不同摘要，而磁盘上没有任何有效承诺。
func (d *drill) scenarioNaiveAccident() error {
	d.rootFor("s1-naive")
	pub := d.publisher()

	v1 := d.makePluginDir("p-v1", map[string]string{"bin/app.exe": "v1", "cfg/conf.ini": "shared"})
	v2 := d.makePluginDir("p-v2", map[string]string{"bin/app.exe": "v2", "cfg/conf.ini": "shared"})
	d1, d2 := d.digestOf(v1, cn), d.digestOf(v2, cn)
	if err := d.check(d1 != d2, "两个版本摘要应当不同"); err != nil {
		return err
	}

	// 第一次“发布成功”：指针直接切到 d1，回执还没来得及写。
	if _, err := pub.PublishNaive(v1, cn, d.approve(cn, d1, "issuer-a", "issuer-b"),
		op.Hooks{Crash: op.CrashAfterPointer}); !isInjectedCrash(err) {
		return fmt.Errorf("预期注入崩溃，实际 %v", err)
	}
	ptr, err := d.newStore().ReadPointer(cn)
	if err != nil {
		return err
	}
	d.logf("  第一次报成功后指针 = %s（回执缺失）", short(op.Digest(ptr.Digest)))

	// 重启后朴素系统不做校验，又一次“发布成功”，指针换成 d2。
	if _, err := pub.PublishNaive(v2, cn, d.approve(cn, d2, "issuer-a", "issuer-b"),
		op.Hooks{Crash: op.CrashAfterPointer}); !isInjectedCrash(err) {
		return fmt.Errorf("预期注入崩溃，实际 %v", err)
	}
	ptr2, _ := d.newStore().ReadPointer(cn)
	d.logf("  重启后再次报成功，指针 = %s", short(op.Digest(ptr2.Digest)))
	if err := d.check(ptr2.Digest == string(d2) && ptr2.Digest != ptr.Digest,
		"重启前后两次成功却指向不同摘要——事故复现"); err != nil {
		return err
	}

	// 验证器直扫磁盘：两个版本都没有有效承诺。
	rep, err := d.verifier().Recover(cn)
	if err != nil {
		return err
	}
	d.logf("  恢复结果：%s；版本定性：%s", rep.Outcome, summarize(rep.Findings))
	if err := d.check(rep.Outcome == op.OutcomeNoValidVersion, "无任何合法承诺，应判定为无有效版本"); err != nil {
		return err
	}
	if err := d.check(len(rep.Quarantined) == 2, "两个无承诺目录都应隔离，实际 %d", len(rep.Quarantined)); err != nil {
		return err
	}
	return nil
}

// S2 崩溃点A：目录改完却未形成有效承诺（回执未写）→ 只能保留旧版。
func (d *drill) scenarioCrashAfterStage() error {
	d.rootFor("s2-after-stage")
	pub := d.publisher()

	v1 := d.makePluginDir("p-v1", map[string]string{"a.txt": "one"})
	d1 := d.digestOf(v1, cn)
	if _, err := pub.Publish(v1, cn, d.approve(cn, d1, "issuer-a", "issuer-b"), op.Hooks{}); err != nil {
		return err
	}

	v2 := d.makePluginDir("p-v2", map[string]string{"a.txt": "two"})
	d2 := d.digestOf(v2, cn)
	if _, err := pub.Publish(v2, cn, d.approve(cn, d2, "issuer-a", "issuer-b"),
		op.Hooks{Crash: op.CrashAfterStage}); !isInjectedCrash(err) {
		return fmt.Errorf("预期注入崩溃，实际 %v", err)
	}
	if _, err := d.newStore().ReadReceipt(cn, d2); !errors.Is(err, op.ErrNotFound) {
		return fmt.Errorf("崩溃点A下回执不应存在，实际 %v", err)
	}

	rep, err := d.verifier().Recover(cn)
	if err != nil {
		return err
	}
	d.logf("  恢复结果：%s，指针保持 %s；隔离 %d 个无承诺目录",
		rep.Outcome, short12(rep.PointerAfter), len(rep.Quarantined))
	// 回执先于指针的顺序保证：指针从未离开 d1，所以不是“回退”而是“保留旧版”。
	if err := d.check(rep.Outcome == op.OutcomeKeptCurrent && rep.PointerAfter == string(d1),
		"指针未切换，应保留旧版 d1"); err != nil {
		return err
	}
	if err := d.check(findStatus(rep.Findings, d2) == op.StatusUncommitted, "d2 应定性为无有效承诺"); err != nil {
		return err
	}
	if err := d.check(len(rep.Quarantined) == 1 && rep.Quarantined[0] == d2, "半成品 d2 应被隔离"); err != nil {
		return err
	}
	return nil
}

// S3 崩溃点B：回执先落盘、指针未切换。新版本已是合法承诺，
// 恢复时当前旧版仍然合法；随后可凭磁盘回执把指针补切到新版本。
func (d *drill) scenarioCrashAfterReceipt() error {
	d.rootFor("s3-after-receipt")
	pub := d.publisher()

	v1 := d.makePluginDir("p-v1", map[string]string{"a.txt": "one"})
	d1 := d.digestOf(v1, cn)
	if _, err := pub.Publish(v1, cn, d.approve(cn, d1, "issuer-a", "issuer-b"), op.Hooks{}); err != nil {
		return err
	}

	v2 := d.makePluginDir("p-v2", map[string]string{"a.txt": "two"})
	d2 := d.digestOf(v2, cn)
	if _, err := pub.Publish(v2, cn, d.approve(cn, d2, "issuer-a", "issuer-b"),
		op.Hooks{Crash: op.CrashAfterReceipt}); !isInjectedCrash(err) {
		return fmt.Errorf("预期注入崩溃，实际 %v", err)
	}
	// 回执确实已在磁盘上，且独立验证器认可它的法定人数。
	receipt, err := d.newStore().ReadReceipt(cn, d2)
	if err != nil {
		return err
	}
	n, err := op.ValidateReceipt(d.registry, cn, d2, receipt)
	if err != nil {
		return err
	}
	if err := d.check(n >= op.Quorum, "回执应已构成有效承诺（%d 票）", n); err != nil {
		return err
	}

	rep, err := d.verifier().Recover(cn)
	if err != nil {
		return err
	}
	d.logf("  恢复结果：%s，指针保持 %s；d2 定性为「%s」",
		rep.Outcome, short12(rep.PointerAfter), findStatus(rep.Findings, d2))
	if err := d.check(rep.Outcome == op.OutcomeKeptCurrent && rep.PointerAfter == string(d1),
		"指针未切换，恢复后应保留旧版 d1"); err != nil {
		return err
	}
	if err := d.check(findStatus(rep.Findings, d2) == op.StatusCommitted, "d2 应是已合法承诺版本"); err != nil {
		return err
	}

	// 重新执行同摘要发布：物化与回执幂等，这次走完指针切换。
	if res, err := pub.Publish(v2, cn, d.approve(cn, d2, "issuer-a", "issuer-b"), op.Hooks{}); err != nil {
		return err
	} else if !res.Switched || res.Digest != d2 {
		return fmt.Errorf("补切应推进到 d2，实际 %+v", res)
	}
	check, err := d.verifier().CheckPointer(cn)
	if err != nil {
		return err
	}
	return d.check(check.Healthy && check.Pointer.Digest == string(d2), "补切后指针应为健康的 d2")
}

// S4 崩溃点C：指针先落盘且回执齐全——这是合法的完整承诺，恢复后新版本保留。
func (d *drill) scenarioCrashAfterPointer() error {
	d.rootFor("s4-after-pointer")
	pub := d.publisher()

	v1 := d.makePluginDir("p-v1", map[string]string{"a.txt": "one"})
	d1 := d.digestOf(v1, cn)
	if _, err := pub.Publish(v1, cn, d.approve(cn, d1, "issuer-a", "issuer-b"), op.Hooks{}); err != nil {
		return err
	}
	v2 := d.makePluginDir("p-v2", map[string]string{"a.txt": "two"})
	d2 := d.digestOf(v2, cn)
	if _, err := pub.Publish(v2, cn, d.approve(cn, d2, "issuer-a", "issuer-b"),
		op.Hooks{Crash: op.CrashAfterPointer}); !isInjectedCrash(err) {
		return fmt.Errorf("预期注入崩溃，实际 %v", err)
	}

	rep, err := d.verifier().Recover(cn)
	if err != nil {
		return err
	}
	d.logf("  恢复结果：%s，指针 = %s", rep.Outcome, short12(rep.PointerAfter))
	if err := d.check(rep.Outcome == op.OutcomeKeptCurrent && rep.PointerAfter == string(d2),
		"合法承诺的新版本应保留"); err != nil {
		return err
	}
	check, err := d.verifier().CheckPointer(cn)
	if err != nil {
		return err
	}
	return d.check(check.Healthy, "磁盘直扫验证应报告健康")
}

// S5 撤销先落盘：撤销 fsync 后进程中止；磁盘指针仍指着已撤销版本，
// 恢复必须沿承诺历史回退旧版，且同一摘要之后无法再次发布（题眼答案）。
func (d *drill) scenarioRevocationFirst() error {
	d.rootFor("s5-revocation-first")
	pub := d.publisher()

	v1 := d.makePluginDir("p-v1", map[string]string{"a.txt": "one"})
	d1 := d.digestOf(v1, cn)
	if _, err := pub.Publish(v1, cn, d.approve(cn, d1, "issuer-a", "issuer-b"), op.Hooks{}); err != nil {
		return err
	}
	v2 := d.makePluginDir("p-v2", map[string]string{"a.txt": "two"})
	d2 := d.digestOf(v2, cn)
	// d2 完整走完协议：回执与指针都已落盘，当前指针就是 d2。
	if _, err := pub.Publish(v2, cn, d.approve(cn, d2, "issuer-a", "issuer-b"), op.Hooks{}); err != nil {
		return err
	}
	// 撤销先于一切后续动作落盘，随即崩溃——切换/清理都还没发生。
	if _, err := pub.Revoke(d.signers["issuer-c"], d2, "演练：缺陷版本召回", op.CrashAfterRevocation); !isInjectedCrash(err) {
		return fmt.Errorf("预期撤销落盘后崩溃，实际 %v", err)
	}
	// 撤销文件确实已持久化，且独立验证器验签通过。
	rev, err := d.newStore().ReadRevocation(d2)
	if err != nil {
		return err
	}
	if err := op.VerifyRevocation(d.registry, rev); err != nil {
		return err
	}
	// 崩溃现场：指针仍引用已撤销的 d2。
	ptr, err := d.newStore().ReadPointer(cn)
	if err != nil {
		return err
	}
	if err := d.check(ptr.Digest == string(d2), "崩溃后指针应仍指着 d2（撤销先落盘、指针尚未处理）"); err != nil {
		return err
	}

	rep, err := d.verifier().Recover(cn)
	if err != nil {
		return err
	}
	d.logf("  恢复结果：%s，指针 %s → %s；d2 定性为「%s」（原地冻结不隔离）",
		rep.Outcome, short12(rep.PointerBefore), short12(rep.PointerAfter), findStatus(rep.Findings, d2))
	if err := d.check(rep.Outcome == op.OutcomeRolledBack && rep.PointerAfter == string(d1) && rep.Fallback == d1,
		"撤销先落盘时应沿历史回退到旧版 d1"); err != nil {
		return err
	}
	if err := d.check(findStatus(rep.Findings, d2) == op.StatusRevoked && len(rep.Quarantined) == 0,
		"d2 应标记为已撤销并保留证据，不得当作普通半成品隔离"); err != nil {
		return err
	}

	// 撤销落盘之后，同一目录摘要不能再发布——哪怕再次集齐两票。
	_, err = pub.Publish(v2, cn, d.approve(cn, d2, "issuer-a", "issuer-b"), op.Hooks{})
	var revokedErr *op.RevokedError
	if err := d.check(errors.As(err, &revokedErr), "已撤销摘要再次发布必须被拒绝，实际 %v", err); err != nil {
		return err
	}
	d.logf("  再发布被拒绝：%v", err)
	return nil
}

// S6 挂名代理不能算两票：本人与代理合计只有一个真实签发者。
func (d *drill) scenarioProxyVote() error {
	d.rootFor("s6-proxy")
	pub := d.publisher()

	v1 := d.makePluginDir("p-v1", map[string]string{"a.txt": "one"})
	d1 := d.digestOf(v1, cn)

	// issuer-a 亲自签 + proxy-a1 挂名签：背后是同一个真实签发者。
	_, err := pub.Publish(v1, cn, d.approve(cn, d1, "issuer-a", "proxy-a1"), op.Hooks{})
	var qerr *op.QuorumError
	if err := d.check(errors.As(err, &qerr), "代理凑票应触发法定人数错误，实际 %v", err); err != nil {
		return err
	}
	d.logf("  两纸批准只计 %d 个真实签发者（%v），门槛 %d", qerr.Got, qerr.Principals, qerr.Need)
	if err := d.check(qerr.Got == 1, "去重后应只有 1 票"); err != nil {
		return err
	}
	// 磁盘上不应留下半成品指针或回执。
	if _, err := d.newStore().ReadPointer(cn); !errors.Is(err, op.ErrNotFound) {
		return fmt.Errorf("失败发布不应写指针，实际 %v", err)
	}
	if _, err := d.newStore().ReadReceipt(cn, d1); !errors.Is(err, op.ErrNotFound) {
		return fmt.Errorf("失败发布不应写回执，实际 %v", err)
	}

	// 补上另一个真正独立的签发者后立即成立。
	if _, err := pub.Publish(v1, cn, d.approve(cn, d1, "issuer-a", "proxy-a1", "issuer-b"), op.Hooks{}); err != nil {
		return err
	}
	check, err := d.verifier().CheckPointer(cn)
	if err != nil {
		return err
	}
	return d.check(check.Healthy, "独立两票到齐后应发布成功且健康")
}

// S7 任一批准必须覆盖同一目录摘要：异摘要批准不能凑数。
func (d *drill) scenarioDigestMismatch() error {
	d.rootFor("s7-digest-mismatch")
	pub := d.publisher()

	v1 := d.makePluginDir("p-v1", map[string]string{"a.txt": "one"})
	vOther := d.makePluginDir("p-other", map[string]string{"a.txt": "different"})
	d1 := d.digestOf(v1, cn)
	dOther := d.digestOf(vOther, cn)

	bundles := d.approve(cn, d1, "issuer-a")
	// 第二张批准针对另一个目录的摘要，试图与第一张凑成两票。
	bundles = append(bundles, d.approve(cn, dOther, "issuer-b")...)
	_, err := pub.Publish(v1, cn, bundles, op.Hooks{})
	if err := d.check(err != nil && !errors.Is(err, op.ErrInjectedCrash), "异摘要批准必须被拒绝，实际 %v", err); err != nil {
		return err
	}
	d.logf("  异摘要批准被拒绝：%v", err)
	if _, err := d.newStore().ReadPointer(cn); !errors.Is(err, op.ErrNotFound) {
		return fmt.Errorf("失败发布不应写指针")
	}

	// 两张批准都覆盖 d1 后正常成立。
	if _, err := pub.Publish(v1, cn, d.approve(cn, d1, "issuer-a", "issuer-b"), op.Hooks{}); err != nil {
		return err
	}
	check, err := d.verifier().CheckPointer(cn)
	if err != nil {
		return err
	}
	return d.check(check.Healthy && check.Pointer.Digest == string(d1), "同摘要两票应发布成功")
}

// S8 两个真实发布者竞争同一代号，其中一个能人为卡在写回执前。
func (d *drill) scenarioContention() error {
	d.rootFor("s8-contention")

	vA := d.makePluginDir("p-A", map[string]string{"a.txt": "from-A"})
	vB := d.makePluginDir("p-B", map[string]string{"a.txt": "from-B"})
	dA, dB := d.digestOf(vA, cn), d.digestOf(vB, cn)

	// 发布者 A 拿到闸门：目录物化后、写回执前被人为卡住。
	gate := op.NewManualGate()
	blocked := make(chan struct{}, 1)
	finishedA := make(chan error, 1)
	pubA := d.publisher()
	go func() {
		_, err := pubA.Publish(vA, cn, d.approve(cn, dA, "issuer-a", "issuer-b"), op.Hooks{
			BlockBeforeReceipt: func(op.Codename, op.Digest) {
				blocked <- struct{}{}
				gate.Block(cn, dA)
			},
		})
		finishedA <- err
	}()
	<-blocked
	d.logf("  发布者 A 已卡在写回执前（目录已物化，回执/指针均未落盘）")

	// A 卡住期间，发布者 B 独立完成全套协议，赢得指针。
	resB, err := d.publisher().Publish(vB, cn, d.approve(cn, dB, "issuer-b", "issuer-c"), op.Hooks{})
	if err != nil {
		return err
	}
	if err := d.check(resB.Switched && resB.Digest == dB, "B 应先完成并赢得代号"); err != nil {
		return err
	}

	// 放行 A 并等它真正收尾：它的回执仍会合法落盘，但指针 CAS 必须失败，
	// 不能覆盖 B。用通道同步，避免用 sleep 猜时序。
	gate.Release()
	errA := <-finishedA
	var casErr *op.CASConflictError
	if err := d.check(errors.As(errA, &casErr), "A 放行后应收到指针 CAS 冲突，实际 %v", errA); err != nil {
		return err
	}
	ptr, err := d.newStore().ReadPointer(cn)
	if err != nil {
		return err
	}
	d.logf("  A 收尾报 %v；竞争结束后指针 = %s（B 的版本）", casErr, short(op.Digest(ptr.Digest)))
	if err := d.check(ptr.Digest == string(dB), "A 不得覆盖 B 已合法承诺的指针"); err != nil {
		return err
	}

	rep, err := d.verifier().Recover(cn)
	if err != nil {
		return err
	}
	if err := d.check(rep.Outcome == op.OutcomeKeptCurrent && rep.PointerAfter == string(dB),
		"恢复后仍应是 B 胜出"); err != nil {
		return err
	}
	if err := d.check(findStatus(rep.Findings, dA) == op.StatusCommitted,
		"A 的版本回执合法，应保留为已承诺版本（只是未被指针选中）"); err != nil {
		return err
	}
	hist, err := d.newStore().ReadHistory(cn)
	if err != nil {
		return err
	}
	if err := d.check(len(hist) == 1 && hist[0].Digest == string(dB),
		"承诺历史只能记录 B 这一次真正完成的切换，实际 %d 行", len(hist)); err != nil {
		return err
	}

	// A 基于最新磁盘状态重试（它想发布的仍是 dA）：这次 CAS 基于 dB，完成切换。
	resA2, err := d.publisher().Publish(vA, cn, d.approve(cn, dA, "issuer-a", "issuer-c"), op.Hooks{})
	if err != nil {
		return err
	}
	if err := d.check(resA2.Switched && resA2.Previous == dB, "A 重试应基于 B 的版本完成接力切换"); err != nil {
		return err
	}

	// 全仓直扫：验证器不接受任何内存参数，自己从磁盘枚举代号、版本、指针与孤儿。
	disk, err := d.verifier().ScanDisk()
	if err != nil {
		return err
	}
	if err := d.check(disk.IssuerCount == 4, "注册表应登记 4 个签发者（3 独立 + 1 代理），实际 %d", disk.IssuerCount); err != nil {
		return err
	}
	if err := d.check(len(disk.Codenames) == 1 && disk.Codenames[0].Check.Healthy,
		"直扫应发现 1 个健康代号，实际 %d 个", len(disk.Codenames)); err != nil {
		return err
	}
	// 接力后 dB 不再被指针引用，但它是已合法承诺版本，应作为孤儿被显式报告。
	if err := d.check(len(disk.Orphans) == 1 && strings.Contains(disk.Orphans[0], short(dB)),
		"直扫应报告 dB 为未被当前指针引用的孤儿版本，实际 %v", disk.Orphans); err != nil {
		return err
	}
	d.logf("  全仓直扫：%d 个签发者、%d 个代号、孤儿版本 %v", disk.IssuerCount, len(disk.Codenames), disk.Orphans)
	return nil
}

// S9 验证器直接扫描磁盘：篡改 payload 与伪造撤销都会被识破。
func (d *drill) scenarioVerifier() error {
	// 攻击一：篡改已发布目录里的文件字节。
	d.rootFor("s9a-tamper")
	pub := d.publisher()
	v1 := d.makePluginDir("p-v1", map[string]string{"bin/app.exe": "original", "cfg.ini": "cfg"})
	d1 := d.digestOf(v1, cn)
	if _, err := pub.Publish(v1, cn, d.approve(cn, d1, "issuer-a", "issuer-b"), op.Hooks{}); err != nil {
		return err
	}
	tampered := filepath.Join(d.root, "releases", string(cn), string(d1), "payload", "bin", "app.exe")
	if err := os.WriteFile(tampered, []byte("tampered-bytes"), 0o644); err != nil {
		return err
	}
	check, err := d.verifier().CheckPointer(cn)
	if err != nil {
		return err
	}
	d.logf("  篡改 payload 后验证器结论：healthy=%v，%s", check.Healthy, check.Finding.Detail)
	if err := d.check(!check.Healthy && check.Finding.Status == op.StatusCorrupt, "篡改必须被扫盘验证识破"); err != nil {
		return err
	}
	rep, err := d.verifier().Recover(cn)
	if err != nil {
		return err
	}
	if err := d.check(rep.Outcome == op.OutcomeNoValidVersion, "唯一版本损坏且无历史可回退，应判无有效版本"); err != nil {
		return err
	}

	// 攻击二：伪造一份撤销文件（用未登记/代理身份都无法通过）。
	d.rootFor("s9b-fake-revocation")
	pub = d.publisher()
	v2 := d.makePluginDir("p-v1", map[string]string{"a.txt": "one"})
	d2 := d.digestOf(v2, cn)
	if _, err := pub.Publish(v2, cn, d.approve(cn, d2, "issuer-a", "issuer-b"), op.Hooks{}); err != nil {
		return err
	}
	fake, err := d.signers["proxy-a1"].SignRevocation(d2, "伪造撤销")
	if err != nil {
		return err
	}
	revPath := filepath.Join(d.root, "revocations", string(d2)+".json")
	if err := op.AtomicWriteJSON(revPath, fake); err != nil {
		return err
	}
	bad, err := d.verifier().VerifyRevocationFiles()
	if err != nil {
		return err
	}
	d.logf("  伪造撤销文件扫描结果：%v", bad)
	if err := d.check(len(bad) == 1, "代理签署的撤销必须被判为非法"); err != nil {
		return err
	}
	// 合法撤销（独立签发者）则通过验证并生效。
	if _, err := pub.Revoke(d.signers["issuer-c"], d2, "真实召回", op.CrashNone); err != nil {
		return err
	}
	bad, err = d.verifier().VerifyRevocationFiles()
	if err != nil {
		return err
	}
	return d.check(len(bad) == 0, "合法撤销验签应全部通过，剩余异常 %v", bad)
}

// S10 共享内容目录上的局部变更重读计量。
func (d *drill) scenarioReRead() error {
	d.rootFor("s10-reread")
	base := d.makePluginDir("shared", map[string]string{
		"bin/app.exe":     "AAAA",
		"bin/helper.dll":  "BBBB",
		"cfg/conf.ini":    "CCCC",
		"cfg/policy.json": "DDDD",
		"assets/logo.txt": "EEEE",
	})
	scanner := op.NewCachedScanner(cn)

	// 冷扫描：5 个文件全部重读。
	r0, err := scanner.Scan(base, "冷扫描（缓存为空）")
	if err != nil {
		return err
	}
	d.printReRead(r0)
	if err := d.check(r0.Stats.FilesReHashed == 5 && r0.Stats.CacheHits == 0, "冷扫描应重读全部 5 个文件"); err != nil {
		return err
	}

	// 无变更再扫：零字节重读，摘要不变。
	r1, err := scanner.Scan(base, "无变更再扫描")
	if err != nil {
		return err
	}
	d.printReRead(r1)
	if err := d.check(r1.Stats.CacheHits == 5 && r1.Stats.BytesReHashed == 0, "无变更时不应重读任何字节"); err != nil {
		return err
	}
	if err := d.check(r1.Digest == r0.Digest, "缓存命中不得改变摘要结果"); err != nil {
		return err
	}

	// 局部变更 1：只改一个文件（内容等长，单靠大小无法发现，必须靠 mtime）。
	target := filepath.Join(base, "cfg", "conf.ini")
	if err := os.WriteFile(target, []byte("CCC2"), 0o644); err != nil {
		return err
	}
	// Windows 上 mtime 分辨率足够，但显式把 mtime 推后 2 秒保证与旧值不同。
	fut := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(target, fut, fut); err != nil {
		return err
	}
	r2, err := scanner.Scan(base, "局部变更：仅 cfg/conf.ini")
	if err != nil {
		return err
	}
	d.printReRead(r2)
	if err := d.check(r2.Stats.FilesReHashed == 1 && r2.Stats.CacheHits == 4,
		"只应重读 1 个变更文件，其余 4 个命中缓存"); err != nil {
		return err
	}
	if err := d.check(onlyReHashed(r2, "cfg/conf.ini"), "被重读的必须是 cfg/conf.ini"); err != nil {
		return err
	}
	if err := d.check(r2.Digest != r1.Digest, "内容变了摘要必须变化"); err != nil {
		return err
	}

	// 局部变更 2：新增一个文件，旧文件全部命中缓存。
	newFile := filepath.Join(base, "assets", "icon.txt")
	if err := os.WriteFile(newFile, []byte("FFFF"), 0o644); err != nil {
		return err
	}
	r3, err := scanner.Scan(base, "局部变更：新增 assets/icon.txt")
	if err != nil {
		return err
	}
	d.printReRead(r3)
	if err := d.check(r3.Stats.FilesTotal == 6 && r3.Stats.FilesReHashed == 1 && r3.Stats.CacheHits == 5,
		"新增场景只应重读新文件"); err != nil {
		return err
	}
	if err := d.check(onlyReHashed(r3, "assets/icon.txt"), "被重读的必须是新文件 assets/icon.txt"); err != nil {
		return err
	}

	// 局部变更 3：删除一个文件，不触发任何重读，但摘要变化。
	if err := os.Remove(filepath.Join(base, "bin", "helper.dll")); err != nil {
		return err
	}
	r4, err := scanner.Scan(base, "局部变更：删除 bin/helper.dll")
	if err != nil {
		return err
	}
	d.printReRead(r4)
	if err := d.check(r4.Stats.FilesTotal == 5 && r4.Stats.FilesReHashed == 0 && r4.Stats.CacheHits == 5,
		"删除场景不应重读任何留存文件"); err != nil {
		return err
	}
	if err := d.check(r4.Digest != r3.Digest, "删除文件后摘要必须变化"); err != nil {
		return err
	}

	// 重启语义：清空缓存后的冷扫描重新全量读取，但算出的摘要与热缓存一致。
	scanner.Reset()
	r5, err := scanner.Scan(base, "重启后冷扫描")
	if err != nil {
		return err
	}
	d.printReRead(r5)
	if err := d.check(r5.Stats.FilesReHashed == 5 && r5.Digest == r4.Digest,
		"冷扫描应全量重读且摘要与热路径完全一致"); err != nil {
		return err
	}
	return nil
}

// ---- 输出辅助 ----

func summarize(fs []op.ReleaseFinding) string {
	parts := make([]string, 0, len(fs))
	for _, f := range fs {
		parts = append(parts, short(f.Digest)+"="+string(f.Status))
	}
	return joinStr(parts, ", ")
}

func findStatus(fs []op.ReleaseFinding, d op.Digest) op.ReleaseStatus {
	for _, f := range fs {
		if f.Digest == d {
			return f.Status
		}
	}
	return "<未找到>"
}

func onlyReHashed(r op.ReReadReport, rel string) bool {
	for _, f := range r.Files {
		if f.ReHashed && f.Path != rel {
			return false
		}
	}
	for _, f := range r.Files {
		if f.Path == rel {
			return f.ReHashed
		}
	}
	return false
}

func (d *drill) printReRead(r op.ReReadReport) {
	d.logf("  〔%s〕文件 %d，重读 %d，缓存命中 %d，重读字节 %d，摘要 %s",
		r.Label, r.Stats.FilesTotal, r.Stats.FilesReHashed, r.Stats.CacheHits,
		r.Stats.BytesReHashed, short(r.Digest))
	for _, f := range r.Files {
		mark := "命中缓存(0B)"
		if f.ReHashed {
			mark = fmt.Sprintf("重读 %dB（%s）", f.BytesRead, f.Reason)
		}
		d.logf("    - %-18s %s", f.Path, mark)
	}
}

func short12(s string) string {
	if len(s) > 12 {
		return s[:12] + "…"
	}
	if s == "" {
		return "<无>"
	}
	return s
}

func joinStr(parts []string, sep string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += sep
		}
		out += p
	}
	return out
}
