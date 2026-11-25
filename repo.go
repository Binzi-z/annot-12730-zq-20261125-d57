package offlineplugin

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ErrNotFound 表示指针/回执/撤销等磁盘对象不存在。
var ErrNotFound = errors.New("对象不存在")

// ReadPointer 读取代号当前指针；不存在返回 ErrNotFound。
func (s *Store) ReadPointer(c Codename) (Pointer, error) {
	var p Pointer
	if err := ReadJSON(s.pointerPath(c), &p); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Pointer{}, ErrNotFound
		}
		return Pointer{}, err
	}
	return p, nil
}

// ReadHistory 读取追加式承诺历史（崩溃产生的半行会被跳过）。
func (s *Store) ReadHistory(c Codename) ([]HistoryEntry, error) {
	f, err := os.Open(s.historyPath(c))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []HistoryEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var h HistoryEntry
		if err := json.Unmarshal([]byte(line), &h); err != nil {
			// 崩溃可能留下最后半行：跳过无法解析的尾部，前面的完整行仍有效。
			continue
		}
		out = append(out, h)
	}
	return out, sc.Err()
}

// ReadReceipt 读取某个发布目录的回执；不存在返回 ErrNotFound。
func (s *Store) ReadReceipt(c Codename, d Digest) (Receipt, error) {
	var r Receipt
	if err := ReadJSON(s.receiptPath(c, d), &r); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Receipt{}, ErrNotFound
		}
		return Receipt{}, err
	}
	return r, nil
}

// ReadManifest 读取发布目录的清单。
func (s *Store) ReadManifest(c Codename, d Digest) (Manifest, error) {
	var m Manifest
	if err := ReadJSON(s.manifestPath(c, d), &m); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Manifest{}, ErrNotFound
		}
		return Manifest{}, err
	}
	return m, nil
}

// ReadRevocation 读取某摘要的撤销记录；不存在返回 ErrNotFound。
func (s *Store) ReadRevocation(d Digest) (Revocation, error) {
	var r Revocation
	if err := ReadJSON(s.revocationPath(d), &r); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Revocation{}, ErrNotFound
		}
		return Revocation{}, err
	}
	return r, nil
}

// ListRevocations 扫描撤销目录，返回全部已落盘撤销的摘要。
func (s *Store) ListRevocations() ([]Digest, error) {
	base := join(s.Root, "revocations")
	entries, err := os.ReadDir(base)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []Digest
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		out = append(out, Digest(strings.TrimSuffix(e.Name(), ".json")))
	}
	return out, nil
}

// ListReleases 直接扫描 releases/<codename> 目录，列出磁盘上所有版本目录
// （包括没有回执、没有指针的“孤儿”半成品——验证器要靠它发现异常）。
func (s *Store) ListReleases(c Codename) ([]Digest, error) {
	base := s.releaseBase(c)
	entries, err := os.ReadDir(base)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []Digest
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, Digest(e.Name()))
		}
	}
	return out, nil
}

// ListCodenames 扫描指针目录，列出仓库里出现过的代号。
func (s *Store) ListCodenames() ([]Codename, error) {
	entries, err := os.ReadDir(join(s.Root, "pointers"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []Codename
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			out = append(out, Codename(strings.TrimSuffix(e.Name(), ".json")))
		}
	}
	return out, nil
}

// copyTree 把源目录整体复制到目标（目标的父目录会被创建）。
// 复制完成后由调用方负责 fsync/rename 语义；这里只做普通文件递归拷贝。
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(full string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, full)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return &UnsupportedFileError{Path: full, Mode: info.Mode()}
		}
		return copyFile(full, target, info.Mode().Perm())
	})
}

func copyFile(src, dst string, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".copy-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := io.Copy(tmp, in); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, dst)
}

// compareAndSwapPointer 仅当磁盘上的旧指针摘要等于 expect 时，
// 才把指针原子替换为 next。expect 为空串表示“当前必须没有指针”。
// 这是两个发布者竞争同一代号时的仲裁点：后写者必须基于最新磁盘状态，
// 否则 CAS 失败，不会覆盖掉别人已经合法承诺的版本。
func (s *Store) compareAndSwapPointer(c Codename, expect string, next Pointer) error {
	cur, err := s.ReadPointer(c)
	switch {
	case errors.Is(err, ErrNotFound):
		if expect != "" {
			return &CASConflictError{Codename: string(c), Want: expect, Have: ""}
		}
	case err != nil:
		return err
	default:
		if cur.Digest != expect {
			return &CASConflictError{Codename: string(c), Want: expect, Have: cur.Digest}
		}
	}
	return AtomicWriteJSON(s.pointerPath(c), next)
}

// CASConflictError 表示指针竞争失败：磁盘状态已被其他发布者推进。
type CASConflictError struct {
	Codename string
	Want     string
	Have     string
}

func (e *CASConflictError) Error() string {
	return fmt.Sprintf("指针 CAS 冲突（代号 %s）：期望旧摘要 %q，实际 %q", e.Codename, short(e.Want), short(e.Have))
}

// TruncateHistoryLast 去掉承诺历史的最后一行。CAS 竞争失败时，
// 失败者要撤回自己刚追加但未被指针采纳的历史行，保证
// “历史只记录已合法承诺的切换”这一不变量。
func (s *Store) TruncateHistoryLast(c Codename) error {
	p := s.historyPath(c)
	data, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return nil
	}
	kept := strings.Join(lines[:len(lines)-1], "\n")
	if kept != "" {
		kept += "\n"
	}
	return AtomicWrite(p, []byte(kept))
}

func short(d string) string {
	if len(d) <= 12 {
		return d
	}
	return d[:12] + "…"
}
