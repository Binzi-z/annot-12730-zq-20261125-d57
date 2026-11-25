package offlineplugin

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sort"
)

// FileReRead 记录单个文件在一次扫描中是否真的被重新读取。
type FileReRead struct {
	Path      string
	Size      int64
	ReHashed  bool   // false = 命中缓存，完全没重读字节
	BytesRead int64  // 实际从磁盘读取的字节数
	Reason    string // 未命中时的原因：新增 / 大小变化 / 修改时间变化
}

// ReReadStats 是一次扫描的重读计量。
type ReReadStats struct {
	FilesTotal    int   // 目录中的普通文件总数
	FilesReHashed int   // 真正重读内容的文件数
	CacheHits     int   // 命中缓存、零字节读取的文件数
	BytesReHashed int64 // 真正重读的总字节数
}

// ReReadReport 是一批目录局部变更实验的单次扫描结果。
type ReReadReport struct {
	Label  string
	Files  []FileReRead
	Stats  ReReadStats
	Digest Digest // 与正式协议相同口径的目录摘要，用于证明缓存不影响结果
}

// fileState 是缓存项：只依赖 size + 修改时间，不缓存文件内容本身。
type fileState struct {
	size  int64
	mtime int64 // UnixNano
	sha   string
}

// CachedScanner 在正式目录摘要算法之上包一层 (size, mtime) 缓存，
// 用来实测“局部变更后到底重读了哪些文件”。缓存只影响读取量，
// 不影响摘要结果——任何元数据变化都会触发完整重哈希。
type CachedScanner struct {
	codename Codename
	cache    map[string]fileState
}

// NewCachedScanner 创建扫描器。
func NewCachedScanner(c Codename) *CachedScanner {
	return &CachedScanner{codename: c, cache: make(map[string]fileState)}
}

// Reset 清空缓存，模拟进程重启后的冷扫描。
func (cs *CachedScanner) Reset() {
	cs.cache = make(map[string]fileState)
}

// Scan 扫描一个目录并返回逐文件的重读情况；重算的摘要与
// BuildManifest + DigestManifest 完全同口径。
func (cs *CachedScanner) Scan(dir, label string) (ReReadReport, error) {
	rep := ReReadReport{Label: label}
	var entries []FileEntry
	seen := make(map[string]bool)

	err := filepath.WalkDir(dir, func(full string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return &UnsupportedFileError{Path: full, Mode: info.Mode()}
		}
		rel := filepath.ToSlash(mustRel(dir, full))
		seen[rel] = true

		cur := fileState{size: info.Size(), mtime: info.ModTime().UnixNano()}
		prev, hit := cs.cache[rel]
		fr := FileReRead{Path: rel, Size: cur.size}

		switch {
		case !hit:
			fr.Reason = "新增文件"
		case prev.size != cur.size:
			fr.Reason = "大小变化"
		case prev.mtime != cur.mtime:
			fr.Reason = "修改时间变化"
		default:
			// 元数据完全一致：零字节读取，直接复用上次摘要。
			fr.ReHashed = false
			rep.Stats.CacheHits++
			entries = append(entries, FileEntry{Path: rel, Size: cur.size, SHA256: prev.sha})
			rep.Files = append(rep.Files, fr)
			rep.Stats.FilesTotal++
			return nil
		}

		sum, n, err := hashFile(full)
		if err != nil {
			return err
		}
		cur.sha = sum
		cs.cache[rel] = cur
		fr.ReHashed = true
		fr.BytesRead = n
		rep.Stats.FilesReHashed++
		rep.Stats.BytesReHashed += n
		entries = append(entries, FileEntry{Path: rel, Size: cur.size, SHA256: sum})
		rep.Files = append(rep.Files, fr)
		rep.Stats.FilesTotal++
		return nil
	})
	if err != nil {
		return rep, err
	}

	// 本轮没出现的文件属于被删除：从缓存剔除，保证下一轮不会复用幽灵项。
	for k := range cs.cache {
		if !seen[k] {
			delete(cs.cache, k)
		}
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	sort.Slice(rep.Files, func(i, j int) bool { return rep.Files[i].Path < rep.Files[j].Path })
	d, err := DigestManifest(Manifest{Codename: string(cs.codename), Files: entries})
	if err != nil {
		return rep, err
	}
	rep.Digest = d
	return rep, nil
}

func mustRel(base, full string) string {
	rel, err := filepath.Rel(base, full)
	if err != nil {
		panic(err)
	}
	return rel
}

func hashFile(p string) (string, int64, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
