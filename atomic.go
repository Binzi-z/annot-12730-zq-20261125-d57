package offlineplugin

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// AtomicWrite 以“临时文件 + 重命名”方式把 data 写入 dst：
// 先写同目录临时文件并 fsync 落盘，再 rename 原子替换，最后 fsync 目录，
// 保证崩溃后要么看到旧文件、要么看到完整新文件，不会出现半截 JSON。
func AtomicWrite(dst string, data []byte) error {
	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, dst); err != nil {
		cleanup()
		return err
	}
	return syncDir(dir)
}

// AtomicWriteJSON 规范化写入 JSON 文档。
func AtomicWriteJSON(dst string, v any) error {
	data, err := canonicalJSON(v)
	if err != nil {
		return err
	}
	return AtomicWrite(dst, data)
}

// ReadJSON 读取并解析 JSON 文档。
func ReadJSON(src string, v any) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// AppendLine 向追加式日志写入一行并 fsync；目录也一并 fsync。
func AppendLine(path string, line []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}
