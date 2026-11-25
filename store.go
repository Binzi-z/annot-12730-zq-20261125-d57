package offlineplugin

import (
	"path/filepath"
	"time"
)

// defaultClock 返回真实当前时间（Unix 秒）。测试可注入固定时钟。
func defaultClock() int64 { return time.Now().Unix() }

// Store 是离线插件仓库的磁盘句柄。多个 Store 指向同一 Root 时，
// 指针切换的 CAS 由磁盘文件内容决定；同进程内另有每代号互斥锁
// 避免 goroutine 竞争（见 Publisher）。
type Store struct {
	Root  string
	Clock func() int64
}

// NewStore 打开（必要时初始化）一个本地仓库。
func NewStore(root string) (*Store, error) {
	if err := ensureRoot(root); err != nil {
		return nil, err
	}
	return &Store{Root: root, Clock: defaultClock}, nil
}

func (s *Store) now() int64 {
	if s.Clock != nil {
		return s.Clock()
	}
	return defaultClock()
}

// ---- 磁盘路径 ----

func (s *Store) registryPath() string {
	return join(s.Root, "registry.json")
}

func (s *Store) pointerPath(c Codename) string {
	return join(s.Root, "pointers", string(c)+".json")
}

func (s *Store) historyPath(c Codename) string {
	return join(s.Root, "history", string(c)+".log")
}

func (s *Store) releaseBase(c Codename) string {
	return join(s.Root, "releases", string(c))
}

func (s *Store) releaseDir(c Codename, d Digest) string {
	return join(s.releaseBase(c), string(d))
}

func (s *Store) manifestPath(c Codename, d Digest) string {
	return join(s.releaseDir(c, d), "manifest.json")
}

func (s *Store) payloadDir(c Codename, d Digest) string {
	return join(s.releaseDir(c, d), "payload")
}

func (s *Store) receiptPath(c Codename, d Digest) string {
	return join(s.releaseDir(c, d), "receipt.json")
}

func (s *Store) revocationPath(d Digest) string {
	return join(s.Root, "revocations", string(d)+".json")
}

func (s *Store) stagingDir(c Codename, nonce string) string {
	return join(s.Root, "staging", string(c), nonce)
}

func join(elem ...string) string {
	// 统一走 filepath.Join，Windows 上得到反斜杠路径。
	return filepath.Join(elem...)
}
