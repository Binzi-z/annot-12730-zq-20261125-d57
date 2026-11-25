//go:build !windows

package offlineplugin

import "os"

// syncDir 在类 Unix 上通过只读目录句柄 fsync，确保 rename/create 落盘。
func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
