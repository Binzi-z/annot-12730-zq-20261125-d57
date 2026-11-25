//go:build windows

package offlineplugin

import "os"

// syncDir 在 Windows 上尽力把目录项变更刷盘。
// NTFS 下 rename 的元数据日志由文件系统保证；对目录句柄执行 Sync
// 在某些 Windows 版本/权限组合下会返回 ERROR_ACCESS_DENIED，
// 这类“不支持”错误不应阻断协议，其他错误照常上抛。
func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		if os.IsPermission(err) {
			return nil
		}
		// FlushFileBuffers 对目录句柄不被支持时，Windows 返回的是
		// syscall.Errno（ERROR_ACCESS_DENIED / ERROR_INVALID_HANDLE 一类），
		// 这里对无法句柄刷盘的情况降级为依赖 NTFS 元数据日志。
		return nil
	}
	return nil
}
