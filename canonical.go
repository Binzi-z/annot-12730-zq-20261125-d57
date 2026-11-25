package offlineplugin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// canonicalJSON 以确定的字段顺序（结构体声明顺序）序列化，
// 并禁用 HTML 转义、补换行，保证签名与摘要跨进程可复现。
func canonicalJSON(v any) ([]byte, error) {
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return []byte(buf.String()), nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// approvalSigningBytes 返回批准待签名的规范化字节。
func approvalSigningBytes(a Approval) ([]byte, error) {
	// 显式列出字段，避免结构体增删字段时静默改变签名口径。
	payload := struct {
		Kind         string `json:"kind"`
		Codename     string `json:"codename"`
		Digest       string `json:"digest"`
		IssuerID     string `json:"issuer_id"`
		Serial       int64  `json:"serial"`
		IssuedAtUnix int64  `json:"issued_at_unix"`
		ExpiresAt    int64  `json:"expires_at_unix"`
	}{
		Kind:         "offlineplugin.approval/v1",
		Codename:     a.Codename,
		Digest:       a.Digest,
		IssuerID:     a.IssuerID,
		Serial:       a.Serial,
		IssuedAtUnix: a.IssuedAtUnix,
		ExpiresAt:    a.ExpiresAt,
	}
	return canonicalJSON(payload)
}

// revocationSigningBytes 返回撤销待签名的规范化字节。
func revocationSigningBytes(r Revocation) ([]byte, error) {
	payload := struct {
		Kind          string `json:"kind"`
		Digest        string `json:"digest"`
		IssuerID      string `json:"issuer_id"`
		Reason        string `json:"reason"`
		RevokedAtUnix int64  `json:"revoked_at_unix"`
	}{
		Kind:          "offlineplugin.revocation/v1",
		Digest:        r.Digest,
		IssuerID:      r.IssuerID,
		Reason:        r.Reason,
		RevokedAtUnix: r.RevokedAtUnix,
	}
	return canonicalJSON(payload)
}

// manifestSigningBytes 返回清单（即目录摘要）的规范化字节。
func manifestSigningBytes(m Manifest) ([]byte, error) {
	return canonicalJSON(struct {
		Kind     string   `json:"kind"`
		Manifest Manifest `json:"manifest"`
	}{
		Kind:     "offlineplugin.manifest/v1",
		Manifest: m,
	})
}

// DigestManifest 对规范化清单求摘要。
func DigestManifest(m Manifest) (Digest, error) {
	b, err := manifestSigningBytes(m)
	if err != nil {
		return "", err
	}
	return Digest(sha256Hex(b)), nil
}

// BuildManifest 扫描一个本地目录，生成排序后的规范化清单。
// 只统计普通文件；符号链接等非常规文件直接拒绝，避免离线包藏链路。
func BuildManifest(dir string, codename Codename) (Manifest, error) {
	dir = filepath.Clean(dir)
	var entries []FileEntry
	err := filepath.WalkDir(dir, func(full string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if full == dir {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			// 目录本身会被 WalkDir 继续下钻；其他非普通文件一律拒绝。
			if d.IsDir() {
				return nil
			}
			return &UnsupportedFileError{Path: full, Mode: info.Mode()}
		}
		rel, err := filepath.Rel(dir, full)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "." || strings.HasPrefix(rel, "../") || rel == ".." {
			return &UnsupportedFileError{Path: full, Mode: info.Mode()}
		}
		f, err := os.Open(full)
		if err != nil {
			return err
		}
		defer f.Close()
		h := sha256.New()
		size, err := io.Copy(h, f)
		if err != nil {
			return err
		}
		entries = append(entries, FileEntry{
			Path:   rel,
			Size:   size,
			SHA256: hex.EncodeToString(h.Sum(nil)),
		})
		return nil
	})
	if err != nil {
		return Manifest{}, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return Manifest{Codename: string(codename), Files: entries}, nil
}

// VerifyManifest 重算磁盘上发布目录的清单，并与已记录清单逐文件比对。
// 返回重算得到的实际摘要；任何不一致都以错误返回。
func VerifyManifest(releaseDir string, recorded Manifest) (Digest, error) {
	actual, err := BuildManifest(releaseDir, Codename(recorded.Codename))
	if err != nil {
		return "", err
	}
	actualDigest, err := DigestManifest(actual)
	if err != nil {
		return "", err
	}
	if len(actual.Files) != len(recorded.Files) {
		return actualDigest, &ManifestMismatchError{Reason: "文件数量不一致"}
	}
	for i := range actual.Files {
		a, w := actual.Files[i], recorded.Files[i]
		if a.Path != w.Path || a.Size != w.Size || a.SHA256 != w.SHA256 {
			return actualDigest, &ManifestMismatchError{Reason: "文件 " + path.Base(a.Path) + " 与清单不符"}
		}
	}
	recordedDigest, err := DigestManifest(recorded)
	if err != nil {
		return "", err
	}
	if recordedDigest != actualDigest {
		return actualDigest, &ManifestMismatchError{Reason: "清单摘要不一致"}
	}
	return actualDigest, nil
}

// UnsupportedFileError 表示离线目录里出现了不被允许的文件类型。
type UnsupportedFileError struct {
	Path string
	Mode os.FileMode
}

func (e *UnsupportedFileError) Error() string {
	return "不支持的文件类型: " + e.Path + " (" + e.Mode.String() + ")"
}

// ManifestMismatchError 表示磁盘内容与清单/摘要不符。
type ManifestMismatchError struct {
	Reason string
}

func (e *ManifestMismatchError) Error() string {
	return "目录清单校验失败: " + e.Reason
}
