// Package offlineplugin 在本地磁盘上重建柜台系统的离线插件发布与恢复协议。
//
// 本包只使用 Go 标准库，所有目录、授权（批准）与撤销数据均为本地模拟数据。
// 协议的核心不变量：
//
//  1. 每个发布版本是一个内容寻址目录，摘要由规范化文件清单决定；
//  2. 一个版本只有在拿到 >= Quorum 个【真正独立】签发者对【同一摘要】的批准，
//     并把由这些批准组成的回执先于指针落盘后，才构成“有效承诺”；
//  3. 挂名代理（proxy）的批准只记其背后真实签发者一票，不能把一票变成两票；
//  4. 指针切换与历史记录是原子的（临时文件 + rename），恢复时只允许落在
//     旧版本或已合法承诺的新版本上；
//  5. 撤销一旦落盘即对该摘要永久生效，无论指针是否还引用它。
package offlineplugin

// 文件布局（Root 之下）：
//
//	registry.json              签发者注册表（独立签发者 + 挂名代理映射）
//	pointers/<codename>.json   当前指针（原子替换）
//	history/<codename>.log     追加式承诺历史（每次有效切换一行 JSON）
//	releases/<codename>/<digest>/
//	    manifest.json            规范化文件清单
//	    payload/<相对路径>        插件文件
//	    receipt.json             法定人数回执（承诺凭证）
//	revocations/<digest>.json   撤销记录（按目录摘要命名）
//	staging/<codename>/...      发布过程中的临时目录（崩溃后即废弃）

const (
	// Quorum 是一个版本生效所需的最少独立签发者票数。
	Quorum = 2
)

// Digest 是一个插件目录的内容摘要（SHA-256，十六进制）。
type Digest string

// Codename 是插件代号；两个真实发布者竞争的就是同一个代号。
type Codename string

// FileEntry 是规范化清单中的单个文件。
type FileEntry struct {
	// Path 是相对于插件根的 POSIX 风格相对路径（永远用 '/'）。
	Path string `json:"path"`
	// Size 是文件字节数。
	Size int64 `json:"size"`
	// SHA256 是该文件内容的 SHA-256 十六进制摘要。
	SHA256 string `json:"sha256"`
}

// Manifest 是写入发布目录的规范化文件清单，目录摘要即对它求哈希。
type Manifest struct {
	Codename string      `json:"codename"`
	Files    []FileEntry `json:"files"`
}

// Approval 是单个签发者对某个插件目录的批准。
type Approval struct {
	Codename     string `json:"codename"`
	Digest       string `json:"digest"`
	IssuerID     string `json:"issuer_id"`
	Serial       int64  `json:"serial"`
	IssuedAtUnix int64  `json:"issued_at_unix"`
	ExpiresAt    int64  `json:"expires_at_unix"`
}

// Receipt 是回执：把覆盖同一摘要的多份独立批准绑定成一份法定人数承诺。
// 回执本身不另行签名——每份批准自带签名，验证器重验所有签名即可发现篡改。
type Receipt struct {
	Codename    string     `json:"codename"`
	Digest      string     `json:"digest"`
	Approvals   []Approval `json:"approvals"`
	Signatures  [][]byte   `json:"signatures"`
	CreatedUnix int64      `json:"created_unix"`
}

// Revocation 是对某个目录摘要的撤销记录，必须由一名独立签发者签署。
type Revocation struct {
	Digest        string `json:"digest"`
	IssuerID      string `json:"issuer_id"`
	Reason        string `json:"reason"`
	RevokedAtUnix int64  `json:"revoked_at_unix"`
	Signature     []byte `json:"signature"`
}

// Pointer 是某个代号当前指向的发布版本。
type Pointer struct {
	Codename      string `json:"codename"`
	Digest        string `json:"digest"`
	UpdatedAtUnix int64  `json:"updated_at_unix"`
}

// HistoryEntry 是追加式承诺历史中的一行；与指针切换在同一协议步骤内落盘。
type HistoryEntry struct {
	Codename       string `json:"codename"`
	Digest         string `json:"digest"`
	Previous       string `json:"previous"` // 切换前指针摘要，首个版本为空串
	SwitchedAtUnix int64  `json:"switched_at_unix"`
}
