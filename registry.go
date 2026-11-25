package offlineplugin

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// IssuerKind 区分真正独立的签发者与挂名代理。
type IssuerKind string

const (
	KindIndependent IssuerKind = "independent" // 真正独立的签发者
	KindProxy       IssuerKind = "proxy"       // 挂名代理：只代表背后的独立签发者
)

// Issuer 是注册表里的一个条目。公钥落盘；私钥只存在于模拟签发者内存中。
type Issuer struct {
	ID        string     `json:"id"`
	Kind      IssuerKind `json:"kind"`
	PublicKey []byte     `json:"public_key"`
	// PrincipalID 仅对 proxy 有意义：它背后真实独立签发者的 ID。
	PrincipalID string `json:"principal_id,omitempty"`
	// DisplayName 只用于演练输出，不参与任何安全判定。
	DisplayName string `json:"display_name"`
}

// Registry 是签发者注册表，验证器只信任这里登记的公钥。
type Registry struct {
	Issuers []Issuer `json:"issuers"`
	byID    map[string]*Issuer
}

// LoadRegistry 从磁盘读取注册表。
func LoadRegistry(path string) (*Registry, error) {
	var r Registry
	if err := ReadJSON(path, &r); err != nil {
		return nil, err
	}
	r.index()
	return &r, nil
}

// Save 把注册表落盘（模拟数据初始化时使用）。
func (r *Registry) Save(path string) error {
	r.index()
	return AtomicWriteJSON(path, r)
}

func (r *Registry) index() {
	r.byID = make(map[string]*Issuer, len(r.Issuers))
	for i := range r.Issuers {
		r.byID[r.Issuers[i].ID] = &r.Issuers[i]
	}
}

// Get 返回签发者条目。
func (r *Registry) Get(id string) (*Issuer, bool) {
	if r.byID == nil {
		r.index()
	}
	is, ok := r.byID[id]
	return is, ok
}

// Principal 把任意签发者 ID 解析为它代表的【真实独立签发者】ID。
// 独立签发者映射到自身；挂名代理映射到其 PrincipalID。
// 未知 ID 或代理背后不是独立签发者都返回错误。
func (r *Registry) Principal(id string) (string, error) {
	is, ok := r.Get(id)
	if !ok {
		return "", fmt.Errorf("未知签发者: %s", id)
	}
	switch is.Kind {
	case KindIndependent:
		return is.ID, nil
	case KindProxy:
		if is.PrincipalID == "" {
			return "", fmt.Errorf("代理 %s 缺少背后签发者", id)
		}
		principal, ok := r.Get(is.PrincipalID)
		if !ok || principal.Kind != KindIndependent {
			return "", fmt.Errorf("代理 %s 的背后签发者 %s 不合法", id, is.PrincipalID)
		}
		return principal.ID, nil
	default:
		return "", fmt.Errorf("签发者 %s 类型未知: %s", id, is.Kind)
	}
}

// VerifySignature 用登记公钥校验签名，签发者不存在或类型不允许都报错。
func (r *Registry) VerifySignature(issuerID string, msg, sig []byte) error {
	is, ok := r.Get(issuerID)
	if !ok {
		return fmt.Errorf("未登记签发者: %s", issuerID)
	}
	if len(is.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("签发者 %s 公钥长度异常", issuerID)
	}
	if !ed25519.Verify(ed25519.PublicKey(is.PublicKey), msg, sig) {
		return &BadSignatureError{IssuerID: issuerID}
	}
	return nil
}

// BadSignatureError 表示签名验签失败。
type BadSignatureError struct {
	IssuerID string
}

func (e *BadSignatureError) Error() string {
	return "签名验证失败: " + e.IssuerID
}

// Signer 是持有私钥的模拟签发者，仅存在于内存（模拟离线授权介质）。
type Signer struct {
	issuer    Issuer
	private   ed25519.PrivateKey
	now       func() int64
	serialSeq int64
}

// NewSigner 基于注册条目和私钥构造模拟签发者。
func NewSigner(is Issuer, private ed25519.PrivateKey) *Signer {
	return &Signer{issuer: is, private: private, now: defaultClock}
}

// Issuer 返回该签名者的注册条目。
func (s *Signer) Issuer() Issuer { return s.issuer }

// GenerateKey 生成一对 Ed25519 密钥（纯本地模拟数据）。
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// SignApproval 对指定代号/摘要签发一份批准。
func (s *Signer) SignApproval(codename Codename, d Digest, ttlSeconds int64) (Approval, []byte, error) {
	s.serialSeq++
	now := s.now()
	a := Approval{
		Codename:     string(codename),
		Digest:       string(d),
		IssuerID:     s.issuer.ID,
		Serial:       s.serialSeq,
		IssuedAtUnix: now,
		ExpiresAt:    now + ttlSeconds,
	}
	msg, err := approvalSigningBytes(a)
	if err != nil {
		return Approval{}, nil, err
	}
	sig := ed25519.Sign(s.private, msg)
	return a, sig, nil
}

// SignRevocation 对指定摘要签发撤销记录。
func (s *Signer) SignRevocation(d Digest, reason string) (Revocation, error) {
	r := Revocation{
		Digest:        string(d),
		IssuerID:      s.issuer.ID,
		Reason:        reason,
		RevokedAtUnix: s.now(),
	}
	msg, err := revocationSigningBytes(r)
	if err != nil {
		return Revocation{}, err
	}
	r.Signature = ed25519.Sign(s.private, msg)
	return r, nil
}

// VerifyApproval 重算批准签名并核对内容绑定。
func VerifyApproval(r *Registry, a Approval, sig []byte) error {
	msg, err := approvalSigningBytes(a)
	if err != nil {
		return err
	}
	if err := r.VerifySignature(a.IssuerID, msg, sig); err != nil {
		return err
	}
	if _, err := r.Principal(a.IssuerID); err != nil {
		return err
	}
	return nil
}

// VerifyRevocation 校验撤销记录的签名，且签发者必须是独立签发者。
func VerifyRevocation(r *Registry, rev Revocation) error {
	is, ok := r.Get(rev.IssuerID)
	if !ok {
		return fmt.Errorf("撤销签发者未登记: %s", rev.IssuerID)
	}
	if is.Kind != KindIndependent {
		return fmt.Errorf("撤销必须由独立签发者签署，%s 是 %s", rev.IssuerID, is.Kind)
	}
	msg, err := revocationSigningBytes(rev)
	if err != nil {
		return err
	}
	return r.VerifySignature(rev.IssuerID, msg, rev.Signature)
}

// CountIndependentApprovals 统计一批批准覆盖了多少个【真正独立】的签发者。
// 去重键是解析后的 PrincipalID：同一个真实签发者无论亲自签还是让代理签，
// 都只算一票；两个代理若背后是同一人，也只算一票。
// 同时校验所有批准确实覆盖同一代号与同一摘要。
func CountIndependentApprovals(reg *Registry, codename Codename, d Digest, approvals []Approval, sigs [][]byte) (int, error) {
	if len(approvals) != len(sigs) {
		return 0, errors.New("批准与签名数量不一致")
	}
	principals := make(map[string]struct{})
	for i, a := range approvals {
		if a.Codename != string(codename) {
			return 0, fmt.Errorf("批准代号不匹配: %s != %s", a.Codename, codename)
		}
		if a.Digest != string(d) {
			return 0, fmt.Errorf("批准摘要不匹配: %s != %s", a.Digest, d)
		}
		if err := VerifyApproval(reg, a, sigs[i]); err != nil {
			return 0, err
		}
		principal, err := reg.Principal(a.IssuerID)
		if err != nil {
			return 0, err
		}
		principals[principal] = struct{}{}
	}
	return len(principals), nil
}

// MustHexKey 是测试/演练辅助：把十六进制私钥解析为 ed25519 私钥。
func MustHexKey(h string) ed25519.PrivateKey {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	return ed25519.PrivateKey(b)
}

// ensureRoot 初始化仓库目录骨架。
func ensureRoot(root string) error {
	for _, sub := range []string{"pointers", "history", "releases", "revocations", "staging"} {
		if err := os.MkdirAll(filepath.Join(root, sub), 0o755); err != nil {
			return err
		}
	}
	return nil
}
