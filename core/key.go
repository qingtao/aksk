package core

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// ParsePublicKey 解析PEM格式的公钥（内部使用）
func ParsePublicKey(pemStr string, algorithm string) (any, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	switch algorithm {
	case SignMethodRSASHA256, SignMethodRSASHA384, SignMethodRSASHA512:
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA public key: %w", err)
		}
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("not an RSA public key")
		}
		return rsaPub, nil
	case SignMethodECDSASHA256, SignMethodECDSASHA384, SignMethodECDSASHA512:
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ECDSA public key: %w", err)
		}
		ecdsaPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("not an ECDSA public key")
		}
		return ecdsaPub, nil
	case SignMethodEd25519:
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse Ed25519 public key: %w", err)
		}
		ed25519Pub, ok := pub.(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("not an Ed25519 public key")
		}
		return ed25519Pub, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// ParsePrivateKey 解析PEM格式的私钥（内部使用）
func ParsePrivateKey(pemStr string, algorithm string) (any, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	switch algorithm {
	case SignMethodRSASHA256, SignMethodRSASHA384, SignMethodRSASHA512:
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			// 尝试解析 PKCS8 格式
			pkcs8Key, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err2 != nil {
				return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
			}
			rsaKey, ok := pkcs8Key.(*rsa.PrivateKey)
			if !ok {
				return nil, errors.New("not an RSA private key")
			}
			return rsaKey, nil
		}
		return key, nil
	case SignMethodECDSASHA256, SignMethodECDSASHA384, SignMethodECDSASHA512:
		// 尝试解析 PKCS8 格式
		pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ECDSA private key: %w", err)
		}
		ecdsaKey, ok := pkcs8Key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("not an ECDSA private key")
		}
		return ecdsaKey, nil
	case SignMethodEd25519:
		// 尝试解析 PKCS8 格式
		pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse Ed25519 private key: %w", err)
		}
		ed25519Key, ok := pkcs8Key.(ed25519.PrivateKey)
		if !ok {
			return nil, errors.New("not an Ed25519 private key")
		}
		return ed25519Key, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// keyEntry 缓存的密钥条目, 包含过期时间
type keyEntry struct {
	key any
	exp time.Time
}

// keyStore 密钥存储，管理密钥缓存
type keyStore struct {
	mu        sync.RWMutex        // 保护 pubKeys 的并发访问
	pubKeys   map[string]keyEntry // 缓存解析后的公钥（ak -> publicKey）
	pubFlight singleflight.Group  // 合并公钥并发请求
	expire    time.Duration       // 公钥缓存过期时间, 0 表示不主动过期
	maxSize   int                 // 最大缓存条目数, 0 表示不限制
}

func newKeyStore() *keyStore {
	return &keyStore{
		pubKeys: make(map[string]keyEntry),
		// 默认缓存 10 分钟, 避免公钥解析结果无限增长;
		// 过期后重新解析由 singleflight 合并, 成本可控
		expire: 10 * time.Minute,
		// 默认上限 4096 个 ak, 超出时清空(公钥数量通常远小于此, 内存占用可忽略)
		maxSize: 4096,
	}
}

// getPubKey 从缓存获取公钥（内部使用）, 若已过期则视为未命中并删除
func (s *keyStore) getPubKey(ak string) (any, bool) {
	s.mu.RLock()
	e, ok := s.pubKeys[ak]
	s.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if s.expire > 0 && time.Now().After(e.exp) {
		s.delPubKey(ak)
		return nil, false
	}
	return e.key, true
}

// setPubKey 缓存公钥（内部使用）, 写入过期时间; 超出 maxSize 时清空后写入
func (s *keyStore) setPubKey(ak string, key any) {
	s.mu.Lock()
	if s.maxSize > 0 && len(s.pubKeys) >= s.maxSize {
		s.pubKeys = make(map[string]keyEntry)
	}
	var exp time.Time
	if s.expire > 0 {
		exp = time.Now().Add(s.expire)
	}
	s.pubKeys[ak] = keyEntry{key: key, exp: exp}
	s.mu.Unlock()
}

// delPubKey 删除缓存的公钥（内部使用）
func (s *keyStore) delPubKey(ak string) {
	s.mu.Lock()
	delete(s.pubKeys, ak)
	s.mu.Unlock()
}
