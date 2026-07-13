package core

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
)

// Signer 签名器接口
type Signer interface {
	// Sign 使用密钥对数据进行签名
	// 对于非对称签名：key 是私钥
	// 对于 HMAC：key 是 secretKey
	Sign(data []byte, key any) ([]byte, error)
	// Verify 使用密钥验证签名
	// 对于非对称签名：key 是公钥
	// 对于 HMAC：key 是 secretKey
	Verify(data []byte, signature []byte, key any) error
	// Algorithm 返回签名算法名称
	Algorithm() string
}

// HMACSigner HMAC签名器
type HMACSigner struct {
	hashFunc  func() hash.Hash
	algorithm string
}

// NewHMACSigner 创建HMAC签名器
func NewHMACSigner(hashFunc HashFunc, algorithm string) *HMACSigner {
	return &HMACSigner{
		hashFunc:  hashFunc,
		algorithm: algorithm,
	}
}

// Sign 使用HMAC签名
// data 格式：access_key + timestamp + nonce（按字符串排序后拼接, nonce 可空）
// key 是 secretKey
func (s *HMACSigner) Sign(data []byte, key any) ([]byte, error) {
	secretKey, ok := key.([]byte)
	if !ok {
		return nil, errors.New("invalid key type for HMAC")
	}

	h := hmac.New(s.hashFunc, secretKey)
	h.Write(data)
	return h.Sum(nil), nil
}

// Verify 验证HMAC签名
func (s *HMACSigner) Verify(data []byte, signature []byte, key any) error {
	computed, err := s.Sign(data, key)
	if err != nil {
		return err
	}
	if !hmac.Equal(computed, signature) {
		return errors.New("signature invalid")
	}
	return nil
}

// Algorithm 返回签名算法名称
func (s *HMACSigner) Algorithm() string {
	return s.algorithm
}

// RSASigner RSA签名器
type RSASigner struct {
	hash      crypto.Hash
	algorithm string
}

// NewRSASigner 创建RSA签名器
func NewRSASigner(hash crypto.Hash, algorithm string) *RSASigner {
	return &RSASigner{hash: hash, algorithm: algorithm}
}

// Sign 使用RSA私钥签名
func (s *RSASigner) Sign(data []byte, privateKey any) ([]byte, error) {
	key, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("invalid private key type")
	}
	hashed := s.hash.New()
	hashed.Write(data)
	return rsa.SignPKCS1v15(rand.Reader, key, s.hash, hashed.Sum(nil))
}

// Verify 使用RSA公钥验证签名
func (s *RSASigner) Verify(data []byte, signature []byte, publicKey any) error {
	key, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("invalid public key type")
	}
	hashed := s.hash.New()
	hashed.Write(data)
	return rsa.VerifyPKCS1v15(key, s.hash, hashed.Sum(nil), signature)
}

// Algorithm 返回签名算法名称
func (s *RSASigner) Algorithm() string {
	return s.algorithm
}

// ECDSASigner ECDSA签名器
type ECDSASigner struct {
	hash      crypto.Hash
	algorithm string
}

// NewECDSASigner 创建ECDSA签名器
func NewECDSASigner(hash crypto.Hash, algorithm string) *ECDSASigner {
	return &ECDSASigner{hash: hash, algorithm: algorithm}
}

// Sign 使用ECDSA私钥签名
func (s *ECDSASigner) Sign(data []byte, privateKey any) ([]byte, error) {
	key, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("invalid private key type")
	}
	hashed := s.hash.New()
	hashed.Write(data)
	return ecdsa.SignASN1(rand.Reader, key, hashed.Sum(nil))
}

// Verify 使用ECDSA公钥验证签名
func (s *ECDSASigner) Verify(data []byte, signature []byte, publicKey any) error {
	key, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("invalid public key type")
	}
	hashed := s.hash.New()
	hashed.Write(data)
	if !ecdsa.VerifyASN1(key, hashed.Sum(nil), signature) {
		return errors.New("invalid signature")
	}
	return nil
}

// Algorithm 返回签名算法名称
func (s *ECDSASigner) Algorithm() string {
	return s.algorithm
}

// Ed25519Signer Ed25519签名器
type Ed25519Signer struct {
	algorithm string
}

// NewEd25519Signer 创建Ed25519签名器
func NewEd25519Signer(algorithm string) *Ed25519Signer {
	return &Ed25519Signer{algorithm: algorithm}
}

// Sign 使用Ed25519私钥签名
func (s *Ed25519Signer) Sign(data []byte, privateKey any) ([]byte, error) {
	key, ok := privateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("invalid private key type")
	}
	return ed25519.Sign(key, data), nil
}

// Verify 使用Ed25519公钥验证签名
func (s *Ed25519Signer) Verify(data []byte, signature []byte, publicKey any) error {
	key, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		return errors.New("invalid public key type")
	}
	if !ed25519.Verify(key, data, signature) {
		return errors.New("invalid signature")
	}
	return nil
}

// Algorithm 返回签名算法名称
func (s *Ed25519Signer) Algorithm() string {
	return s.algorithm
}

// newSigner 根据算法名称获取签名器（内部使用）
func newSigner(algorithm string) (Signer, error) {
	switch algorithm {

	case SignMethodHMACSHA256:
		return NewHMACSigner(sha256.New, algorithm), nil
	case SignMethodHMACSHA384:
		return NewHMACSigner(sha512.New384, algorithm), nil
	case SignMethodHMACSHA512:
		return NewHMACSigner(sha512.New, algorithm), nil
	case SignMethodRSASHA256:
		return NewRSASigner(crypto.SHA256, algorithm), nil
	case SignMethodRSASHA384:
		return NewRSASigner(crypto.SHA384, algorithm), nil
	case SignMethodRSASHA512:
		return NewRSASigner(crypto.SHA512, algorithm), nil
	case SignMethodECDSASHA256:
		return NewECDSASigner(crypto.SHA256, algorithm), nil
	case SignMethodECDSASHA384:
		return NewECDSASigner(crypto.SHA384, algorithm), nil
	case SignMethodECDSASHA512:
		return NewECDSASigner(crypto.SHA512, algorithm), nil
	case SignMethodEd25519:
		return NewEd25519Signer(algorithm), nil
	default:
		return nil, errors.New("unsupported signing algorithm")
	}
}
