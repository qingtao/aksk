// Package core aksk认证的编码和hash算法定义
package core

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"sort"
	"strconv"
	"strings"
	"time"
)

// KeyGetter 查询accesskey,返回密钥的函数
// 对于对称签名（HMAC）：返回 secretKey
// 对于非对称签名（RSA/ECDSA/Ed25519）：返回 PEM 格式的公钥/私钥, 取决于是签名还是验证
type KeyGetter func(accessKey string) (key string, err error)

// HashFunc 返回一个hash.Hash接口
type HashFunc func() hash.Hash

// Encoder 编码方法接口
type Encoder interface {
	// EncodeToString 编码成字符串
	EncodeToString(b []byte) string
	// DecodeString 将字符串解码成字节切片
	DecodeString(s string) ([]byte, error)
}

// HexEncoder 16进制编码格式
type HexEncoder struct{}

// EncodeToString 编码为16进制字符串
func (enc *HexEncoder) EncodeToString(b []byte) string {
	return hex.EncodeToString(b)
}

// DecodeString 解码给定的16进制字符串得到MAC
func (enc *HexEncoder) DecodeString(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

// Base64Encoder base64编码格式
type Base64Encoder struct{}

// EncodeToString 编码为base64字符串
func (enc *Base64Encoder) EncodeToString(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// DecodeString 解码给定的base64字符串的但MAC
func (enc *Base64Encoder) DecodeString(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// Auth 核心功能
type Auth struct {
	enc            Encoder
	acceptableSkew time.Duration
	signMethod     string
	signer         Signer
	keys           *keyStore
}

// OptionFunc 选项函数，直接修改 Auth 并返回错误
type OptionFunc func(*Auth)

// WithEncoder 使用指定的编码
func WithEncoder(enc Encoder) OptionFunc {
	return func(a *Auth) {
		if enc != nil {
			a.enc = enc
		}
	}
}

// WithAcceptableSkew 可接受的时间误差
func WithAcceptableSkew(d time.Duration) OptionFunc {
	return func(a *Auth) {
		if d >= 0 {
			a.acceptableSkew = d
		}
	}
}

// WithSignMethod 使用指定的签名方法
// 可选值: hmac-sha256, hmac-sha384, hmac-sha512, rsa-sha256, rsa-sha384, rsa-sha512,
//
//	ecdsa-sha256, ecdsa-sha384, ecdsa-sha512, ed25519
func WithSignMethod(method string) OptionFunc {
	return func(a *Auth) {
		a.signMethod = strings.ToUpper(method)
	}
}

// 签名方法常量
const (
	SignMethodHMACSHA256  = "HMAC-SHA256"
	SignMethodHMACSHA384  = "HMAC-SHA384"
	SignMethodHMACSHA512  = "HMAC-SHA512"
	SignMethodRSASHA256   = "RSA-SHA256"
	SignMethodRSASHA384   = "RSA-SHA384"
	SignMethodRSASHA512   = "RSA-SHA512"
	SignMethodECDSASHA256 = "ECDSA-SHA256"
	SignMethodECDSASHA384 = "ECDSA-SHA384"
	SignMethodECDSASHA512 = "ECDSA-SHA512"
	SignMethodEd25519     = "ED25519"
)

// Key 错误类型
var (
	// ErrKeyNotFound 密钥不存在，应该清除缓存
	ErrKeyNotFound = errors.New("key not found")
	// ErrKeyRevoked 密钥已撤销，应该清除缓存
	ErrKeyRevoked = errors.New("key revoked")
	// ErrKeyExpired 密钥已过期，应该清除缓存
	ErrKeyExpired = errors.New("key expired")
)

// IsKeyError 判断是否是需要清除缓存的密钥错误
func IsKeyError(err error) bool {
	return errors.Is(err, ErrKeyNotFound) ||
		errors.Is(err, ErrKeyRevoked) ||
		errors.Is(err, ErrKeyExpired)
}

// isHMAC 判断是否是HMAC签名算法（内部使用）
func isHMAC(algorithm string) bool {
	return strings.HasPrefix(algorithm, "HMAC-")
}

// New 新建认证对象并返回错误（支持所有签名方法）
// 默认时: 字符串编码使用base64.StdEncoding, 允许的时间戳误差为60秒
// 当未指定 SignMethod 时，默认使用 HMAC-SHA256 以保持向后兼容
// signMethod 会统一转换为大写并验证有效性
func New(opts ...OptionFunc) (*Auth, error) {
	a := &Auth{
		enc:            &Base64Encoder{},
		acceptableSkew: 60 * time.Second,
		keys:           newKeyStore(),
	}

	for _, opt := range opts {
		if opt != nil {
			opt(a)
		}
	}

	if a.signMethod == "" {
		a.signMethod = SignMethodHMACSHA256
	}

	signer, err := newSigner(a.signMethod)
	if err != nil {
		return nil, err
	}
	a.signer = signer

	return a, nil
}

// ParseTimestamp 解析时间戳,如果时间戳不是有效的整数,或者超过允许的时间误差,则认为是无效的
func (s *Auth) ParseTimestamp(ts string) error {
	if ts == "" {
		return fmt.Errorf("timetamp is empty")
	}
	n, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return fmt.Errorf("timestamp %s invalid: %w", ts, err)
	}
	t := time.Unix(n, 0)
	d := time.Since(t)
	if d > s.acceptableSkew {
		return fmt.Errorf("timestamp %s expired", ts)
	} else if d < -s.acceptableSkew {
		return fmt.Errorf("timestamp %s invalid", ts)
	}
	return nil
}

// EncodeToString 编码
func (s *Auth) EncodeToString(b []byte) string {
	return s.enc.EncodeToString(b)
}

// Verify 校验头部签名
// ak: access key
// key: 对于HMAC签名是secretKey，对于非对称签名是PEM格式的公钥
func (s *Auth) Verify(ak, sk, sign string, elems ...string) error {
	if s.signer == nil {
		return errors.New("signer not initialized")
	}
	// 解码签名
	signature, err := s.enc.DecodeString(sign)
	if err != nil {
		return fmt.Errorf("signature %s invalid", sign)
	}

	// 构建签名数据: 各字段升序排序后以英文逗号连接(access key 不得包含逗号)
	sort.Strings(elems)
	data := []byte(strings.Join(elems, ","))

	var key any

	if isHMAC(s.signMethod) {
		key = []byte(sk)
	} else {
		// 获取已解析的公钥
		publicKey, err := s.getPublicKey(ak, sk)
		if err != nil {
			return fmt.Errorf("parse public key error: %w", err)
		}
		key = publicKey
	}
	return s.signer.Verify(data, signature, key)
}

// getPublicKey 获取已解析的公钥，如果不存在则解析并缓存（内部使用）
// ak: access key，用作缓存键
// key: PEM 格式的公钥
func (s *Auth) getPublicKey(ak, sk string) (any, error) {
	// 快速路径：检查缓存
	if cached, ok := s.keys.getPubKey(ak); ok {
		return cached, nil
	}

	// 使用 singleflight 合并并发请求
	result, err, _ := s.keys.pubFlight.Do(ak, func() (any, error) {
		// 再次检查缓存
		if cached, ok := s.keys.getPubKey(ak); ok {
			return cached, nil
		}

		// 解析密钥
		parsed, err := ParsePublicKey(sk, s.signMethod)
		if err != nil {
			return nil, err
		}

		// 缓存解析后的密钥
		s.keys.setPubKey(ak, parsed)
		return parsed, nil
	})

	if err != nil {
		return nil, err
	}
	return result, nil
}

// HandleKeyError 处理密钥错误，如果是需要清除缓存的错误则清除（公开方法）
// 当 KeyGetter 返回 ErrKeyNotFound、ErrKeyRevoked 或 ErrKeyExpired 时调用
func (s *Auth) HandleKeyError(ak string, err error) {
	if IsKeyError(err) {
		s.keys.delPubKey(ak)
	}
}

// Sign 对数据进行签名
// 对于HMAC签名：sk是secretKey
// 对于非对称签名：sk是PEM格式的私钥
func (s *Auth) Sign(sk any, elems ...string) (string, error) {
	if s.signer == nil {
		return "", errors.New("signer not initialized")
	}
	// 构建签名数据: 各字段升序排序后以英文逗号连接(access key 不得包含逗号)
	sort.Strings(elems)
	data := []byte(strings.Join(elems, ","))

	var key any
	if isHMAC(s.signMethod) {
		switch v := sk.(type) {
		case string:
			key = []byte(v)
		case []byte:
			key = v
		default:
			return "", fmt.Errorf("invalid secret key type for HMAC: %T", sk)
		}
	} else {
		key = sk
	}

	// 签名
	signature, err := s.signer.Sign(data, key)
	if err != nil {
		return "", fmt.Errorf("sign error: %w", err)
	}

	return s.enc.EncodeToString(signature), nil
}
