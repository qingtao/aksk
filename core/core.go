// Package core aksk认证的编码和hash算法定义
package core

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"hash"
	"sort"
	"strconv"
	"strings"
	"time"
)

// KeyFunc 查询accesskey,返回secretKey的函数
type KeyFunc func(accessKey string) (secretKey string)

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
	enc Encoder
	h   HashFunc
	d   time.Duration
}

// Options 选项
type Options struct {
	// Encoder 初始化时使用的编码方法
	Encoder Encoder
	// Hash 初始化时使用的hash算法
	Hash HashFunc
	// 时间戳在一个时间段内有效
	Duration time.Duration
}

func mergeOptions(opts ...Options) Options {
	o := Options{}
	for _, opt := range opts {
		if opt.Encoder != nil {
			o.Encoder = opt.Encoder
		}
		if opt.Hash != nil {
			o.Hash = opt.Hash
		}
		if opt.Duration > 0 {
			o.Duration = opt.Duration
		}
	}
	if o.Encoder == nil {
		o.Encoder = &Base64Encoder{}
	}
	if o.Hash == nil {
		o.Hash = sha256.New
	}
	if o.Duration <= 0 {
		o.Duration = 2 * time.Minute
	}
	return o
}

// New 新建认证对象,默认时: 字符串编码使用base64.StdEncoding, hash算法使用sha256,时间戳有效时间2分钟
func New(opts ...Options) *Auth {
	o := mergeOptions(opts...)
	return &Auth{
		enc: o.Encoder,
		h:   o.Hash,
		d:   o.Duration,
	}
}

// ParseTimestamp 解析时间戳,如果时间戳不是有效的整数,或者超过指定的时间段,则认为无效
func (s *Auth) ParseTimestamp(ts string) error {
	if ts == "" {
		return &Error{Message: timestampEmpty}
	}
	n, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return &Error{Message: timestampInvalid, err: err}
	}
	t := time.Unix(n, 0)
	d := time.Now().Sub(t)
	if d > s.d {
		return &Error{Message: timestampExpired, err: err}
	} else if d < -s.d {
		return &Error{Message: timestampInvalid, err: err}
	}
	return nil
}

// Sum 计算hash值
func (s *Auth) Sum(b []byte) []byte {
	h := s.h()
	h.Write(b)
	return h.Sum(nil)
}

// EncodeToString 编码
func (s *Auth) EncodeToString(b []byte) string {
	return s.enc.EncodeToString(b)
}

// Hmac 计算hmac值
func (s *Auth) Hmac(key []byte, elems ...string) []byte {
	h := hmac.New(s.h, key)
	sort.Strings(elems)
	str := strings.Join(elems, "")
	h.Write([]byte(str))
	return h.Sum(nil)
}

// ValidBody 通过计算请求b的sha256值验证请求内容
// 如果b长度为0, 返回真; 否则检查mac和编码器计算的Mac是否一致
func (s *Auth) ValidBody(b []byte, str string) error {
	if len(b) == 0 {
		return nil
	}
	if str == "" {
		return &Error{Message: bodyHashEmpty}
	}
	mac, err := s.enc.DecodeString(str)
	if err != nil {
		return &Error{Message: bodyInvalid, err: err}
	}
	if ok := bytes.Equal(mac, s.Sum(b)); !ok {
		return &Error{Message: bodyInvalid}
	}
	return nil
}

// ValidSignature 校验头部签名
func (s *Auth) ValidSignature(sk, sign string, elems ...string) error {
	// 解码签名,得道原始的字节切片
	mac, err := s.enc.DecodeString(sign)
	if err != nil {
		return &Error{Message: signatureInvalid, err: err}
	}
	if ok := hmac.Equal(mac, s.Hmac([]byte(sk), elems...)); !ok {
		return &Error{Message: signatureInvalid}
	}
	return nil
}
