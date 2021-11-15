// Package core aksk认证的编码和hash算法定义
package core

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
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

// KeyGetter 查询accesskey,返回secretKey的函数
type KeyGetter func(accessKey string) (secretKey string, err error)

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
	// 初始化时使用的编码方法
	Encoder Encoder
	// 初始化时使用的hash算法
	Hash HashFunc
	// 检查时间戳时,允许的误差
	AcceptableSkew time.Duration
}

func defaultOptions() *Options {
	return &Options{
		Encoder:        &Base64Encoder{},
		Hash:           sha256.New,
		AcceptableSkew: 60 * time.Second,
	}
}

// Option 选项
type Option func(*Options)

func mergeOptions(opts ...Option) *Options {
	o := defaultOptions()
	for _, opt := range opts {
		if opt != nil {
			opt(o)
		}
	}
	return o
}

// WithEncoder 使用指定的编码
func WithEncoder(enc Encoder) Option {
	return func(o *Options) {
		if enc != nil {
			o.Encoder = enc
		}
	}
}

// WithHash 使用指定的hash函数
func WithHash(h HashFunc) Option {
	return func(o *Options) {
		if h != nil {
			o.Hash = h
		}
	}
}

// WithAcceptableSkew 可接受的时间误差
func WithAcceptableSkew(d time.Duration) Option {
	return func(o *Options) {
		if d >= 0 {
			o.AcceptableSkew = d
		}
	}
}

// New 新建认证对象,默认时: 字符串编码使用base64.StdEncoding, hash算法使用sha256,允许的时间戳误差为60秒
func New(opts ...Option) *Auth {
	o := mergeOptions(opts...)
	return &Auth{
		enc: o.Encoder,
		h:   o.Hash,
		d:   o.AcceptableSkew,
	}
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
	if d > s.d {
		return fmt.Errorf("timestamp %s expired", ts)
	} else if d < -s.d {
		return fmt.Errorf("timestamp %s invalid", ts)
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
		return fmt.Errorf("the mac of body is empty")
	}
	mac, err := s.enc.DecodeString(str)
	if err != nil {
		return fmt.Errorf("body invalid")
	}
	if ok := bytes.Equal(mac, s.Sum(b)); !ok {
		return fmt.Errorf("body invalid")
	}
	return nil
}

// ValidSignature 校验头部签名
func (s *Auth) ValidSignature(sk, sign string, elems ...string) error {
	// 解码签名,得道原始的字节切片
	mac, err := s.enc.DecodeString(sign)
	if err != nil {
		return fmt.Errorf("signature %s invalid", sign)
	}
	if ok := hmac.Equal(mac, s.Hmac([]byte(sk), elems...)); !ok {
		return errors.New("signature invalid")
	}
	return nil
}
