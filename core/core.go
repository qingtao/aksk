package core

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"sort"
	"strconv"
	"strings"
	"time"
)

// HashFunc 返回一个hash.Hash接口
type HashFunc func() hash.Hash

// Encoder 编码方法接口
type Encoder interface {
	// EncodeToString 编码成字符串
	EncodeToString(b []byte) string
	// DecodeString 将字符串解码成字节切片
	DecodeString(s string) ([]byte, error)
}

// hexEncoder 16进制编码格式
type hexEncoder struct{}

// EncodeToString 编码为16进制字符串
func (h *hexEncoder) EncodeToString(b []byte) string {
	return hex.EncodeToString(b)
}

// DecodeString 解码给定的16进制字符串得到MAC
func (h *hexEncoder) DecodeString(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

const (
	// HeaderAccessKey accesskey
	HeaderAccessKey = `x-auth-access-key`
	// HeaderTimestramp 访问时间戳, 前1分钟或者后5分钟之内有效
	HeaderTimestramp = `x-auth-timestramp`
	// HeaderSignature hmac的签名,值取决于hash算法和编码规则
	HeaderSignature = `x-auth-signature`
	// HeaderBodyHash Body的hash值,值取决于hash算法
	HeaderBodyHash = `x-auth-body-hash`
	// HeaderRandomStr 随机字符串
	HeaderRandomStr = `x-auth-random-str`
)

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
	// HashFn 初始化时使用的hash算法
	HashFn HashFunc
	// 时间戳在一个时间段内有效
	Duration time.Duration
}

func mergeOptions(opts ...Options) Options {
	o := Options{}
	for _, opt := range opts {
		if opt.Encoder != nil {
			o.Encoder = opt.Encoder
		}
		if opt.HashFn != nil {
			o.HashFn = opt.HashFn
		}
		if opt.Duration > 0 {
			o.Duration = opt.Duration
		}
	}
	if o.Encoder == nil {
		o.Encoder = &hexEncoder{}
	}
	if o.HashFn == nil {
		o.HashFn = sha256.New
	}
	if o.Duration <= 0 {
		o.Duration = 2 * time.Minute
	}
	return o
}

// New 新建认证对象
func New(opts ...Options) *Auth {
	o := mergeOptions(opts...)
	return &Auth{
		enc: o.Encoder,
		h:   o.HashFn,
	}
}

// ParseTimestramp 解析时间戳,如果时间戳不是有效的整数,或者超过指定的时间段,则认为无效
func (s *Auth) ParseTimestramp(ts string) error {
	if ts == "" {
		return &Error{Message: timestrampEmpty}
	}
	n, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return &Error{Message: timestrampInvalid, Err: err}
	}
	t := time.Unix(n, 0)
	d := time.Now().Sub(t)
	if d > s.d {
		return &Error{Message: timestrampExpired, Err: err}
	} else if d < -s.d {
		return &Error{Message: timestrampInvalid, Err: err}
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
		return &Error{Message: bodyInvalid, Err: err}
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
		return &Error{Message: signatureInvalid, Err: err}
	}
	if ok := hmac.Equal(mac, s.Hmac([]byte(sk), elems...)); !ok {
		return &Error{Message: signatureInvalid}
	}
	return nil
}
