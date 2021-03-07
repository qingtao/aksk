// Package request 包含http请求的头部常量和构造函数
package request

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"

	"github.com/qingtao/aksk/v2/core"
)

const (
	// HeaderAccessKey accesskey
	HeaderAccessKey = `x-auth-access-key`
	// HeaderTimestamp 访问时间戳, 前1分钟或者后5分钟之内有效
	HeaderTimestamp = `x-auth-timestamp`
	// HeaderSignature hmac的签名,值取决于hash算法和编码规则
	HeaderSignature = `x-auth-signature`
	// HeaderBodyHash Body的hash值,值取决于hash算法
	HeaderBodyHash = `x-auth-body-hash`
	// HeaderRandomStr 随机字符串
	HeaderRandomStr = `x-auth-random-str`
)

// Modifier 接口实现修改请求
type Modifier interface {
	// 修改请求,添加aksk的头部信息到*http.Request
	ModifyRequest(req *http.Request) error
}

// ModifierFunc 一个修改请求,附加aksk的签名头部的函数
type ModifierFunc func(req *http.Request) error

// ModifyRequest 附加aksk的签名头部的函数类型
func (f ModifierFunc) ModifyRequest(req *http.Request) error {
	return f(req)
}

// NewModifierFunc 创建新的修改请求的函数
func NewModifierFunc(ak, sk string, skipBody bool, opts ...core.Option) (ModifierFunc, error) {
	if ak == "" {
		return nil, errors.New("access key is empty")
	}
	if sk == "" {
		return nil, errors.New("access key is invalid")
	}
	a := core.New(opts...)
	modifier := func(req *http.Request) error {
		// 随机字符串
		b := make([]byte, 6)
		if _, err := io.ReadFull(rand.Reader, b); err != nil {
			return fmt.Errorf("read random string: %w", err)
		}
		randomstr := a.EncodeToString(b)
		ss := make([]string, 0, 4)
		ss = append(ss, ak, randomstr)
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		ss = append(ss, ts)

		var bodyhash string
		if !skipBody && req.Body != nil {
			b, err := readBody(req)
			if err != nil {
				return err
			}
			bodyhash = a.EncodeToString(a.Sum(b))
			ss = append(ss, bodyhash)
			req.Body = ioutil.NopCloser(bytes.NewReader(b))
		}
		b = a.Hmac([]byte(sk), ss...)
		// 添加ak头部
		req.Header.Set(HeaderAccessKey, ak)
		// 添加randomstr头部
		req.Header.Set(HeaderRandomStr, randomstr)
		// 添加时间戳头部
		req.Header.Set(HeaderTimestamp, ts)
		if bodyhash != "" {
			// body的hash头部
			req.Header.Set(HeaderBodyHash, bodyhash)
		}
		// 添加签名头部
		req.Header.Set(HeaderSignature, a.EncodeToString(b))
		return nil
	}
	return modifier, nil
}

// readBody 读取body
func readBody(r *http.Request) ([]byte, error) {
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, errors.New("read body failed")
	}
	r.Body = ioutil.NopCloser(bytes.NewReader(b))

	return bytes.TrimSpace(b), nil
}

// Validator 验证器
type Validator interface {
	// 验证请求的aksk头部签名,验证失败返回非空错误
	Validate(req *http.Request) error
}

// ValidatorFunc 验证器函数
type ValidatorFunc func(req *http.Request) error

// Validate 通过aksk签名验证请求
func (f ValidatorFunc) Validate(req *http.Request) error {
	return f(req)
}

// NewValidatorFunc 创键aksk的验证器
func NewValidatorFunc(getter core.KeyGetter, skipBody bool, opts ...core.Option) (ValidatorFunc, error) {
	if getter == nil {
		return nil, errors.New("key getter is nil")
	}
	a := core.New(opts...)
	validator := func(req *http.Request) error {
		ak := req.Header.Get(HeaderAccessKey)
		if ak == "" {
			return errors.New("access key is empty")
		}
		sk, err := getter(ak)
		if err != nil {
			return fmt.Errorf("getter key error %w", err)
		}
		if sk == "" {
			return errors.New("access key is invalid")
		}
		ts := req.Header.Get(HeaderTimestamp)
		if err := a.ParseTimestamp(ts); err != nil {
			return err
		}
		signature := req.Header.Get(HeaderSignature)
		if signature == "" {
			return errors.New("signature is empty")
		}
		bodyhash := req.Header.Get(HeaderBodyHash)
		randomstr := req.Header.Get(HeaderRandomStr)
		if err := a.ValidSignature(sk, signature, ak, ts, randomstr, bodyhash); err != nil {
			return err
		}
		if skipBody || req.Body == nil {
			return nil
		}
		b, err := readBody(req)
		if err != nil {
			return err
		}
		return a.ValidBody(b, bodyhash)
	}
	return validator, nil
}
