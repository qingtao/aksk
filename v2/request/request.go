// Package request 包含http请求的头部常量和构造函数
package request

import (
	"bytes"
	"context"
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

// HandlerFunc aksk的请求构造函数
type HandlerFunc func(ctx context.Context, method, url string, body io.Reader) (*http.Request, error)

// NewHandlerFunc 返回一个HandlerFunc
func NewHandlerFunc(ak, sk string, skipBody bool, opts ...core.Option) (HandlerFunc, error) {
	if ak == "" {
		return nil, errors.New("access key is empty")
	}
	if sk == "" {
		return nil, errors.New("access key is invalid")
	}
	auth := core.New(opts...)
	fn := func(ctx context.Context, method, url string, body io.Reader) (req *http.Request, err error) {

		// 随机字符串
		b := make([]byte, 6)
		if _, err := io.ReadFull(rand.Reader, b); err != nil {
			return nil, fmt.Errorf("read random string: %w", err)
		}
		randomstr := auth.EncodeToString(b)
		ss := make([]string, 0, 4)
		ss = append(ss, ak, randomstr)
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		ss = append(ss, ts)

		var bodyhash string

		if !skipBody {
			buf := new(bytes.Buffer)
			r := io.TeeReader(body, buf)
			b, err := ioutil.ReadAll(r)
			if err != nil {
				return nil, fmt.Errorf("read body: %w", err)
			}
			body = buf
			bodyhash = auth.EncodeToString(auth.Sum(b))
			ss = append(ss, bodyhash)
		}
		req, err = http.NewRequestWithContext(ctx, method, url, body)
		if err != nil {
			return nil, fmt.Errorf("create http request: %w", err)
		}
		b = auth.Hmac([]byte(sk), ss...)
		// ak头部
		req.Header.Set(HeaderAccessKey, ak)
		// randomstr头部
		req.Header.Set(HeaderRandomStr, randomstr)
		// 时间戳头部
		req.Header.Set(HeaderTimestamp, ts)
		if bodyhash != "" {
			// body的hash头部
			req.Header.Set(HeaderBodyHash, bodyhash)
		}
		// 签名头部
		req.Header.Set(HeaderSignature, auth.EncodeToString(b))

		return req, nil
	}
	return fn, nil
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

// Validate 校验请求
func Validate(req *http.Request, a *core.Auth, f core.KeyGetter, skipBody bool) error {
	ak := req.Header.Get(HeaderAccessKey)
	if ak == "" {
		return errors.New("access key is empty")
	}
	sk := f(ak)
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
	if skipBody {
		return nil
	}
	b, err := readBody(req)
	if err != nil {
		return err
	}
	return a.ValidBody(b, bodyhash)
}
