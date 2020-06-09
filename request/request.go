// Package request 包含http请求的头部常量和构造函数
package request

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"

	"github.com/qingtao/aksk/core"
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

	// AccessKeyEmpty ak为空
	AccessKeyEmpty = "accesskey is empty"
	// SecretKeyEmpty sk为空
	SecretKeyEmpty = "invalid accesskey"
	// SignatueEmpty 请求签名为空
	SignatueEmpty = "signature is empty"
)

// HandlerFunc aksk的请求构造函数
type HandlerFunc func(ctx context.Context, method, url string, body []byte) (*http.Request, error)

// New 返回一个HandlerFunc
func New(ak, sk string, opts ...core.Options) (HandlerFunc, error) {
	if ak == "" {
		return nil, &core.Error{Message: AccessKeyEmpty}
	}
	if sk == "" {
		return nil, &core.Error{Message: SecretKeyEmpty}
	}
	auth := core.New(opts...)
	fn := func(ctx context.Context, method, url string, body []byte) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("create http request: %w", err)
		}

		// 随机字符串
		b := make([]byte, 6)
		if _, err := io.ReadFull(rand.Reader, b); err != nil {
			return nil, fmt.Errorf("read random string: %w", err)
		}
		randomstr := auth.EncodeToString(b)

		ss := make([]string, 0, 4)
		ss = append(ss, ak, randomstr)
		// ak头部
		req.Header.Set(HeaderAccessKey, ak)
		// randomstr头部
		req.Header.Set(HeaderRandomStr, randomstr)

		ts := strconv.FormatInt(time.Now().Unix(), 10)
		ss = append(ss, ts)
		// 时间戳头部
		req.Header.Set(HeaderTimestamp, ts)

		if len(body) > 0 {
			bodyhash := auth.EncodeToString(auth.Sum(body))
			ss = append(ss, bodyhash)
			// body的hash头部
			req.Header.Set(HeaderBodyHash, bodyhash)
		}

		// 签名头部
		b = auth.Hmac([]byte(sk), ss...)
		req.Header.Set(HeaderSignature, auth.EncodeToString(b))
		return req, nil
	}
	return fn, nil
}

// ReadBody 读取body
func ReadBody(r *http.Request) ([]byte, error) {
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, core.NewError("read body", err)
	}
	r.Body = ioutil.NopCloser(bytes.NewReader(b))

	return bytes.TrimSpace(b), nil
}
