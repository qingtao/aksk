package request

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/antlinker/aksk/core"
)

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

	// AccessKeyEmpty ak为空
	AccessKeyEmpty = "accesskey为空"
	// SecretKeyEmpty sk为空
	SecretKeyEmpty = "accesskey无效"
	// SignatueEmpty 请求签名为空
	SignatueEmpty = "缺少签名"
)

// HandlerFunc aksk的请求构造函数
type HandlerFunc func(ctx context.Context, method, url string, body []byte) (*http.Request, error)

// NewHandlerFunc 返回一个HandlerFunc
func NewHandlerFunc(ak, sk string, opts ...core.Options) (HandlerFunc, error) {
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
			return nil, fmt.Errorf("创建HTTP请求发生错误:%w", err)
		}

		// 随机字符串
		b := make([]byte, 6)
		if _, err := io.ReadFull(rand.Reader, b); err != nil {
			return nil, fmt.Errorf("读取随机字符串发生错误:%w", err)
		}
		randomstr := hex.EncodeToString(b)

		ss := make([]string, 0, 4)
		ss = append(ss, ak, randomstr)
		// ak头部
		req.Header.Set(HeaderAccessKey, ak)
		// randomstr头部
		req.Header.Set(HeaderRandomStr, randomstr)

		ts := strconv.FormatInt(time.Now().Unix(), 10)
		ss = append(ss, ts)
		// 时间戳头部
		req.Header.Set(HeaderTimestramp, ts)

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
