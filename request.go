package ginaksk

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

	"github.com/antlinker/ginaksk/core"
)

// RequestFunc aksk的请求构造函数
type RequestFunc func(ctx context.Context, method, url string, body []byte) (*http.Request, error)

const (
	// accessKeyEmpty ak为空
	accessKeyEmpty = "accesskey为空"
	// secretKeyEmpty sk为空
	secretKeyEmpty = "accesskey无效"
)

// NewRequestFunc 返回一个RequestFunc
func NewRequestFunc(ak, sk string, opts ...core.Options) (RequestFunc, error) {
	if ak == "" {
		return nil, &core.Error{Message: accessKeyEmpty}
	}
	if sk == "" {
		return nil, &core.Error{Message: secretKeyEmpty}
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
		req.Header.Set(core.HeaderAccessKey, ak)
		// randomstr头部
		req.Header.Set(core.HeaderRandomStr, randomstr)

		ts := strconv.FormatInt(time.Now().Unix(), 10)
		ss = append(ss, ts)
		// 时间戳头部
		req.Header.Set(core.HeaderTimestramp, ts)

		if len(body) > 0 {
			bodyhash := auth.EncodeToString(auth.Sum(body))
			ss = append(ss, bodyhash)
			// body的hash头部
			req.Header.Set(core.HeaderBodyHash, bodyhash)
		}

		// 签名头部
		b = auth.Hmac([]byte(sk), ss...)
		req.Header.Set(core.HeaderSignature, auth.EncodeToString(b))
		return req, nil
	}
	return fn, nil
}
