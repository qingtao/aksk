package middleware_test

import (
	"crypto/sha1"
	"fmt"
	"net/http"
	"time"

	"github.com/qingtao/aksk/v2/core"
	"github.com/qingtao/aksk/v2/middleware"
)

func getSecretKey(ak string) (string, error) {
	// TODO: get secret_key
	return "", nil
}

func handleError(w http.ResponseWriter, err error) {
	if err == nil {
		return
	}
	w.WriteHeader(http.StatusUnauthorized)
	fmt.Fprintf(w, "%s", err)
}

func hello(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(`hello world!`))
}

func ExampleNew() {
	config := middleware.Config{
		// Key 获取密钥, 必须非nil
		KeyGetter: getSecretKey,
		// 不验证请求Body
		SkipBody: false,
		// 错误处理函数
		ErrorHandler: handleError,
	}
	opts := []core.Option{
		// 编码格式
		core.WithEncoder(&core.Base64Encoder{}),
		// 哈希算法
		core.WithHash(sha1.New),
		// 签名的时间戳有效时间范围
		core.WithAcceptableSkew(60 * time.Second),
	}
	middleware := middleware.New(config, opts...)
	// 包装http.HandlerFunc
	http.Handle("/hello", middleware.HandleFunc(hello))
	http.ListenAndServe(":8080", nil)
}
