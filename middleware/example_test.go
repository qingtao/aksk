package middleware_test

import (
	"fmt"
	"net/http"
	"time"

	"github.com/qingtao/aksk/v2/core"
	"github.com/qingtao/aksk/v2/middleware"
	"github.com/qingtao/aksk/v2/request"
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
		Config: request.Config{
			// Key 获取密钥, 必须非nil
			// 对于对称签名：返回 secretKey
			// 对于非对称签名：返回 PEM 格式的公钥
			KeyGetter: getSecretKey,
		},
		// 错误处理函数
		ErrorHandler: handleError,
	}
	opts := []core.OptionFunc{
		// 签名方法（必选）
		core.WithSignMethod(core.SignMethodHMACSHA256),
		// 编码格式
		core.WithEncoder(&core.Base64Encoder{}),
		// 签名的时间戳有效时间范围
		core.WithAcceptableSkew(60 * time.Second),
	}
	m, err := middleware.New(config, opts...)
	if err != nil {
		panic(err)
	}
	// 包装http.HandlerFunc
	http.Handle("/hello", m.HandleFunc(hello))
	http.ListenAndServe(":8080", nil)
}
