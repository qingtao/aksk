package http_test

import (
	"crypto/sha1"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/qingtao/aksk/core"
	aksk "github.com/qingtao/aksk/middleware/http"
)

func getSecretKey(ak string) string {
	// TODO: get secret_key
	return ""
}

func handleError(w http.ResponseWriter, err error) {
	if err == nil {
		return
	}
	var e *core.Error
	var b []byte
	if !errors.As(err, &e) {
		e = &core.Error{Message: err.Error()}
	}
	b, _ = json.Marshal(e)
	w.Header().Set("Context-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	w.Write(b)
}

func hello(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(`hello world!`))
}

func ExampleNew() {
	config := aksk.Config{
		// Key 获取密钥, 必须非nil
		Key: getSecretKey,
		// 不验证请求Body
		SkipBody: false,
		// 错误处理函数
		ErrorHandler: handleError,
	}
	opts := core.Options{
		// 编码格式
		Encoder: &core.Base64Encoder{},
		// 哈希算法
		Hash: sha1.New,
		// 签名的时间戳有效时间范围
		Duration: 60 * time.Second,
	}
	middleware := aksk.New(config, opts)
	// 包装http.HandlerFunc
	http.HandleFunc("/hello", middleware.HandleFunc(hello))
	http.ListenAndServe(":8080", nil)
}
