// Package http aksk认证中间件
package http

import (
	"encoding/json"
	"net/http"

	"github.com/qingtao/aksk/core"
	"github.com/qingtao/aksk/request"
)

// ErrorHandler 错误处理函数, 接收错误处理后, 不再执行后续操作
type ErrorHandler func(w http.ResponseWriter, err error)

func defaultErrorHandler(w http.ResponseWriter, err error) {
	if err == nil {
		return
	}
	e := &core.Error{Message: err.Error()}
	b, _ := json.Marshal(e)
	w.Header().Set("Context-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	w.Write(b)
}

// Middleware 中间件
type Middleware struct {
	auth         *core.Auth
	keyFn        core.KeyFunc
	skipBody     bool
	errorHandler ErrorHandler
}

// Config 配置
type Config struct {
	Key          core.KeyFunc
	SkipBody     bool
	ErrorHandler ErrorHandler
}

// New 新建一个中间件
func New(cfg Config, opts ...core.Options) *Middleware {
	if cfg.Key == nil {
		panic("Config.Key is nil")
	}
	middleware := &Middleware{
		keyFn:        cfg.Key,
		skipBody:     cfg.SkipBody,
		errorHandler: cfg.ErrorHandler,
		auth:         core.New(opts...),
	}
	if middleware.errorHandler == nil {
		middleware.errorHandler = defaultErrorHandler
	}
	return middleware
}

// Handle 验证请求, 成功后调用handler.ServeHTTP(w,r)
func (m *Middleware) Handle(handler http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := m.ValidRequest(r); err != nil {
			m.errorHandler(w, err)
			return
		}
		handler.ServeHTTP(w, r)
	}
}

// HandleFunc 验证请求, 成功后调用handler(w,r)
func (m *Middleware) HandleFunc(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := m.ValidRequest(r); err != nil {
			m.errorHandler(w, err)
			return
		}
		handler(w, r)
	}
}

// ValidRequest 校验请求的签名是否有效
func (m *Middleware) ValidRequest(r *http.Request) error {
	ak := r.Header.Get(request.HeaderAccessKey)
	if ak == "" {
		return &core.Error{Message: request.AccessKeyEmpty}
	}
	sk := m.keyFn(ak)
	if sk == "" {
		return &core.Error{Message: request.SecretKeyEmpty}
	}
	ts := r.Header.Get(request.HeaderTimestamp)
	if err := m.auth.ParseTimestamp(ts); err != nil {
		return err
	}
	signature := r.Header.Get(request.HeaderSignature)
	if signature == "" {
		return &core.Error{Message: request.SignatueEmpty}
	}
	bodyhash := r.Header.Get(request.HeaderBodyHash)
	randomstr := r.Header.Get(request.HeaderRandomStr)
	if err := m.auth.ValidSignature(sk, signature, ak, ts, randomstr, bodyhash); err != nil {
		return err
	}
	if m.skipBody {
		return nil
	}
	b, err := request.ReadBody(r)
	if err != nil {
		return err
	}
	return m.auth.ValidBody(b, bodyhash)
}
