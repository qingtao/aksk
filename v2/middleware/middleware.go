// Package middleware aksk认证中间件
package middleware

import (
	"fmt"
	"net/http"

	"github.com/qingtao/aksk/v2/core"
	"github.com/qingtao/aksk/v2/request"
)

// ErrorHandler 错误处理函数, 接收错误处理后, 不再执行后续操作
type ErrorHandler func(w http.ResponseWriter, err error)

func defaultErrorHandler(w http.ResponseWriter, err error) {
	if err == nil {
		return
	}
	w.WriteHeader(http.StatusUnauthorized)
	fmt.Fprintf(w, "%s", err)
}

// Middleware 中间件
type Middleware struct {
	Validator    request.Validator
	errorHandler ErrorHandler
}

// Config 配置
type Config struct {
	// 可以以ak为参数查询sk
	KeyGetter    core.KeyGetter
	SkipBody     bool
	ErrorHandler ErrorHandler
}

// New 新建一个中间件
func New(cfg Config, opts ...core.Option) *Middleware {
	if cfg.KeyGetter == nil {
		panic("Config.Key is nil")
	}
	validator, err := request.NewValidatorFunc(cfg.KeyGetter, cfg.SkipBody, opts...)
	if err != nil {
		panic(err)
	}
	middleware := &Middleware{
		Validator:    validator,
		errorHandler: cfg.ErrorHandler,
	}
	if middleware.errorHandler == nil {
		middleware.errorHandler = defaultErrorHandler
	}
	return middleware
}

// Handle 验证请求, 成功后调用handler.ServeHTTP(w,r)
func (m *Middleware) Handle(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := m.Validator.Validate(r); err != nil {
			m.errorHandler(w, err)
			return
		}
		handler.ServeHTTP(w, r)
	})
}

// HandleFunc 验证请求, 成功后调用handler(w,r)
func (m *Middleware) HandleFunc(handler http.HandlerFunc) http.Handler {
	return m.Handle(http.Handler(handler))
}
