// Package aksk 实现http的中间件, 用于认证客户端请求和校验请求内容
package aksk

import (
	"github.com/gin-gonic/gin"
	"github.com/qingtao/aksk/core"
	aksk_gin "github.com/qingtao/aksk/middleware/gin"
	aksk_http "github.com/qingtao/aksk/middleware/http"
)

// HTTPMiddleware http中间件
type HTTPMiddleware = aksk_http.Middleware

// HTTPErrorHandler http中间件的错误处理函数
type HTTPErrorHandler = aksk_http.ErrorHandler

// DefaultHTTPMiddleware 新的http中间件
func DefaultHTTPMiddleware(fn core.KeyFunc, errHandler HTTPErrorHandler) *HTTPMiddleware {
	return aksk_http.New(aksk_http.Config{Key: fn, ErrorHandler: errHandler})
}

// GinErrorHandler gin中间件的错误处理函数
type GinErrorHandler = aksk_gin.ErrorHandler

// DefaultGinMiddleware 新的gin中间件
func DefaultGinMiddleware(fn core.KeyFunc, errHandler GinErrorHandler) gin.HandlerFunc {
	return aksk_gin.New(aksk_gin.Config{Key: fn, ErrorHandler: errHandler})
}
