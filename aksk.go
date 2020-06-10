// Package aksk 实现http的中间件, 用于认证客户端请求和校验请求内容
package aksk

import (
	"github.com/gin-gonic/gin"
	"github.com/qingtao/aksk/core"
	akskgin "github.com/qingtao/aksk/middleware/gin"
	akskhttp "github.com/qingtao/aksk/middleware/http"
)

// HTTPMiddleware http中间件
type HTTPMiddleware = akskhttp.Middleware

// HTTPErrorHandler http中间件的错误处理函数
type HTTPErrorHandler = akskhttp.ErrorHandler

// DefaultHTTPMiddleware 新的http中间件
func DefaultHTTPMiddleware(fn core.KeyFunc, errHandler HTTPErrorHandler) *HTTPMiddleware {
	return akskhttp.New(akskhttp.Config{Key: fn, ErrorHandler: errHandler})
}

// GinErrorHandler gin中间件的错误处理函数
type GinErrorHandler = akskgin.ErrorHandler

// DefaultGinMiddleware 新的gin中间件
func DefaultGinMiddleware(fn core.KeyFunc, errHandler GinErrorHandler) gin.HandlerFunc {
	return akskgin.New(akskgin.Config{Key: fn, ErrorHandler: errHandler})
}
