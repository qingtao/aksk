package gin

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/qingtao/aksk/core"
	"github.com/qingtao/aksk/request"
)

// ErrorHandler 错误处理函数
type ErrorHandler func(c *gin.Context, err error)

func defaultErrorHandler(c *gin.Context, err error) {
	if err == nil {
		return
	}
	e := &core.Error{Message: err.Error()}
	c.AbortWithStatusJSON(http.StatusUnauthorized, e)
}

// Validate 返回一个验证请求的gin中间件, key指定了查询SecretKey的函数,如果等于nil,将panic; 如果skipBody为true, 跳过检查body的hash值是否一致; fn不为nil时,使用自定义的错误处理函数

// Config 配置
type Config struct {
	Key          core.KeyFunc
	SkipBody     bool
	ErrorHandler ErrorHandler

	auth *core.Auth
}

// New 创建中间件
func New(cfg Config, opts ...core.Options) gin.HandlerFunc {
	if cfg.Key == nil {
		panic("Config.Key is nil")
	}
	fn := cfg.ErrorHandler
	if fn == nil {
		fn = defaultErrorHandler
	}
	auth := core.New(opts...)
	return func(c *gin.Context) {
		if err := validRequest(c, auth, cfg.Key, cfg.SkipBody); err != nil {
			fn(c, err)
			if !c.IsAborted() {
				c.Abort()
			}
		}
	}
}

func validRequest(c *gin.Context, auth *core.Auth, keyFn core.KeyFunc, skipBody bool) error {
	ak := c.GetHeader(request.HeaderAccessKey)
	if ak == "" {
		return &core.Error{Message: request.AccessKeyEmpty}
	}
	sk := keyFn(ak)
	if sk == "" {
		return &core.Error{Message: request.SecretKeyEmpty}
	}
	ts := c.GetHeader(request.HeaderTimestamp)
	if err := auth.ParseTimestamp(ts); err != nil {
		return err
	}
	signature := c.GetHeader(request.HeaderSignature)
	if signature == "" {
		return &core.Error{Message: request.SignatueEmpty}
	}
	bodyhash := c.GetHeader(request.HeaderBodyHash)
	randomstr := c.GetHeader(request.HeaderRandomStr)
	if err := auth.ValidSignature(sk, signature, ak, ts, randomstr, bodyhash); err != nil {
		return err
	}
	if skipBody {
		return nil
	}
	b, err := request.ReadBody(c.Request)
	if err != nil {
		return err
	}
	return auth.ValidBody(b, bodyhash)
}
