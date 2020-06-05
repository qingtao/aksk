package ginaksk

import (
	"bytes"
	"errors"
	"io/ioutil"
	"net/http"

	"github.com/antlinker/aksk/core"
	"github.com/antlinker/aksk/request"
	"github.com/gin-gonic/gin"
)

// ErrorHandler 错误处理函数
type ErrorHandler func(c *gin.Context, err error)

func handleError(c *gin.Context, err error) {
	if err == nil {
		return
	}
	var e *core.Error
	if errors.As(err, &e) {
		c.AbortWithStatusJSON(http.StatusUnauthorized, e)
		return
	}
	c.AbortWithError(http.StatusUnauthorized, err)
}

// Validate 返回一个验证请求的gin中间件, keyFn指定了查询SecretKey的函数,如果等于nil,将panic; 如果skipBody为true, 跳过检查body的hash值是否一致; fn不为nil时,使用自定义的错误处理函数

// Config 配置
type Config struct {
	KeyFn        core.KeyFunc
	SkipBody     bool
	ErrorHandler ErrorHandler
}

// New 创建中间件
func New(cfg Config, opts ...core.Options) gin.HandlerFunc {
	if cfg.KeyFn == nil {
		panic("keyFn is nil")
	}
	fn := cfg.ErrorHandler
	if fn == nil {
		cfg.ErrorHandler = handleError
	}
	auth := core.New(opts...)
	return func(c *gin.Context) {
		if err := validRequest(c, auth, cfg.KeyFn, cfg.SkipBody); err != nil {
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
	ts := c.GetHeader(request.HeaderTimestramp)
	if err := auth.ParseTimestramp(ts); err != nil {
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
	b, err := readBody(c)
	if err != nil {
		return err
	}
	return auth.ValidBody(b, bodyhash)
}

// readBody 读取body
func readBody(c *gin.Context) ([]byte, error) {
	b, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		return nil, &core.Error{Message: "读取Body发生错误", Err: err}
	}
	c.Request.Body = ioutil.NopCloser(bytes.NewReader(b))

	return bytes.TrimSpace(b), nil
}
