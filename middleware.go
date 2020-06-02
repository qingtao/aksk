package ginaksk

import (
	"bytes"
	"errors"
	"io/ioutil"
	"net/http"

	"github.com/antlinker/ginaksk/core"
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

// KeyFunc 查询accesskey,返回secretKey的函数
type KeyFunc func(accessKey string) (secretKey string)

// Validate 返回一个验证请求的gin中间件, keyFn指定了查询SecretKey的函数,如果等于nil,将panic; 如果skipBody为true, 跳过检查body的hash值是否一致; fn不为nil时,使用自定义的错误处理函数
func Validate(keyFn KeyFunc, skipBody bool, fn ErrorHandler, opts ...core.Options) gin.HandlerFunc {
	if keyFn == nil {
		panic("keyFn is nil")
	}
	if fn == nil {
		fn = handleError
	}
	auth := core.New(opts...)
	return func(c *gin.Context) {
		if err := validRequest(c, auth, keyFn, skipBody); err != nil {
			fn(c, err)
			if !c.IsAborted() {
				c.Abort()
			}
		}
	}
}

// signatueEmpty 请求签名为空
const signatueEmpty = "缺少签名"

func validRequest(c *gin.Context, auth *core.Auth, keyFn KeyFunc, skipBody bool) error {
	ak := c.GetHeader(core.HeaderAccessKey)
	if ak == "" {
		return &core.Error{Message: accessKeyEmpty}
	}
	sk := keyFn(ak)
	if sk == "" {
		return &core.Error{Message: secretKeyEmpty}
	}
	ts := c.GetHeader(core.HeaderTimestramp)
	if err := auth.ParseTimestramp(ts); err != nil {
		return err
	}
	signature := c.GetHeader(core.HeaderSignature)
	if signature == "" {
		return &core.Error{Message: signatueEmpty}
	}
	bodyhash := c.GetHeader(core.HeaderBodyHash)
	randomstr := c.GetHeader(core.HeaderRandomStr)
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
