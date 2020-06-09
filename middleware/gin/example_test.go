package gin_test

import (
	"crypto/sha1"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/qingtao/aksk/core"
	aksk "github.com/qingtao/aksk/middleware/gin"
)

func getSecretKey(ak string) string {
	// TODO: get secret_key
	return ""
}

func handleError(c *gin.Context, err error) {
	if err == nil {
		return
	}
	var e *core.Error
	if !errors.As(err, &e) {
		e = &core.Error{Message: err.Error()}
	}
	c.JSON(http.StatusUnauthorized, e)
}

func hello(c *gin.Context) {
	c.String(http.StatusOK, "hello world!")
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
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	auth := engine.Group("auth", middleware)
	auth.Any("/hello", hello)
	if err := engine.Run(":8080"); err != nil {
		log.Fatalln(err)
	}
}
