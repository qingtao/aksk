// Package request 包含http请求的头部常量和构造函数
package request

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/qingtao/aksk/v2/core"
)

const (
	// HeaderAccessKey accesskey
	HeaderAccessKey = `x-auth-access-key`
	// HeaderTimestamp 访问时间戳, 有效期由可接受时间误差(acceptableSkew, 默认±60秒)控制
	HeaderTimestamp = `x-auth-timestamp`
	// HeaderSignature 签名,值取决于签名方法和编码规则
	HeaderSignature = `x-auth-signature`
	// HeaderNonce 随机字符串, 用于防重放攻击
	HeaderNonce = `x-auth-nonce`
)

// Modifier 接口实现修改请求
type Modifier interface {
	// 修改请求,添加aksk的头部信息到*http.Request
	ModifyRequest(req *http.Request) error
}

// ModifierFunc 一个修改请求,附加aksk的签名头部的函数
type ModifierFunc func(req *http.Request) error

// ModifyRequest 附加aksk的签名头部的函数类型
func (f ModifierFunc) ModifyRequest(req *http.Request) error {
	return f(req)
}

// Config 配置
type Config struct {
	Ak        string
	Sk        string
	KeyGetter core.KeyGetter

	NonceStore NonceStore
	// AcceptableSkew 请求时间戳可接受的时间误差; 大于 0 时自动注入 core.WithAcceptableSkew,
	// 并同步给 MemoryStore 的 TTL, 使 nonce 防重放窗口与时间戳有效窗口保持一致
	AcceptableSkew time.Duration
}

func defaultConfig() Config {
	return Config{}
}

func (a Config) merge(b Config) Config {
	if b.Ak != "" {
		a.Ak = b.Ak
	}
	if b.Sk != "" {
		a.Sk = b.Sk
	}
	if b.KeyGetter != nil {
		a.KeyGetter = b.KeyGetter
	}
	if b.NonceStore != nil {
		a.NonceStore = b.NonceStore
	}
	if b.AcceptableSkew > 0 {
		a.AcceptableSkew = b.AcceptableSkew
	}
	return a
}

// NewModifierFunc 创建新的修改请求的函数
// 对于HMAC签名：sk是secretKey
// 对于非对称签名：sk是PEM格式的私钥
func NewModifierFunc(ak, sk string, coreOpts ...core.OptionFunc) (ModifierFunc, error) {
	cfg := Config{
		Ak: ak,
		Sk: sk,
	}
	return NewModifier(cfg, coreOpts...)
}

// withAcceptableSkew 若配置了 AcceptableSkew, 则注入 core 选项(等价 WithAcceptableSkew),
// 并同步给 MemoryStore 的 TTL, 保证 nonce 防重放窗口与时间戳有效窗口一致
func withAcceptableSkew(opts []core.OptionFunc, cfg Config) []core.OptionFunc {
	if cfg.AcceptableSkew <= 0 {
		return opts
	}
	if ms, ok := cfg.NonceStore.(*MemoryStore); ok {
		ms.SetTTL(cfg.AcceptableSkew)
	}
	return append(opts, core.WithAcceptableSkew(cfg.AcceptableSkew))
}

// NewModifier 创建支持nonce的修改请求函数
// nonceStore 为 nil 时禁用 nonce
func NewModifier(config Config, coreOpts ...core.OptionFunc) (ModifierFunc, error) {
	cfg := defaultConfig().merge(config)
	if cfg.Ak == "" {
		return nil, errors.New("access key is empty")
	}
	if cfg.Sk == "" {
		return nil, errors.New("secret key is empty")
	}
	coreOpts = withAcceptableSkew(coreOpts, cfg)
	a, err := core.New(coreOpts...)
	if err != nil {
		return nil, err
	}

	modifier := func(req *http.Request) error {
		// 添加ak头部
		req.Header.Set(HeaderAccessKey, cfg.Ak)
		// 添加时间戳头部
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		req.Header.Set(HeaderTimestamp, ts)

		// 生成并添加nonce（如果启用）
		var nonce string
		if cfg.NonceStore != nil {
			nonce, err = cfg.NonceStore.GenerateNonce()
			if err != nil {
				return fmt.Errorf("generate nonce error: %w", err)
			}
			req.Header.Set(HeaderNonce, nonce)
		}

		// 统一签名（根据 Auth 的 signMethod 自动选择 HMAC 或非对称签名）
		// sk 是签名的密钥, ak 是签名数据, ts 是签名时间戳, nonce 是随机字符串
		signature, err := a.Sign(cfg.Sk, cfg.Ak, ts, nonce)
		if err != nil {
			return err
		}
		req.Header.Set(HeaderSignature, signature)
		return nil
	}
	return modifier, nil
}

// Validator 验证器
type Validator interface {
	// 验证请求的aksk头部签名,验证失败返回非空错误
	Validate(req *http.Request) error
}

// ValidatorFunc 验证器函数
type ValidatorFunc func(req *http.Request) error

// Validate 通过aksk签名验证请求
func (f ValidatorFunc) Validate(req *http.Request) error {
	return f(req)
}

// NewValidatorFunc 创键aksk的验证器
func NewValidatorFunc(getter core.KeyGetter, coreOpts ...core.OptionFunc) (ValidatorFunc, error) {
	cfg := Config{
		KeyGetter: getter,
	}
	return NewValidator(cfg, coreOpts...)
}

// NewValidator 创建支持nonce的验证器
// nonceStore 为 nil 时禁用 nonce 验证
func NewValidator(config Config, coreOpts ...core.OptionFunc) (ValidatorFunc, error) {
	cfg := defaultConfig().merge(config)
	if cfg.KeyGetter == nil {
		return nil, errors.New("key getter is nil")
	}
	coreOpts = withAcceptableSkew(coreOpts, cfg)
	a, err := core.New(coreOpts...)
	if err != nil {
		return nil, err
	}

	validator := func(req *http.Request) error {
		ak := req.Header.Get(HeaderAccessKey)
		if ak == "" {
			return errors.New("access key is empty")
		}
		sk, err := cfg.KeyGetter(ak)
		if err != nil {
			// 处理密钥错误，如果是需要清除缓存的错误则清除
			a.HandleKeyError(ak, err)
			return fmt.Errorf("getter key error %w", err)
		}
		if sk == "" {
			return errors.New("access key is invalid")
		}
		ts := req.Header.Get(HeaderTimestamp)
		if err := a.ParseTimestamp(ts); err != nil {
			return err
		}
		signature := req.Header.Get(HeaderSignature)
		if signature == "" {
			return errors.New("signature is empty")
		}

		// 取出 nonce 用于签名验证（若启用 nonce）
		var nonce string
		if cfg.NonceStore != nil {
			nonce = req.Header.Get(HeaderNonce)
		}

		// 先验证签名（根据 Auth 的 signMethod 自动选择验证方式）
		// 第一个 ak 是密钥标识, sk 是密钥, 第二个 ak 是签名数据,
		// ts 是签名时间戳, nonce 是随机字符串(参与签名)
		if err := a.Verify(ak, sk, signature, ak, ts, nonce); err != nil {
			return err
		}

		// 签名通过后再校验 nonce: 避免未授权请求在未验证签名前占用 nonce 缓存,
		// 也避免客户端首次签名错误时误占用 nonce 导致正常重试被拒
		if cfg.NonceStore != nil {
			if err := cfg.NonceStore.Check(ak, nonce); err != nil {
				return err
			}
		}

		return nil
	}
	return validator, nil
}
