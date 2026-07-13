# aksk 实现 HTTP 的中间件, 用于认证客户端请求和校验请求内容

[![PkgGoDev](https://pkg.go.dev/badge/github.com/qingtao/aksk/v2)](https://pkg.go.dev/github.com/qingtao/aksk/v2)

## HTTP 头部

| 名称              | 说明                        |
| ----------------- | --------------------------- |
| x-auth-access-key | 客户端的访问密钥            |
| x-auth-timestamp  | 请求发起时的时间戳, 单位: 秒 |
| x-auth-signature  | 请求的签名                  |
| x-auth-nonce      | 随机字符串, 用于防重放攻击  |

## 签名方法

> 注意: 各字段按字符串升序排序后, 以英文逗号 `,` 连接拼接成待签名字符串 `s`;
> 因此 access key 中**不得包含英文逗号 `,`**。

### 对称签名 (HMAC)

支持的签名算法:
- `HMAC-SHA256`: HMAC with SHA-256
- `HMAC-SHA384`: HMAC with SHA-384
- `HMAC-SHA512`: HMAC with SHA-512

1. 取出客户端访问密钥: `x-auth-access-key`;
2. 取当前的时间戳: `x-auth-timestamp`;
3. 取随机字符串: `x-auth-nonce` (可选);
4. 将 `x-auth-access-key`, `x-auth-timestamp`, `x-auth-nonce` 按字符串排序, 拼接成字符串 `s`（各字段按字符串升序排序后, 用英文逗号 `,` 连接）;
5. 取出客户端访问密钥对应的 secretKey, 对 `s` 使用指定的 HMAC 算法计算签名, 并编码为 base64, 得到 `x-auth-signature`;

### 非对称签名 (RSA/ECDSA/Ed25519)

支持的签名算法:
- `RSA-SHA256`: RSA with SHA-256
- `RSA-SHA384`: RSA with SHA-384
- `RSA-SHA512`: RSA with SHA-512
- `ECDSA-SHA256`: ECDSA with SHA-256
- `ECDSA-SHA384`: ECDSA with SHA-384
- `ECDSA-SHA512`: ECDSA with SHA-512
- `ED25519`: Ed25519

1. 取出客户端访问密钥: `x-auth-access-key`;
2. 取当前的时间戳: `x-auth-timestamp`;
3. 取随机字符串: `x-auth-nonce` (可选);
4. 将 `x-auth-access-key`, `x-auth-timestamp`, `x-auth-nonce` 按字符串排序, 拼接成字符串 `s`（各字段按字符串升序排序后, 用英文逗号 `,` 连接）;
5. 使用私钥对 `s` 进行签名, 并编码为 base64, 得到 `x-auth-signature`;

## 使用方法

### 客户端签名请求

```go
package main

import (
	"net/http"

	"github.com/qingtao/aksk/v2/core"
	"github.com/qingtao/aksk/v2/request"
)

func main() {
	// 创建签名修改器
	modifier, err := request.NewModifier(request.Config{
		Ak: "your-access-key",
		Sk: "your-secret-key",
	}, core.WithSignMethod(core.SignMethodHMACSHA256))
	if err != nil {
		panic(err)
	}

	// 创建请求
	req, _ := http.NewRequest("GET", "http://example.com/api", nil)

	// 添加签名头部
	if err := modifier.ModifyRequest(req); err != nil {
		panic(err)
	}

	// 发送请求
	resp, _ := http.DefaultClient.Do(req)
	defer resp.Body.Close()
}
```

### 服务端验证请求

```go
package main

import (
	"net/http"

	"github.com/qingtao/aksk/v2/core"
	"github.com/qingtao/aksk/v2/middleware"
)

func main() {
	config := middleware.Config{
		KeyGetter: func(ak string) (string, error) {
			// 根据 ak 查询 secret key
			return "your-secret-key", nil
		},
	}

	m, err := middleware.New(config,
		core.WithSignMethod(core.SignMethodHMACSHA256),
	)
	if err != nil {
		panic(err)
	}

	http.Handle("/api", m.HandleFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))

	http.ListenAndServe(":8080", nil)
}
```

### 启用 Nonce 防重放

```go
package main

import (
	"net/http"
	"time"

	"github.com/qingtao/aksk/v2/core"
	"github.com/qingtao/aksk/v2/request"
)

func main() {
	// 创建 NonceStore, 使用选项函数配置
	store := request.NewMemoryStore(
		request.WithMinLen(16),
		request.WithMaxLen(64),
		request.WithTTL(5*time.Minute),
	)

	// 客户端: 创建带 nonce 的签名修改器
	modifier, _ := request.NewModifier(request.Config{
		Ak:         "your-access-key",
		Sk:         "your-secret-key",
		NonceStore: store,
	}, core.WithSignMethod(core.SignMethodHMACSHA256))

	// 服务端: 创建带 nonce 校验的验证器
	validator, _ := request.NewValidator(request.Config{
		KeyGetter: func(ak string) (string, error) {
			return "your-secret-key", nil
		},
		NonceStore: store,
	}, core.WithSignMethod(core.SignMethodHMACSHA256))

	_ = modifier
	_ = validator
}
```

### Nonce 使用限制

`MemoryStore` 是基于进程内存 (`fastcache`) 的默认实现, 使用时有以下限制:

- **仅限单实例部署**: 各实例的 nonce 缓存相互独立, 服务横向扩展 (多副本) 后
  攻击者向不同副本重放即可绕过防重放。多实例场景请实现 `NonceStore` 接口,
  使用共享存储 (如 Redis) 保存 nonce。
- **防重放窗口受缓存容量影响**: `freecache` 按最大条目数上限 + LRU 淘汰, 过期由 TTL 主动清理。
  正常流量下 nonce 在 TTL 后自动失效; 但当写入达到上限时会淘汰最久未用条目,
  极端高负载下仍可能提前删除尚未过期的 nonce, 缩短防重放窗口。
  建议按流量规划 `CacheSize`, 使其足以容纳一个 TTL 周期内的请求量。
- **nonce TTL 须与 acceptableSkew 对齐**: 防重放窗口(ttl)必须不小于请求时间戳有效窗口(acceptableSkew), 否则会出现"时间戳仍有效但 nonce 已过期"的空窗, 可被重放。在 `request.Config` 中设置 `AcceptableSkew` 即可自动注入 `core.WithAcceptableSkew` 并同步给 `MemoryStore` 的 TTL, 无需手动对齐两者。

> 客户端重试请使用**新的 nonce**; 若复用同一 nonce, 在 TTL 内会被判定为 `nonce already used`。

### 自定义 NonceStore

实现 `NonceStore` 接口即可使用自定义存储 (如 Redis):

```go
type NonceStore interface {
	GenerateNonce() (string, error)
	Check(ak, nonce string) error
}
```

## 默认值

| 配置项          | 默认值   | 说明             |
| --------------- | -------- | ---------------- |
| MinLen          | 16       | nonce 最小长度   |
| MaxLen          | 64       | nonce 最大长度   |
| TTL             | 60 秒    | nonce 过期时间, 应与 acceptableSkew 保持一致 |
| CacheSize       | 1,048,576 | nonce 缓存最大条目数(硬上限, 防溢出) |
