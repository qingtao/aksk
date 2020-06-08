# ginaksk 实现 gin 的中间件, 用于认证客户端请求和校验请求内容

[godoc](https://pkg.go.dev/github.com/antlinker/ginaksk?tab=doc)

## 编码格式

ginaksk 默认使用 encoding/hex 生成字符串，添加到 HTTP 请求的头部;
可以在使用 Validate 中间件之前，调用 SetEncoder 修改为其他编码格式，如示例中的 base64

## Hash 算法

ginaksk 默认使用 sha256.New 作为 hmac.New 的 hash.Hash 类型;
可以在使用 Validate 中间件之前，调用 SetHash 修改为其他算法，如 sha512.New

## HTTP 头部

| 名称              | 说明                        |
| ----------------- | --------------------------- |
| x-auth-access-key | 客户端的访问密钥            |
| x-auth-timestramp | 请求发起时的时间戳,单位: 秒 |
| x-auth-signature  | 请求的签名                  |
| x-auth-body-hash  | 请求的 Body 的 Hash 值      |
| x-auth-random-str | 随机字符串                  |

## 签名方法

1. 假设哈希算法为`SHA256`, 编码格式为`HEX`;
2. 取出客户端访问密钥: `x-auth-accesskey`;
3. 取当前的时间戳: `x-auth-timestramp`;
4. 生成随机字符串: `x-auth-random-str`;
5. 如果请求的`BODY`非空, 对`BODY`计算`SHA256`的值, 并编码为`HEX`得到:`x-auth-body-hash`;
6. 将 `x-auth-accesskey`,`x-auth-timestramp`,`x-auth-random-str`,`x-auth-body-hash` 按照字典序排序, 拼接成字符串`s`;
7. 取出客户端访问密钥对应的`secretkey`, 对`s`计算`HMACSHA256`的值, 并编码为`HEX`, 得到 `x-auth-signature`;
