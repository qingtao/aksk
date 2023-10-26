# aksk 实现 http 的中间件, 用于认证客户端请求和校验请求内容

[![PkgGoDev](https://pkg.go.dev/badge/github.com/qingtao/aksk/v2)](https://pkg.go.dev/github.com/qingtao/aksk/v2)

## HTTP 头部

| 名称              | 说明                        |
| ----------------- | --------------------------- |
| x-auth-access-key | 客户端的访问密钥            |
| x-auth-timestamp  | 请求发起时的时间戳,单位: 秒 |
| x-auth-signature  | 请求的签名                  |
| x-auth-body-hash  | 请求的 body 的 hash 值      |

## 签名方法

1. 假设哈希算法为`sha256`, 编码格式为`base64`;
2. 取出客户端访问密钥: `x-auth-access-key`;
3. 取当前的时间戳: `x-auth-timestamp`;
4. 如果请求的`body`非空, 对`body`计算`sha256`的值, 并编码为`base64`得到:`x-auth-body-hash`;
5. 将 `x-auth-access-key`,`x-auth-timestamp`,`x-auth-body-hash` 按字符串排序, 使用空字符作为分隔符拼接成字符串`s`;
6. 取出客户端访问密钥对应的`secret_key`, 对`s`计算`hmac_sha256`的值, 并编码为`base64`, 得到 `x-auth-signature`;
