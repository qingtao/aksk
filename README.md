# aksk 实现http的中间件, 用于认证客户端请求和校验请求内容

[![PkgGoDev](https://pkg.go.dev/badge/github.com/qingtao/aksk)](https://pkg.go.dev/github.com/qingtao/aksk)

## HTTP 头部

| 名称              | 说明                        |
| ----------------- | --------------------------- |
| x-auth-access-key | 客户端的访问密钥            |
| x-auth-timestamp  | 请求发起时的时间戳,单位: 秒 |
| x-auth-signature  | 请求的签名                  |
| x-auth-body-hash  | 请求的 Body 的 Hash 值      |
| x-auth-random-str | 随机字符串                  |

## 签名方法

1. 假设哈希算法为`SHA256`, 编码格式为`BASE64`;
2. 取出客户端访问密钥: `x-auth-access-key`;
3. 取当前的时间戳: `x-auth-timestamp`;
4. 生成随机字符串: `x-auth-random-str`;
5. 如果请求的`BODY`非空, 对`BODY`计算`SHA256`的值, 并编码为`BASE64`得到:`x-auth-body-hash`;
6. 将 `x-auth-accesskey`,`x-auth-timestamp`,`x-auth-random-str`,`x-auth-body-hash` 按照字典序排序, 拼接成字符串`s`;
7. 取出客户端访问密钥对应的`secre_tkey`, 对`s`计算`HMACSHA256`的值, 并编码为`BASE64`, 得到 `x-auth-signature`;
