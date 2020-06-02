package core

import "fmt"

const (
	// timestrampExpired 时间戳过期
	timestrampExpired = "时间戳过期"
	// timestrampInvalid 时间戳无效
	timestrampInvalid = "时间戳无效"
	// timestrampEmpty 缺少时间戳
	timestrampEmpty = "缺少时间戳"
	// signatureInvalid 请求签名无效
	signatureInvalid = "签名无效"
	// bodyInvalid 请求内容无效
	bodyInvalid = "内容无效"
	// bodyHashEmpty 缺少内容散列值
	bodyHashEmpty = "缺少内容散列值"
)

// Error aksk的错误定义
type Error struct {
	// 错误消息
	Message string `json:"message"`
	// 内部错误
	Err error `json:"error"`
}

func (e *Error) Error() string {
	if e == nil {
		return "nil"
	}
	if e.Message != "" {
		return fmt.Sprintf("%s: %s", e.Message, e.Err)
	}
	return e.Err.Error()
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func (e *Error) String() string {
	return e.Message
}
