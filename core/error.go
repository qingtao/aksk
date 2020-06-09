package core

import (
	"strings"
)

const (
	// timestampExpired 时间戳过期
	timestampExpired = "timestamp expired"
	// timestampInvalid 时间戳无效
	timestampInvalid = "invalid timestamp"
	// timestampEmpty 缺少时间戳
	timestampEmpty = "timestamp is empty"
	// signatureInvalid 请求签名无效
	signatureInvalid = "invalid signature"
	// bodyInvalid 请求内容无效
	bodyInvalid = "invalid body"
	// bodyHashEmpty 缺少内容散列值
	bodyHashEmpty = "the hash of body is empty"
)

// Error aksk的错误定义
type Error struct {
	// 错误消息
	Message string `json:"message"`
	// 内部错误
	err error
}

// NewError 新的错误
func NewError(msg string, err error) *Error {
	return &Error{Message: msg, err: err}
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	var buf strings.Builder
	if e.Message != "" {
		buf.WriteString(e.Message)
	}
	if e.err != nil {
		buf.WriteString(": ")
		buf.WriteString(e.err.Error())
	}
	return buf.String()
}

func (e *Error) Unwrap() error { return e.err }
