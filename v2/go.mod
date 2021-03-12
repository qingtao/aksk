module github.com/qingtao/aksk/v2

go 1.16

require github.com/stretchr/testify v1.7.0

retract (
	// 文档描述有拼写错误
	v2.0.1
	// 不符合实现目的
	v2.0.0
)
