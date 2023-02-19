module github.com/qingtao/aksk/v2

go 1.19

require github.com/stretchr/testify v1.7.1

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

retract (
	// 文档描述有拼写错误
	v2.0.1
	// 不符合实现目的
	v2.0.0
)
