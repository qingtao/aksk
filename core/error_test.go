package core

import (
	"errors"
	"testing"
)

func TestError_Error(t *testing.T) {
	type fields struct {
		err *Error
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "Ok",
			fields: fields{
				err: &Error{
					Message: "验证失败",
					Err:     nil,
				},
			},
			want: "验证失败",
		},
		{
			name: "Ok",
			fields: fields{
				err: nil,
			},
			want: "<nil>",
		},
		{
			name: "Ok",
			fields: fields{
				err: &Error{
					Message: "验证失败",
					Err:     errors.New("未找到密钥"),
				},
			},
			want: "验证失败: 未找到密钥",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.fields.err.Error(); got != tt.want {
				t.Errorf("Error.Error() = %v, want %v", got, tt.want)
			}
			if tt.fields.err != nil {
				t.Logf("%+v", errors.Unwrap(tt.fields.err))
			}
		})
	}
}
