package request

import (
	"bytes"
	"context"
	"crypto/sha1"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/qingtao/aksk/v2/core"
)

// goodRequest 正常的请求
func goodRequest() *http.Request {
	modifier, _ := NewModifierFunc("123", "456", false)
	r, _ := http.NewRequestWithContext(context.TODO(), "POST", httptest.DefaultRemoteAddr, bytes.NewReader([]byte(`helloworld`)))
	modifier(r)
	return r
}

// invalidAkRequest 错误的Ak
func invalidAkRequest() *http.Request {
	modifier, _ := NewModifierFunc("123", "456", false)
	r, _ := http.NewRequestWithContext(context.TODO(), "POST", httptest.DefaultRemoteAddr, bytes.NewReader([]byte(`helloworld`)))
	modifier(r)
	r.Header.Set(HeaderAccessKey, "")
	return r
}

// invalidSkRequest 错误的Sk
func invalidSkRequest() *http.Request {
	modifier, _ := NewModifierFunc("wantEmpty", "456", false)
	r, _ := http.NewRequestWithContext(context.TODO(), "POST", httptest.DefaultRemoteAddr, bytes.NewReader([]byte(`helloworld`)))
	modifier(r)
	return r
}

// invalidTsRequest 错误的时间戳
func invalidTsRequest() *http.Request {
	modifier, _ := NewModifierFunc("123", "456", false)
	r, _ := http.NewRequestWithContext(context.TODO(), "POST", httptest.DefaultRemoteAddr, bytes.NewReader([]byte(`helloworld`)))
	modifier(r)
	r.Header.Set(HeaderTimestamp, "150a0")
	return r
}

// invalidRequestSignIsEmpty 没有签名
func invalidRequestSignIsEmpty() *http.Request {
	modifier, _ := NewModifierFunc("123", "456", false)
	r, _ := http.NewRequestWithContext(context.TODO(), "POST", httptest.DefaultRemoteAddr, bytes.NewReader([]byte(`helloworld`)))
	modifier(r)
	r.Header.Set(HeaderSignature, "")
	return r
}

// invalidRequestSign 签名错误
func invalidRequestSign() *http.Request {
	modifier, _ := NewModifierFunc("123", "456", false)
	r, _ := http.NewRequestWithContext(context.TODO(), "POST", httptest.DefaultRemoteAddr, bytes.NewReader([]byte(`helloworld`)))
	modifier(r)
	r.Header.Set(HeaderSignature, "936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af")
	return r
}

func TestNewValidatorFunc(t *testing.T) {
	getKey := func(ak string) (string, error) {
		if ak == "wantEmpty" {
			return "", nil
		}
		return "456", nil
	}
	type args struct {
		req      *http.Request
		a        *core.Auth
		f        core.KeyGetter
		skipBody bool
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Good",
			args: args{
				req: goodRequest(),
				f:   getKey,
				a:   core.New(),
			},
			wantErr: false,
		},
		{
			name: "GetterIsNil",
			args: args{
				req: goodRequest(),
				f:   nil,
				a:   core.New(),
			},
			wantErr: true,
		},
		{
			name: "GoodSkipBody",
			args: args{
				req:      goodRequest(),
				f:        getKey,
				a:        core.New(),
				skipBody: true,
			},
			wantErr: false,
		},
		{
			name: "FailedAk",
			args: args{
				req: invalidAkRequest(),
				f:   getKey,
				a:   core.New(),
			},
			wantErr: true,
		},
		{
			name: "FailedSk",
			args: args{
				req: invalidSkRequest(),
				f:   getKey,
				a:   core.New(),
			},
			wantErr: true,
		},
		{
			name: "FailedTs",
			args: args{
				req: invalidTsRequest(),
				f:   getKey,
				a:   core.New(),
			},
			wantErr: true,
		},
		{
			name: "FailedSignIsEmpty",
			args: args{
				req: invalidRequestSignIsEmpty(),
				f:   getKey,
				a:   core.New(),
			},
			wantErr: true,
		},
		{
			name: "FailedSign",
			args: args{
				req: invalidRequestSign(),
				f:   getKey,
				a:   core.New(),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator, err := NewValidatorFunc(tt.args.f, tt.args.skipBody)
			if err != nil {
				if tt.wantErr {
					t.Logf("NewValidatorFunc error = %v", err)
					return
				}
				t.Errorf("NewValidatorFunc error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			var f Validator = validator
			if err = f.Validate(tt.args.req); err != nil {
				if tt.wantErr {
					t.Logf("validator.Validate error = %v", err)
					return
				}
				t.Errorf("validator.Validate error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewModifierFunc(t *testing.T) {
	getKey := func(ak, sk string) func(ak string) (string, error) {
		return func(ak string) (string, error) {
			if ak == "wantErr" {
				return "", errors.New(ak)
			}
			return sk, nil
		}
	}
	type args struct {
		ak       string
		sk       string
		skipBody bool
		url      string
		opts     []core.Option
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Ok",
			args: args{
				ak:  "123",
				sk:  "456",
				url: httptest.DefaultRemoteAddr,
				opts: []core.Option{
					core.WithEncoder(&core.Base64Encoder{}),
					core.WithHash(sha1.New),
				},
			},
			wantErr: false,
		},
		{
			name: "OkSkipBody",
			args: args{
				ak:       "123",
				sk:       "456",
				url:      httptest.DefaultRemoteAddr,
				skipBody: true,
				opts: []core.Option{
					core.WithEncoder(&core.Base64Encoder{}),
					core.WithHash(sha1.New),
				},
			},
			wantErr: false,
		},
		{
			name: "KeyGetterError",
			args: args{
				ak:  "wantErr",
				sk:  "456",
				url: httptest.DefaultRemoteAddr,
				opts: []core.Option{
					core.WithEncoder(&core.Base64Encoder{}),
					core.WithHash(sha1.New),
				},
			},
			wantErr: true,
		},
		{
			name: "FailedAK",
			args: args{
				ak:  "",
				sk:  "456",
				url: httptest.DefaultRemoteAddr,
				opts: []core.Option{
					core.WithEncoder(&core.Base64Encoder{}),
					core.WithHash(sha1.New),
				},
			},
			wantErr: true,
		},
		{
			name: "FailedSK",
			args: args{
				ak:  "123",
				sk:  "",
				url: httptest.DefaultRemoteAddr,
				opts: []core.Option{
					core.WithEncoder(&core.Base64Encoder{}),
					core.WithHash(sha1.New),
				},
			},
			wantErr: true,
		},
		{
			name: "FailedNewRequest",
			args: args{
				ak:  "123",
				sk:  "456",
				url: "tcp:// ",
				opts: []core.Option{
					core.WithEncoder(&core.Base64Encoder{}),
					core.WithHash(sha1.New),
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			modifier, err := NewModifierFunc(tt.args.ak, tt.args.sk, tt.args.skipBody, tt.args.opts...)
			if err != nil {
				if tt.wantErr {
					t.Logf("NewModifierFunc error = %v", err)
					return
				}
				t.Errorf("NewModifierFunc error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			req, err := http.NewRequestWithContext(context.TODO(), http.MethodPost, tt.args.url, strings.NewReader("hello,world!"))
			if err != nil {
				if tt.wantErr {
					t.Logf("http.NewRequestWithContext error = %v", err)
					return
				}
				t.Errorf("http.NewRequestWithContext error %v, wantErr %v", err, tt.wantErr)
				return
			}
			var f Modifier = modifier
			if err := f.ModifyRequest(req); err != nil {
				if tt.wantErr {
					t.Logf("modifier.ModifyRequest error %v", err)
					return
				}
				t.Errorf("modifier.ModifyRequest error %v, wantErr %v", err, tt.wantErr)
			}
			t.Logf("%s: %s", HeaderAccessKey, req.Header.Get(HeaderAccessKey))
			t.Logf("%s: %s", HeaderRandomStr, req.Header.Get(HeaderRandomStr))
			t.Logf("%s: %s", HeaderTimestamp, req.Header.Get(HeaderTimestamp))
			t.Logf("%s: %s", HeaderBodyHash, req.Header.Get(HeaderBodyHash))
			t.Logf("%s: %s", HeaderSignature, req.Header.Get(HeaderSignature))

			validator, err := NewValidatorFunc(getKey(tt.args.ak, tt.args.sk), tt.args.skipBody, tt.args.opts...)
			if err != nil {
				t.Errorf("NewValidatorFunc error %v", err)
				return
			}
			if err := validator.Validate(req); err != nil {
				if tt.wantErr {
					t.Logf("validator.Validate error %v", err)
					return
				}
				t.Errorf("validator.Validate error %v", err)
			}
		})
	}
}
