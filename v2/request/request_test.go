package request

import (
	"bytes"
	"context"
	"crypto/sha1"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/qingtao/aksk/v2/core"
)

// goodRequest 正常的请求
func goodRequest() *http.Request {
	requestFunc, _ := NewHandlerFunc("123", "456", false)
	r, _ := requestFunc(context.TODO(), "POST", httptest.DefaultRemoteAddr, bytes.NewReader([]byte(`helloworld`)))
	return r
}

// invalidAkRequest 错误的Ak
func invalidAkRequest() *http.Request {
	requestFunc, _ := NewHandlerFunc("123", "456", false)
	r, _ := requestFunc(context.TODO(), "POST", httptest.DefaultRemoteAddr, bytes.NewReader([]byte(`helloworld`)))
	r.Header.Set(HeaderAccessKey, "")
	return r
}

// invalidSkRequest 错误的Sk
func invalidSkRequest() *http.Request {
	requestFunc, _ := NewHandlerFunc("wantEmpty", "456", false)
	r, _ := requestFunc(context.TODO(), "POST", httptest.DefaultRemoteAddr, bytes.NewReader([]byte(`helloworld`)))
	return r
}

// invalidTsRequest 错误的时间戳
func invalidTsRequest() *http.Request {
	requestFunc, _ := NewHandlerFunc("123", "456", false)
	r, _ := requestFunc(context.TODO(), "POST", httptest.DefaultRemoteAddr, bytes.NewReader([]byte(`helloworld`)))
	r.Header.Set(HeaderTimestamp, "150a0")
	return r
}

// invalidRequestSignIsEmpty 没有签名
func invalidRequestSignIsEmpty() *http.Request {
	requestFunc, _ := NewHandlerFunc("123", "456", false)
	r, _ := requestFunc(context.TODO(), "POST", httptest.DefaultRemoteAddr, bytes.NewReader([]byte(`helloworld`)))
	r.Header.Set(HeaderSignature, "")
	return r
}

// invalidRequestSign 签名错误
func invalidRequestSign() *http.Request {
	requestFunc, _ := NewHandlerFunc("123", "456", false)
	r, _ := requestFunc(context.TODO(), "POST", httptest.DefaultRemoteAddr, bytes.NewReader([]byte(`helloworld`)))
	r.Header.Set(HeaderSignature, "936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af")
	return r
}

func TestNewHandlerFunc(t *testing.T) {
	type args struct {
		ak       string
		sk       string
		url      string
		skipBody bool
		opts     []core.Option
	}
	tests := []struct {
		name     string
		args     args
		wantErr  bool
		wantErr2 bool
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
			wantErr:  false,
			wantErr2: false,
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
			wantErr:  false,
			wantErr2: false,
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
			wantErr:  true,
			wantErr2: false,
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
			wantErr:  true,
			wantErr2: false,
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
			wantErr:  false,
			wantErr2: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewHandlerFunc(tt.args.ak, tt.args.sk, tt.args.skipBody, tt.args.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewHandlerFunc() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got == nil {
				return
			}
			req, err := got(context.TODO(), "POST", tt.args.url, bytes.NewReader([]byte(`{"msg":"helloworld!"}`)))
			if (err != nil) != tt.wantErr2 {
				t.Errorf("create request failed %s", err)
				return
			}
			if req != nil {
				for k, v := range req.Header {
					t.Logf("%s: %+v", k, v)
				}
				b, err := ioutil.ReadAll(req.Body)
				if err != nil {
					t.Errorf("ioutil.ReadAll %s", err)
					return
				}
				t.Logf("body: %s", b)
			}
		})

	}
}

func TestValidate(t *testing.T) {
	f := func(ak string) string {
		if ak == "wantEmpty" {
			return ""
		}
		return "456"
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
				f:   f,
				a:   core.New(),
			},
			wantErr: false,
		},
		{
			name: "GoodSkipBody",
			args: args{
				req:      goodRequest(),
				f:        f,
				a:        core.New(),
				skipBody: true,
			},
			wantErr: false,
		},
		{
			name: "FailedAk",
			args: args{
				req: invalidAkRequest(),
				f:   f,
				a:   core.New(),
			},
			wantErr: true,
		},
		{
			name: "FailedSk",
			args: args{
				req: invalidSkRequest(),
				f:   f,
				a:   core.New(),
			},
			wantErr: true,
		},
		{
			name: "FailedTs",
			args: args{
				req: invalidTsRequest(),
				f:   f,
				a:   core.New(),
			},
			wantErr: true,
		},
		{
			name: "FailedSignIsEmpty",
			args: args{
				req: invalidRequestSignIsEmpty(),
				f:   f,
				a:   core.New(),
			},
			wantErr: true,
		},
		{
			name: "FailedSign",
			args: args{
				req: invalidRequestSign(),
				f:   f,
				a:   core.New(),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := Validate(tt.args.req, tt.args.a, tt.args.f, tt.args.skipBody); (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
