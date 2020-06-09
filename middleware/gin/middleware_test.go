package gin

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/antlinker/aksk/core"
	"github.com/antlinker/aksk/request"
	"github.com/gin-gonic/gin"
)

func Test_defaultErrorHandler(t *testing.T) {
	type args struct {
		w   *httptest.ResponseRecorder
		err error
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Good",
			args: args{
				w:   httptest.NewRecorder(),
				err: nil,
			},
		},
		{
			name: "Good",
			args: args{
				w:   httptest.NewRecorder(),
				err: errors.New(`err`),
			},
		},
		{
			name: "Good",
			args: args{
				w:   httptest.NewRecorder(),
				err: core.NewError("core.Error", errors.New(`err`)),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gin.SetMode(gin.ReleaseMode)
			c, _ := gin.CreateTestContext(tt.args.w)
			defaultErrorHandler(c, tt.args.err)
			if tt.args.err != nil {
				t.Logf("%s", tt.args.w.Body.String())
			}
		})
	}
}

func getSecretKey(ak string) string {
	if ak == "wantEmpty" {
		return ""
	}
	return "456"
}

func Test_New(t *testing.T) {
	type args struct {
		w        *httptest.ResponseRecorder
		cfg      Config
		opts     core.Options
		keyFn    core.KeyFunc
		skipBody bool
	}
	tests := []struct {
		name      string
		args      args
		wantPanic bool
	}{
		{
			name: "Good",
			args: args{
				w:   httptest.NewRecorder(),
				cfg: Config{KeyFn: getSecretKey},
			},
			wantPanic: false,
		},
		{
			name: "KeyFnIsNil",
			args: args{
				w:   httptest.NewRecorder(),
				cfg: Config{},
			},
			wantPanic: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if err := recover(); err != nil {
					if !tt.wantPanic {
						t.Errorf("want no panic, but got %v", err)
					}
				}
			}()
			_ = createTestServer(tt.args.cfg, tt.args.opts, tt.args.w)

		})
	}
}

func createTestServer(cfg Config, opts core.Options, w http.ResponseWriter) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	middleware := New(cfg, opts)
	_, g := gin.CreateTestContext(w)
	g.Use(middleware)
	g.Any("/", func(c *gin.Context) {
		b, _ := c.GetRawData()
		c.String(http.StatusOK, "%s", b)
	})
	return g
}

func goodRequest() (*http.Request, string) {
	s := `helloworld!`
	requestFunc, _ := request.New("123", "456")
	r, _ := requestFunc(context.TODO(), "POST", "/", []byte(s))
	return r, s
}

func accessKeyIsEmpty() (*http.Request, string) {
	s := `helloworld!`
	r := httptest.NewRequest("POST", "/", strings.NewReader(s))
	return r, s
}

func secretKeyIsEmpty() (*http.Request, string) {
	s := `helloworld!`
	requestFunc, _ := request.New("wantEmpty", "456")
	r, _ := requestFunc(context.TODO(), "POST", "/", []byte(s))
	return r, s
}

func invalidTimestamp() (*http.Request, string) {
	s := `helloworld!`
	requestFunc, _ := request.New("123", "456")
	r, _ := requestFunc(context.TODO(), "POST", "/", []byte(s))
	r.Header.Set(request.HeaderTimestamp, `150a`)
	return r, s
}

func invalidSignatureIsEmpty() (*http.Request, string) {
	s := `helloworld!`
	requestFunc, _ := request.New("123", "456")
	r, _ := requestFunc(context.TODO(), "POST", "/", []byte(s))
	r.Header.Set(request.HeaderSignature, ``)
	return r, s
}

func invalidSignature() (*http.Request, string) {
	s := `helloworld!`
	requestFunc, _ := request.New("123", "456")
	r, _ := requestFunc(context.TODO(), "POST", "/", []byte(s))
	r.Header.Set(request.HeaderSignature, `MTIz`)
	return r, s
}

func testErrorHandler(c *gin.Context, err error) {
	if err == nil {
		return
	}
	var e *core.Error
	if errors.As(err, &e) {
		c.JSON(http.StatusUnauthorized, e)
		return
	}
	e = &core.Error{Message: err.Error()}
	c.JSON(http.StatusUnauthorized, e)
}

func TestValidRequest(t *testing.T) {
	type args struct {
		cfg  Config
		opts core.Options
		w    *httptest.ResponseRecorder
		r    func() (*http.Request, string)
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Good",
			args: args{
				cfg:  Config{KeyFn: getSecretKey},
				opts: core.Options{},
				w:    httptest.NewRecorder(),
				r:    goodRequest,
			},
			want: "",
		},
		{
			name: "GoodSkipBody",
			args: args{
				cfg:  Config{KeyFn: getSecretKey, SkipBody: true},
				opts: core.Options{},
				w:    httptest.NewRecorder(),
				r:    goodRequest,
			},
			want: "",
		},
		{
			name: "GoodCustomErrorHandler",
			args: args{
				cfg:  Config{KeyFn: getSecretKey, ErrorHandler: testErrorHandler},
				opts: core.Options{},
				w:    httptest.NewRecorder(),
				r:    accessKeyIsEmpty,
			},
			want: `{"message":"accesskey is empty"}`,
		},
		{
			name: "AccessKeyIsEmpty",
			args: args{
				cfg:  Config{KeyFn: getSecretKey, ErrorHandler: testErrorHandler},
				opts: core.Options{},
				w:    httptest.NewRecorder(),
				r:    accessKeyIsEmpty,
			},
			want: `{"message":"accesskey is empty"}`,
		},
		{
			name: "SecretKeyIsEmpty",
			args: args{
				cfg:  Config{KeyFn: getSecretKey, ErrorHandler: testErrorHandler},
				opts: core.Options{},
				w:    httptest.NewRecorder(),
				r:    secretKeyIsEmpty,
			},
			want: `{"message":"invalid accesskey"}`,
		},
		{
			name: "InvalidTimestamp",
			args: args{
				cfg:  Config{KeyFn: getSecretKey, ErrorHandler: testErrorHandler},
				opts: core.Options{},
				w:    httptest.NewRecorder(),
				r:    invalidTimestamp,
			},
			want: `{"message":"invalid timestamp"}`,
		},
		{
			name: "InvalidSignatureIsEmpty",
			args: args{
				cfg:  Config{KeyFn: getSecretKey, ErrorHandler: testErrorHandler},
				opts: core.Options{},
				w:    httptest.NewRecorder(),
				r:    invalidSignatureIsEmpty,
			},
			want: `{"message":"signature is empty"}`,
		},
		{
			name: "InvalidSignature",
			args: args{
				cfg:  Config{KeyFn: getSecretKey, ErrorHandler: testErrorHandler},
				opts: core.Options{},
				w:    httptest.NewRecorder(),
				r:    invalidSignature,
			},
			want: `{"message":"invalid signature"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := createTestServer(tt.args.cfg, tt.args.opts, tt.args.w)
			r, want := tt.args.r()
			if tt.want != "" {
				want = tt.want
			}
			g.ServeHTTP(tt.args.w, r)
			got := tt.args.w.Body.String()
			if got != want {
				t.Errorf("want %v, but got %v", want, got)
			}
		})
	}
}
