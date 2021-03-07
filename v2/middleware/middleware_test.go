package middleware

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/qingtao/aksk/v2/request"
)

// testHandler http.Handler
type testHandler struct{}

func (h *testHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "hello 111")
}

func TestKeyGetterIsNil(t *testing.T) {
	defer func() {
		if err := recover(); err == nil {
			t.Errorf("expect panic, but normal")
		}
	}()
	_ = New(Config{})
}

// getSecretKey key函数
func getSecretKey(ak string) (string, error) {
	if ak == "wantEmpty" {
		return "", nil
	}
	return "456", nil
}

// goodTestRequest 正常的测试请求
func goodTestRequest(url string) *http.Request {
	modifier, _ := request.NewModifierFunc("123", "456", false)
	r, _ := http.NewRequestWithContext(context.TODO(), "POST", url, bytes.NewReader([]byte(`helloworld`)))
	modifier(r)
	return r
}

func TestMiddleware(t *testing.T) {
	cfg := Config{KeyGetter: getSecretKey}
	m1 := New(cfg)

	mux := http.DefaultServeMux
	f1 := func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "helloworld!")
	}
	mux.Handle("/1", m1.HandleFunc(f1))
	mux.Handle("/11", m1.Handle(&testHandler{}))
	mux.HandleFunc("/2", f1)
	mux.Handle("/22", m1.Handle(&testHandler{}))

	const url = `http://example.com/`

	type args struct {
		r *http.Request
	}
	tests := []struct {
		name     string
		args     args
		wantCode int
	}{
		{
			name: "Good-1",
			args: args{
				r: goodTestRequest(url + "1"),
			},
			wantCode: 200,
		},
		{
			name: "Invalid-1",
			args: args{
				r: httptest.NewRequest(http.MethodGet, url+"1", nil),
			},
			wantCode: 401,
		},
		{
			name: "Good-11",
			args: args{
				r: goodTestRequest(url + "11"),
			},
			wantCode: 200,
		},
		{
			name: "Invalid-11",
			args: args{
				r: httptest.NewRequest(http.MethodGet, url+"11", nil),
			},
			wantCode: 401,
		},
		{
			name: "Good-2",
			args: args{
				r: goodTestRequest(url + "2"),
			},
			wantCode: 200,
		},
		{
			name: "Good-22",
			args: args{
				r: goodTestRequest(url + "22"),
			},
			wantCode: 200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, tt.args.r)
			if w.Code != tt.wantCode {
				t.Errorf("expect StatusCode %v, but got %v", tt.wantCode, w.Code)
				return
			}
		})
	}
}

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
				err: errors.New(`{msg:"core.Error"}`),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defaultErrorHandler(tt.args.w, tt.args.err)
			if tt.args.err != nil {
				t.Logf("%s", tt.args.w.Body.String())
			}
		})
	}
}
