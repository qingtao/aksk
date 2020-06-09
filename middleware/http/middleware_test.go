package http

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/qingtao/aksk/core"
	"github.com/qingtao/aksk/request"
)

func goodRequest() *http.Request {
	requestFunc, _ := request.New("123", "456")
	r, _ := requestFunc(context.TODO(), "POST", httptest.DefaultRemoteAddr, []byte(`helloworld`))
	return r
}

func goodTestRequest(url string) *http.Request {
	requestFunc, _ := request.New("123", "456")
	r, _ := requestFunc(context.TODO(), "POST", url, []byte(`helloworld`))
	return r
}

func invalidAkRequest() *http.Request {
	requestFunc, _ := request.New("123", "456")
	r, _ := requestFunc(context.TODO(), "POST", httptest.DefaultRemoteAddr, []byte(`helloworld`))
	r.Header.Set(request.HeaderAccessKey, "")
	return r
}

func invalidSkRequest() *http.Request {
	requestFunc, _ := request.New("wantEmpty", "456")
	r, _ := requestFunc(context.TODO(), "POST", httptest.DefaultRemoteAddr, []byte(`helloworld`))
	return r
}

func invalidTsRequest() *http.Request {
	requestFunc, _ := request.New("123", "456")
	r, _ := requestFunc(context.TODO(), "POST", httptest.DefaultRemoteAddr, []byte(`helloworld`))
	r.Header.Set(request.HeaderTimestamp, "150a0")
	return r
}

func invalidRequestSignIsEmpty() *http.Request {
	requestFunc, _ := request.New("123", "456")
	r, _ := requestFunc(context.TODO(), "POST", httptest.DefaultRemoteAddr, []byte(`helloworld`))
	r.Header.Set(request.HeaderSignature, "")
	return r
}

func invalidRequestSign() *http.Request {
	requestFunc, _ := request.New("123", "456")
	r, _ := requestFunc(context.TODO(), "POST", httptest.DefaultRemoteAddr, []byte(`helloworld`))
	r.Header.Set(request.HeaderSignature, "936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af")
	return r
}

func getSecretKey(ak string) string {
	if ak == "wantEmpty" {
		return ""
	}
	return "456"
}

type testHandler struct{}

func (h *testHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "hello 111")
}

func TestKeyFnIsNil(t *testing.T) {
	defer func() {
		if err := recover(); err == nil {
			t.Errorf("expect panic, but normal")
		}
	}()
	_ = New(Config{})
}

func TestMiddleware(t *testing.T) {
	cfg := Config{Key: getSecretKey}
	m1 := New(cfg)

	mux := http.DefaultServeMux
	f1 := func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "helloworld!")
	}
	mux.HandleFunc("/1", m1.HandleFunc(f1))
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

func TestMiddleware_ValidRequest(t *testing.T) {
	type fields struct {
		opts core.Options
		cfg  Config
	}
	type args struct {
		r *http.Request
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "Good",
			fields: fields{
				opts: core.Options{},
				cfg: Config{
					Key: getSecretKey,
				},
			},
			args: args{
				r: goodRequest(),
			},
			wantErr: false,
		},
		{
			name: "GoodSkipBody",
			fields: fields{
				opts: core.Options{},
				cfg: Config{
					Key:      getSecretKey,
					SkipBody: true,
				},
			},
			args: args{
				r: goodRequest(),
			},
			wantErr: false,
		},
		{
			name: "FailedAk",
			fields: fields{
				opts: core.Options{},
				cfg: Config{
					Key: getSecretKey,
				},
			},
			args: args{
				r: invalidSkRequest(),
			},
			wantErr: true,
		},
		{
			name: "FailedSk",
			fields: fields{
				opts: core.Options{},
				cfg: Config{
					Key: getSecretKey,
				},
			},
			args: args{
				r: invalidSkRequest(),
			},
			wantErr: true,
		},
		{
			name: "FailedTs",
			fields: fields{
				opts: core.Options{},
				cfg: Config{
					Key: getSecretKey,
				},
			},
			args: args{
				r: invalidTsRequest(),
			},
			wantErr: true,
		},
		{
			name: "FailedSignIsEmpty",
			fields: fields{
				opts: core.Options{},
				cfg: Config{
					Key: getSecretKey,
				},
			},
			args: args{
				r: invalidRequestSignIsEmpty(),
			},
			wantErr: true,
		},
		{
			name: "FailedSign",
			fields: fields{
				opts: core.Options{},
				cfg: Config{
					Key: getSecretKey,
				},
			},
			args: args{
				r: invalidRequestSign(),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := New(tt.fields.cfg, tt.fields.opts)
			if err := m.ValidRequest(tt.args.r); (err != nil) != tt.wantErr {
				t.Errorf("Middleware.ValidRequest() error = %v, wantErr %v", err, tt.wantErr)
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
				err: core.NewError("core.Error", errors.New(`err`)),
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
