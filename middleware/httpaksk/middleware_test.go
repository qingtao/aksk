package httpaksk

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func getSecretKey(ak string) string {
	return "test_password"
}

func TestMiddleware(t *testing.T) {
	cfg := Config{KeyFn: getSecretKey}
	m1 := New(cfg)

	mux := http.DefaultServeMux
	mux.HandleFunc("/1", m1.WrapHandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello 111")
	}))
	mux.HandleFunc("/2", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello 222")
	})

	t.Run("401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/1", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != 401 {
			t.Errorf("expect StatusCode 401, but got %d", w.Code)
			return
		}
		// t.Logf("%+v", w)
	})

	t.Run("200", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/2", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Errorf("expect StatusCode 200, but got %d", w.Code)
			return
		}
		// t.Logf("%+v", w)
	})
}
