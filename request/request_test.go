package request

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/qingtao/aksk/v2/core"
)

// goodRequest 正常的请求
func goodRequest() *http.Request {
	modifier, _ := NewModifierFunc("123", "456")
	r, _ := http.NewRequestWithContext(context.TODO(), "POST", httptest.DefaultRemoteAddr, bytes.NewReader([]byte(`helloworld`)))
	modifier(r)
	return r
}

// invalidAkRequest 错误的Ak
func invalidAkRequest() *http.Request {
	modifier, _ := NewModifierFunc("123", "456")
	r, _ := http.NewRequestWithContext(context.TODO(), "POST", httptest.DefaultRemoteAddr, bytes.NewReader([]byte(`helloworld`)))
	modifier(r)
	r.Header.Set(HeaderAccessKey, "")
	return r
}

// invalidSkRequest 错误的Sk
func invalidSkRequest() *http.Request {
	modifier, _ := NewModifierFunc("wantEmpty", "456")
	r, _ := http.NewRequestWithContext(context.TODO(), "POST", httptest.DefaultRemoteAddr, bytes.NewReader([]byte(`helloworld`)))
	modifier(r)
	return r
}

// invalidTsRequest 错误的时间戳
func invalidTsRequest() *http.Request {
	modifier, _ := NewModifierFunc("123", "456")
	r, _ := http.NewRequestWithContext(context.TODO(), "POST", httptest.DefaultRemoteAddr, bytes.NewReader([]byte(`helloworld`)))
	modifier(r)
	r.Header.Set(HeaderTimestamp, "150a0")
	return r
}

// invalidRequestSignIsEmpty 没有签名
func invalidRequestSignIsEmpty() *http.Request {
	modifier, _ := NewModifierFunc("123", "456")
	r, _ := http.NewRequestWithContext(context.TODO(), "POST", httptest.DefaultRemoteAddr, bytes.NewReader([]byte(`helloworld`)))
	modifier(r)
	r.Header.Set(HeaderSignature, "")
	return r
}

// invalidRequestSign 签名错误
func invalidRequestSign() *http.Request {
	modifier, _ := NewModifierFunc("123", "456")
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
		req  *http.Request
		f    core.KeyGetter
		opts []core.OptionFunc
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
				opts: []core.OptionFunc{
					core.WithSignMethod(core.SignMethodHMACSHA256),
				},
			},
			wantErr: false,
		},
		{
			name: "GetterIsNil",
			args: args{
				req: goodRequest(),
				f:   nil,
				opts: []core.OptionFunc{
					core.WithSignMethod(core.SignMethodHMACSHA256),
				},
			},
			wantErr: true,
		},
		{
			name: "FailedAk",
			args: args{
				req: invalidAkRequest(),
				f:   getKey,
				opts: []core.OptionFunc{
					core.WithSignMethod(core.SignMethodHMACSHA256),
				},
			},
			wantErr: true,
		},
		{
			name: "FailedSk",
			args: args{
				req: invalidSkRequest(),
				f:   getKey,
				opts: []core.OptionFunc{
					core.WithSignMethod(core.SignMethodHMACSHA256),
				},
			},
			wantErr: true,
		},
		{
			name: "FailedTs",
			args: args{
				req: invalidTsRequest(),
				f:   getKey,
				opts: []core.OptionFunc{
					core.WithSignMethod(core.SignMethodHMACSHA256),
				},
			},
			wantErr: true,
		},
		{
			name: "FailedSignIsEmpty",
			args: args{
				req: invalidRequestSignIsEmpty(),
				f:   getKey,
				opts: []core.OptionFunc{
					core.WithSignMethod(core.SignMethodHMACSHA256),
				},
			},
			wantErr: true,
		},
		{
			name: "FailedSign",
			args: args{
				req: invalidRequestSign(),
				f:   getKey,
				opts: []core.OptionFunc{
					core.WithSignMethod(core.SignMethodHMACSHA256),
				},
			},
			wantErr: true,
		},
		{
			name: "DefaultHMAC",
			args: args{
				req: goodRequest(),
				f:   getKey,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator, err := NewValidatorFunc(tt.args.f, tt.args.opts...)
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
	getKey := func(sk string) func(ak string) (string, error) {
		return func(ak string) (string, error) {
			if ak == "wantErr" {
				return "", errors.New(ak)
			}
			return sk, nil
		}
	}
	type args struct {
		ak   string
		sk   string
		url  string
		opts []core.OptionFunc
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
				opts: []core.OptionFunc{
					core.WithSignMethod(core.SignMethodHMACSHA256),
					core.WithEncoder(&core.Base64Encoder{}),
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
				opts: []core.OptionFunc{
					core.WithSignMethod(core.SignMethodHMACSHA256),
					core.WithEncoder(&core.Base64Encoder{}),
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
				opts: []core.OptionFunc{
					core.WithSignMethod(core.SignMethodHMACSHA256),
					core.WithEncoder(&core.Base64Encoder{}),
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
				opts: []core.OptionFunc{
					core.WithSignMethod(core.SignMethodHMACSHA256),
					core.WithEncoder(&core.Base64Encoder{}),
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
				opts: []core.OptionFunc{
					core.WithSignMethod(core.SignMethodHMACSHA256),
					core.WithEncoder(&core.Base64Encoder{}),
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			modifier, err := NewModifierFunc(tt.args.ak, tt.args.sk, tt.args.opts...)
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
			t.Logf("%s: %s", HeaderTimestamp, req.Header.Get(HeaderTimestamp))
			t.Logf("%s: %s", HeaderSignature, req.Header.Get(HeaderSignature))

			validator, err := NewValidatorFunc(getKey(tt.args.sk), tt.args.opts...)
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

func TestNonceStore(t *testing.T) {
	store := NewMemoryStore(WithTTL(5 * time.Minute))

	t.Run("StoreAndExists", func(t *testing.T) {
		err := store.store("test-ak-1", "test-nonce-1")
		if err != nil {
			t.Errorf("store error = %v", err)
		}

		exists, err := store.exists("test-ak-1", "test-nonce-1")
		if err != nil {
			t.Errorf("exists error = %v", err)
		}
		if !exists {
			t.Error("nonce should exist")
		}
	})

	t.Run("DuplicateNonce", func(t *testing.T) {
		err := store.store("test-ak-2", "test-nonce-2")
		if err != nil {
			t.Errorf("store error = %v", err)
		}

		err = store.store("test-ak-2", "test-nonce-2")
		if err == nil {
			t.Error("expected error for duplicate nonce")
		}
	})

	t.Run("NonExistentNonce", func(t *testing.T) {
		exists, err := store.exists("test-ak-3", "non-existent")
		if err != nil {
			t.Errorf("exists error = %v", err)
		}
		if exists {
			t.Error("nonce should not exist")
		}
	})
}

func TestNonceValidation(t *testing.T) {
	tests := []struct {
		name      string
		nonce     string
		minLen    int
		maxLen    int
		wantError bool
	}{
		{
			name:      "ValidLength",
			nonce:     "1234567890123456",
			minLen:    16,
			maxLen:    64,
			wantError: false,
		},
		{
			name:      "TooShort",
			nonce:     "12345",
			minLen:    16,
			maxLen:    64,
			wantError: true,
		},
		{
			name:      "TooLong",
			nonce:     strings.Repeat("a", 65),
			minLen:    16,
			maxLen:    64,
			wantError: true,
		},
		{
			name:      "EmptyNonce",
			nonce:     "",
			minLen:    16,
			maxLen:    64,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewMemoryStore(WithMinLen(tt.minLen), WithMaxLen(tt.maxLen))
			err := store.validateNonceLength(tt.nonce)
			if (err != nil) != tt.wantError {
				t.Errorf("validateNonceLength() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestModifier(t *testing.T) {
	store := NewMemoryStore()
	keyGetter := func(ak string) (string, error) {
		return "456", nil
	}

	coreOpts := []core.OptionFunc{
		core.WithSignMethod(core.SignMethodHMACSHA256),
		core.WithEncoder(&core.Base64Encoder{}),
	}

	cfg := Config{
		Ak:         "123",
		Sk:         "456",
		NonceStore: store,
		KeyGetter:  keyGetter,
	}

	// 创建带nonce的modifier
	modifier, err := NewModifier(cfg, coreOpts...)
	if err != nil {
		t.Fatalf("NewModifierWithNonce error = %v", err)
	}

	// 创建请求
	req, err := http.NewRequestWithContext(context.TODO(), http.MethodPost, httptest.DefaultRemoteAddr, strings.NewReader("hello"))
	if err != nil {
		t.Fatalf("http.NewRequestWithContext error = %v", err)
	}

	// 添加签名
	if err := modifier.ModifyRequest(req); err != nil {
		t.Fatalf("ModifyRequest error = %v", err)
	}

	// 验证nonce头部存在
	nonce := req.Header.Get(HeaderNonce)
	if nonce == "" {
		t.Error("nonce header should be set")
	}
	t.Logf("nonce: %s", nonce)

	// 创建带nonce的validator
	validator, err := NewValidator(cfg, coreOpts...)
	if err != nil {
		t.Fatalf("NewValidatorWithNonce error = %v", err)
	}

	// 验证请求
	if err := validator.Validate(req); err != nil {
		t.Errorf("Validate error = %v", err)
	}

	// 重放请求应该失败（nonce已使用）
	if err := validator.Validate(req); err == nil {
		t.Error("replay request should fail")
	}
}

func TestModifierWithoutNonce(t *testing.T) {
	keyGettter := func(ak string) (string, error) {
		return "456", nil
	}

	coreOpts := []core.OptionFunc{
		core.WithSignMethod(core.SignMethodHMACSHA256),
		core.WithEncoder(&core.Base64Encoder{}),
	}

	// 创建不带nonce的modifier
	modifier, err := NewModifierFunc("123", "456", coreOpts...)
	if err != nil {
		t.Fatalf("NewModifierFunc error = %v", err)
	}

	// 创建请求
	req, err := http.NewRequestWithContext(context.TODO(), http.MethodPost, httptest.DefaultRemoteAddr, strings.NewReader("hello"))
	if err != nil {
		t.Fatalf("http.NewRequestWithContext error = %v", err)
	}

	// 添加签名
	if err := modifier.ModifyRequest(req); err != nil {
		t.Fatalf("ModifyRequest error = %v", err)
	}

	// 验证nonce头部不存在
	nonce := req.Header.Get(HeaderNonce)
	if nonce != "" {
		t.Error("nonce header should not be set")
	}

	// 创建不带nonce的validator
	validator, err := NewValidatorFunc(keyGettter, coreOpts...)
	if err != nil {
		t.Fatalf("NewValidatorFunc error = %v", err)
	}

	// 验证请求
	if err := validator.Validate(req); err != nil {
		t.Errorf("Validate error = %v", err)
	}
}

func TestValidatorNonceEmpty(t *testing.T) {
	getKey := func(ak string) (string, error) {
		return "456", nil
	}

	coreOpts := []core.OptionFunc{
		core.WithSignMethod(core.SignMethodHMACSHA256),
		core.WithEncoder(&core.Base64Encoder{}),
	}

	// 创建不带nonce的modifier
	modifier, err := NewModifierFunc("123", "456", coreOpts...)
	if err != nil {
		t.Fatalf("NewModifierFunc error = %v", err)
	}

	// 创建请求
	req, err := http.NewRequestWithContext(context.TODO(), http.MethodPost, httptest.DefaultRemoteAddr, strings.NewReader("hello"))
	if err != nil {
		t.Fatalf("http.NewRequestWithContext error = %v", err)
	}

	// 添加签名（不带nonce）
	if err := modifier.ModifyRequest(req); err != nil {
		t.Fatalf("ModifyRequest error = %v", err)
	}

	cfg := Config{
		KeyGetter:  getKey,
		NonceStore: NewMemoryStore(),
	}
	// 创建带nonce的validator
	validator, err := NewValidator(cfg, coreOpts...)
	if err != nil {
		t.Fatalf("NewValidatorWithNonce error = %v", err)
	}

	// 验证请求应该失败（nonce为空）
	if err := validator.Validate(req); err == nil {
		t.Error("expected error for empty nonce")
	}
}

func TestNonceLengthOptions(t *testing.T) {
	coreOpts := []core.OptionFunc{
		core.WithSignMethod(core.SignMethodHMACSHA256),
		core.WithEncoder(&core.Base64Encoder{}),
	}

	store := NewMemoryStore(WithMinLen(16), WithMaxLen(64))
	cfg := Config{
		Ak:         "123",
		Sk:         "456",
		NonceStore: store,
	}

	// 创建带nonce的modifier
	modifier, err := NewModifier(cfg, coreOpts...)
	if err != nil {
		t.Fatalf("NewModifierWithNonce error = %v", err)
	}

	// 创建请求
	req, err := http.NewRequestWithContext(context.TODO(), http.MethodPost, httptest.DefaultRemoteAddr, strings.NewReader("hello"))
	if err != nil {
		t.Fatalf("http.NewRequestWithContext error = %v", err)
	}

	// 添加签名
	if err := modifier.ModifyRequest(req); err != nil {
		t.Fatalf("ModifyRequest error = %v", err)
	}

	// 验证nonce头部存在
	nonce := req.Header.Get(HeaderNonce)
	if nonce == "" {
		t.Error("nonce header should be set")
	}

	// 验证nonce长度在自定义范围内
	if len(nonce) < store.minLen || len(nonce) > store.maxLen {
		t.Errorf("nonce length %d not in range [%d, %d]", len(nonce), store.minLen, store.maxLen)
	}
}
