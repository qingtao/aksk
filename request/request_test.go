package request

import (
	"context"
	"crypto/sha1"
	"net/http/httptest"
	"testing"

	"github.com/qingtao/aksk/core"
)

func TestNewHandlerFunc(t *testing.T) {
	type args struct {
		ak   string
		sk   string
		url  string
		opts []core.Options
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
				opts: []core.Options{
					{
						Encoder: &core.Base64Encoder{},
						Hash:    sha1.New,
					},
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
				opts: []core.Options{
					{
						Encoder: &core.Base64Encoder{},
						Hash:    sha1.New,
					},
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
				opts: []core.Options{
					{
						Encoder: &core.Base64Encoder{},
						Hash:    sha1.New,
					},
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
				opts: []core.Options{
					{
						Encoder: &core.Base64Encoder{},
						Hash:    sha1.New,
					},
				},
			},
			wantErr:  false,
			wantErr2: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.args.ak, tt.args.sk, tt.args.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewHandlerFunc() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got == nil {
				return
			}
			req, err := got(context.TODO(), "POST", tt.args.url, []byte(`{"msg":"helloworld!"}`))
			if (err != nil) != tt.wantErr2 {
				t.Errorf("create request failed %s", err)
				return
			}
			if req != nil {
				t.Logf("%+v", req.Header)
			}
		})

	}
}
