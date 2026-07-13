package core

import (
	"crypto/sha256"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAuth_ValidSignature(t *testing.T) {
	type fields struct {
		enc            Encoder
		hashFunc       HashFunc
		acceptableSkew time.Duration
		signMethod     string
	}
	type args struct {
		sk    string
		sign  string
		elems []string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "Ok",
			fields: fields{
				enc:            &Base64Encoder{},
				hashFunc:       sha256.New,
				acceptableSkew: 30 * time.Second,
				signMethod:     SignMethodHMACSHA256,
			},
			args: args{
				sk:    "123",
				sign:  "8qoXQ5qeZiCxxK6L7dZZh7kPqluAIdrBD82dbrcPWlI=",
				elems: []string{"123456", "helloworld"},
			},
			wantErr: false,
		},
		{
			name: "FailedInvalidSignStr",
			fields: fields{
				enc:            &Base64Encoder{},
				hashFunc:       sha256.New,
				acceptableSkew: 30 * time.Second,
				signMethod:     SignMethodHMACSHA256,
			},
			args: args{
				sk:    "123",
				sign:  "TwcsQLXoVS8PeAJYpqZuCVHfIkMWwuWF4k0EvKRVA=",
				elems: []string{"123456", "helloworld"},
			},
			wantErr: true,
		},
		{
			name: "FailedInvalidSign",
			fields: fields{
				enc:            &Base64Encoder{},
				hashFunc:       sha256.New,
				acceptableSkew: 30 * time.Second,
				signMethod:     SignMethodHMACSHA256,
			},
			args: args{
				sk:    "123",
				sign:  "TwcsQLXoVS8PeAJYptZqZuCVHfIkMWwuWF4k0EvKRVA=",
				elems: []string{"123456", "helloworld!"},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Auth{
				enc:            tt.fields.enc,
				acceptableSkew: tt.fields.acceptableSkew,
				signMethod:     tt.fields.signMethod,
			}
			// 为HMAC签名创建signer
			if isHMAC(tt.fields.signMethod) {
				s.signer = NewHMACSigner(tt.fields.hashFunc, tt.fields.signMethod)
			}
			// 使用固定的 ak 进行测试
			ak := "test-ak"
			if err := s.Verify(ak, tt.args.sk, tt.args.sign, tt.args.elems...); (err != nil) != tt.wantErr {
				t.Errorf("Auth.ValidSignature() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAuth_EncodeToString(t *testing.T) {
	type fields struct {
		enc            Encoder
		hashFunc       HashFunc
		acceptableSkew time.Duration
	}
	type args struct {
		b []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   string
	}{
		{
			name: "Ok",
			fields: fields{
				enc:            &Base64Encoder{},
				hashFunc:       sha256.New,
				acceptableSkew: 30 * time.Second,
			},
			args: args{
				b: []byte(`helloworld`),
			},
			want: "aGVsbG93b3JsZA==",
		},
		{
			name: "Ok",
			fields: fields{
				enc:            &Base64Encoder{},
				hashFunc:       sha256.New,
				acceptableSkew: 30 * time.Second,
			},
			args: args{
				b: []byte{},
			},
			want: "",
		},
		{
			name: "Ok",
			fields: fields{
				enc:            &HexEncoder{},
				hashFunc:       sha256.New,
				acceptableSkew: 30 * time.Second,
			},
			args: args{
				b: []byte{},
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Auth{
				enc:            tt.fields.enc,
				acceptableSkew: tt.fields.acceptableSkew,
			}
			if got := s.EncodeToString(tt.args.b); got != tt.want {
				t.Errorf("Auth.EncodeToString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuth_ParseTimestamp(t *testing.T) {
	type fields struct {
		enc            Encoder
		hashFunc       HashFunc
		acceptableSkew time.Duration
	}
	type args struct {
		ts string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "Ok",
			fields: fields{
				enc:            &Base64Encoder{},
				hashFunc:       sha256.New,
				acceptableSkew: 30 * time.Second,
			},
			args: args{
				ts: strconv.FormatInt(time.Now().Add(20*time.Second).Unix(), 10),
			},
			wantErr: false,
		},
		{
			name: "Expired",
			fields: fields{
				enc:            &Base64Encoder{},
				hashFunc:       sha256.New,
				acceptableSkew: 30 * time.Second,
			},
			args: args{
				ts: "1570000000",
			},
			wantErr: true,
		},
		{
			name: "TooNew",
			fields: fields{
				enc:            &Base64Encoder{},
				hashFunc:       sha256.New,
				acceptableSkew: 30 * time.Second,
			},
			args: args{
				ts: strconv.FormatInt(time.Now().Add(60*time.Second).Unix(), 10),
			},
			wantErr: true,
		},
		{
			name: "Empty",
			fields: fields{
				enc:            &Base64Encoder{},
				hashFunc:       sha256.New,
				acceptableSkew: 30 * time.Second,
			},
			args: args{
				ts: "",
			},
			wantErr: true,
		},
		{
			name: "Invalid",
			fields: fields{
				enc:            &Base64Encoder{},
				hashFunc:       sha256.New,
				acceptableSkew: 30 * time.Second,
			},
			args: args{
				ts: "1570000a00",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Auth{
				enc:            tt.fields.enc,
				acceptableSkew: tt.fields.acceptableSkew,
			}
			if err := s.ParseTimestamp(tt.args.ts); (err != nil) != tt.wantErr {
				t.Errorf("Auth.ParseTimestamp() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNew(t *testing.T) {
	type args struct {
		opts []OptionFunc
		s    string
	}
	tests := []struct {
		name    string
		args    args
		want    *Auth
		wantErr bool
	}{
		{
			name: "Ok",
			args: args{
				opts: []OptionFunc{
					WithSignMethod(SignMethodHMACSHA256),
					WithEncoder(&Base64Encoder{}),
					WithAcceptableSkew(30 * time.Second),
				},
				s: "123",
			},
			want: &Auth{
				enc:            &Base64Encoder{},
				acceptableSkew: 30 * time.Second,
				signMethod:     SignMethodHMACSHA256,
			},
			wantErr: false,
		},
		{
			name: "DefaultHMAC",
			args: args{
				opts: []OptionFunc{
					WithEncoder(&Base64Encoder{}),
				},
				s: "123",
			},
			want: &Auth{
				enc:            &Base64Encoder{},
				acceptableSkew: 60 * time.Second,
				signMethod:     SignMethodHMACSHA256,
			},
			wantErr: false,
		},
		{
			name: SignMethodHMACSHA384,
			args: args{
				opts: []OptionFunc{
					WithSignMethod(SignMethodHMACSHA384),
					WithEncoder(&Base64Encoder{}),
				},
				s: "123",
			},
			want: &Auth{
				enc:            &Base64Encoder{},
				acceptableSkew: 60 * time.Second,
				signMethod:     SignMethodHMACSHA384,
			},
			wantErr: false,
		},
		{
			name: SignMethodHMACSHA512,
			args: args{
				opts: []OptionFunc{
					WithSignMethod(SignMethodHMACSHA512),
					WithEncoder(&Base64Encoder{}),
				},
				s: "123",
			},
			want: &Auth{
				enc:            &Base64Encoder{},
				acceptableSkew: 60 * time.Second,
				signMethod:     SignMethodHMACSHA512,
			},
			wantErr: false,
		},
		{
			name: "InvalidSignMethod",
			args: args{
				opts: []OptionFunc{
					WithSignMethod("invalid"),
				},
			},
			wantErr: true,
		},
		{
			name: SignMethodRSASHA256,
			args: args{
				opts: []OptionFunc{
					WithSignMethod(SignMethodRSASHA256),
					WithEncoder(&Base64Encoder{}),
				},
				s: "123",
			},
			want: &Auth{
				enc:            &Base64Encoder{},
				acceptableSkew: 60 * time.Second,
				signMethod:     SignMethodRSASHA256,
			},
			wantErr: false,
		},
		{
			name: SignMethodECDSASHA256,
			args: args{
				opts: []OptionFunc{
					WithSignMethod(SignMethodECDSASHA256),
					WithEncoder(&Base64Encoder{}),
				},
				s: "123",
			},
			want: &Auth{
				enc:            &Base64Encoder{},
				acceptableSkew: 60 * time.Second,
				signMethod:     SignMethodECDSASHA256,
			},
			wantErr: false,
		},
		{
			name: SignMethodEd25519,
			args: args{
				opts: []OptionFunc{
					WithSignMethod(SignMethodEd25519),
					WithEncoder(&Base64Encoder{}),
				},
				s: "123",
			},
			want: &Auth{
				enc:            &Base64Encoder{},
				acceptableSkew: 60 * time.Second,
				signMethod:     SignMethodEd25519,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.args.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			b := []byte(tt.args.s)
			assert.Equal(t, tt.want.enc.EncodeToString(b), got.enc.EncodeToString(b))
			assert.Equal(t, tt.want.acceptableSkew, got.acceptableSkew)
			assert.Equal(t, tt.want.signMethod, got.signMethod)
		})
	}
}
