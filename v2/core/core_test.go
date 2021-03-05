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
		enc Encoder
		h   HashFunc
		d   time.Duration
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
				enc: &Base64Encoder{},
				h:   sha256.New,
				d:   30 * time.Second,
			},
			args: args{
				sk:    "123",
				sign:  "TwcsQLXoVS8PeAJYptZqZuCVHfIkMWwuWF4k0EvKRVA=",
				elems: []string{"123456", "helloworld"},
			},
			wantErr: false,
		},
		{
			name: "FailedInvalidSignStr",
			fields: fields{
				enc: &Base64Encoder{},
				h:   sha256.New,
				d:   30 * time.Second,
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
				enc: &Base64Encoder{},
				h:   sha256.New,
				d:   30 * time.Second,
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
				enc: tt.fields.enc,
				h:   tt.fields.h,
				d:   tt.fields.d,
			}
			if err := s.ValidSignature(tt.args.sk, tt.args.sign, tt.args.elems...); (err != nil) != tt.wantErr {
				t.Errorf("Auth.ValidSignature() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAuth_ValidBody(t *testing.T) {
	type fields struct {
		enc Encoder
		h   HashFunc
		d   time.Duration
	}
	type args struct {
		b   []byte
		str string
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
				enc: &Base64Encoder{},
				h:   sha256.New,
				d:   30 * time.Second,
			},
			args: args{
				b:   []byte(`helloworld`),
				str: "k2oYXKqiZrucvpgengXLeM1zKwsygOuURBK7b4+PB68=",
			},
			wantErr: false,
		},
		{
			name: "OkEmptyBody",
			fields: fields{
				enc: &Base64Encoder{},
				h:   sha256.New,
				d:   30 * time.Second,
			},
			args: args{
				b:   nil,
				str: "k2oYXKqiZrucvpgengXLeM1zKwsygOuURBK7b4+PB68=",
			},
			wantErr: false,
		},
		{
			name: "OkEmptyMac",
			fields: fields{
				enc: &Base64Encoder{},
				h:   sha256.New,
				d:   30 * time.Second,
			},
			args: args{
				b:   []byte(`helloworld`),
				str: "",
			},
			wantErr: true,
		},
		{
			name: "FailedInvalidStr",
			fields: fields{
				enc: &Base64Encoder{},
				h:   sha256.New,
				d:   30 * time.Second,
			},
			args: args{
				b:   []byte(`helloworld`),
				str: "TwcsQLXoVS8PeAJYtZqZuCVHfIkMWwuWF4k0EvKRVA=",
			},
			wantErr: true,
		},
		{
			name: "FailedInvalidMac",
			fields: fields{
				enc: &Base64Encoder{},
				h:   sha256.New,
				d:   30 * time.Second,
			},
			args: args{
				b:   []byte(`helloworld`),
				str: "TwcsQLXoVS8PeAJYptZqZuCVHfIkMWwuWF4k0EvKRVA=",
			},
			wantErr: true,
		},
		{
			name: "OkHexEncoder",
			fields: fields{
				enc: &HexEncoder{},
				h:   sha256.New,
				d:   30 * time.Second,
			},
			args: args{
				b:   []byte(`helloworld`),
				str: "936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Auth{
				enc: tt.fields.enc,
				h:   tt.fields.h,
				d:   tt.fields.d,
			}
			str := s.Sum(tt.args.b)
			t.Logf("%s", s.EncodeToString(str))
			if err := s.ValidBody(tt.args.b, tt.args.str); (err != nil) != tt.wantErr {
				t.Errorf("Auth.ValidBody() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAuth_EncodeToString(t *testing.T) {
	type fields struct {
		enc Encoder
		h   HashFunc
		d   time.Duration
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
				enc: &Base64Encoder{},
				h:   sha256.New,
				d:   30 * time.Second,
			},
			args: args{
				b: []byte(`helloworld`),
			},
			want: "aGVsbG93b3JsZA==",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Auth{
				enc: tt.fields.enc,
				h:   tt.fields.h,
				d:   tt.fields.d,
			}
			if got := s.EncodeToString(tt.args.b); got != tt.want {
				t.Errorf("Auth.EncodeToString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuth_ParseTimestamp(t *testing.T) {
	type fields struct {
		enc Encoder
		h   HashFunc
		d   time.Duration
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
				enc: &Base64Encoder{},
				h:   sha256.New,
				d:   30 * time.Second,
			},
			args: args{
				ts: strconv.FormatInt(time.Now().Add(20*time.Second).Unix(), 10),
			},
			wantErr: false,
		},
		{
			name: "Expired",
			fields: fields{
				enc: &Base64Encoder{},
				h:   sha256.New,
				d:   30 * time.Second,
			},
			args: args{
				ts: "1570000000",
			},
			wantErr: true,
		},
		{
			name: "TooNew",
			fields: fields{
				enc: &Base64Encoder{},
				h:   sha256.New,
				d:   30 * time.Second,
			},
			args: args{
				ts: strconv.FormatInt(time.Now().Add(60*time.Second).Unix(), 10),
			},
			wantErr: true,
		},
		{
			name: "Empty",
			fields: fields{
				enc: &Base64Encoder{},
				h:   sha256.New,
				d:   30 * time.Second,
			},
			args: args{
				ts: "",
			},
			wantErr: true,
		},
		{
			name: "Invalid",
			fields: fields{
				enc: &Base64Encoder{},
				h:   sha256.New,
				d:   30 * time.Second,
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
				enc: tt.fields.enc,
				h:   tt.fields.h,
				d:   tt.fields.d,
			}
			if err := s.ParseTimestamp(tt.args.ts); (err != nil) != tt.wantErr {
				t.Errorf("Auth.ParseTimestamp() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNew(t *testing.T) {
	type args struct {
		opts []Option
		s    string
	}
	tests := []struct {
		name string
		args args
		want *Auth
	}{
		{
			name: "Ok",
			args: args{
				opts: []Option{
					WithEncoder(&Base64Encoder{}),
					WithHash(sha256.New),
					WithAcceptableSkew(30 * time.Second),
				},
				s: "123",
			},
			want: &Auth{
				enc: &Base64Encoder{},
				h:   sha256.New,
				d:   30 * time.Second,
			},
		},
		{
			name: "Default",
			args: args{
				opts: nil,
			},
			want: &Auth{
				enc: &Base64Encoder{},
				h:   sha256.New,
				d:   1 * time.Minute,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := New(tt.args.opts...)
			b := []byte(tt.args.s)
			assert.Equal(t, tt.want.enc.EncodeToString(b), got.enc.EncodeToString(b))
			assert.Equal(t, tt.want.h().Sum(b), got.h().Sum(b))
			assert.Equal(t, tt.want.d, got.d)
		})
	}
}
