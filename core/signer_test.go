package core

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestRSASigner(t *testing.T) {
	// 生成RSA密钥对
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	testCases := []struct {
		name string
		hash crypto.Hash
	}{
		{SignMethodRSASHA256, crypto.SHA256},
		{SignMethodRSASHA384, crypto.SHA384},
		{SignMethodRSASHA512, crypto.SHA512},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			signer := NewRSASigner(tc.hash, tc.name)
			data := []byte("test data for signing")

			// 签名
			signature, err := signer.Sign(data, privateKey)
			if err != nil {
				t.Fatalf("failed to sign: %v", err)
			}

			// 验证
			err = signer.Verify(data, signature, &privateKey.PublicKey)
			if err != nil {
				t.Fatalf("failed to verify: %v", err)
			}

			// 验证错误的数据
			wrongData := []byte("wrong data")
			err = signer.Verify(wrongData, signature, &privateKey.PublicKey)
			if err == nil {
				t.Fatal("expected verification to fail with wrong data")
			}
		})
	}
}

func TestECDSASigner(t *testing.T) {
	// 生成ECDSA密钥对
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	testCases := []struct {
		name string
		hash crypto.Hash
	}{
		{SignMethodECDSASHA256, crypto.SHA256},
		{SignMethodECDSASHA384, crypto.SHA384},
		{SignMethodECDSASHA512, crypto.SHA512},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			signer := NewECDSASigner(tc.hash, tc.name)
			data := []byte("test data for signing")

			// 签名
			signature, err := signer.Sign(data, privateKey)
			if err != nil {
				t.Fatalf("failed to sign: %v", err)
			}

			// 验证
			err = signer.Verify(data, signature, &privateKey.PublicKey)
			if err != nil {
				t.Fatalf("failed to verify: %v", err)
			}

			// 验证错误的数据
			wrongData := []byte("wrong data")
			err = signer.Verify(wrongData, signature, &privateKey.PublicKey)
			if err == nil {
				t.Fatal("expected verification to fail with wrong data")
			}
		})
	}
}

func TestEd25519Signer(t *testing.T) {
	// 生成Ed25519密钥对
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}

	signer := NewEd25519Signer(SignMethodEd25519)
	data := []byte("test data for signing")

	// 签名
	signature, err := signer.Sign(data, privateKey)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	// 验证
	err = signer.Verify(data, signature, publicKey)
	if err != nil {
		t.Fatalf("failed to verify: %v", err)
	}

	// 验证错误的数据
	wrongData := []byte("wrong data")
	err = signer.Verify(wrongData, signature, publicKey)
	if err == nil {
		t.Fatal("expected verification to fail with wrong data")
	}
}

func TestGetSigner(t *testing.T) {
	testCases := []struct {
		algorithm string
		wantErr   bool
	}{
		{SignMethodRSASHA256, false},
		{SignMethodRSASHA384, false},
		{SignMethodRSASHA512, false},
		{SignMethodECDSASHA256, false},
		{SignMethodECDSASHA384, false},
		{SignMethodECDSASHA512, false},
		{SignMethodEd25519, false},
		{"invalid", true},
	}

	for _, tc := range testCases {
		t.Run(tc.algorithm, func(t *testing.T) {
			signer, err := newSigner(tc.algorithm)
			if (err != nil) != tc.wantErr {
				t.Errorf("getSigner(%s) error = %v, wantErr %v", tc.algorithm, err, tc.wantErr)
				return
			}
			if !tc.wantErr && signer == nil {
				t.Errorf("getSigner(%s) returned nil signer", tc.algorithm)
			}
		})
	}
}
