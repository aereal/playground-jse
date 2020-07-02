package key

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func TestIssueToken(t *testing.T) {
	loc, err := time.LoadLocation("Asia/Tokyo")
	if err != nil {
		t.Fatal(err)
	}
	issuedAt, err := time.ParseInLocation(time.RFC3339, "2006-01-02T15:04:05Z", loc)
	if err != nil {
		t.Fatal(err)
	}
	expiry := issuedAt.Add(time.Hour)

	privKey, err := loadOrCreateKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewSigner(privKey)
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		signer jose.Signer
		claims Claims
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "ok",
			args: args{
				signer: signer,
				claims: Claims{
					Issuer:    "iss.example.com",
					Subject:   "sub",
					Audience:  jwt.Audience{"aud.example.com"},
					ID:        "123",
					Expiry:    jwt.NewNumericDate(expiry),
					NotBefore: jwt.NewNumericDate(issuedAt),
					IssuedAt:  jwt.NewNumericDate(issuedAt),
				},
			},
			want:    "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsiYXVkLmV4YW1wbGUuY29tIl0sImV4cCI6MTEzNjIxNzg0NSwiaWF0IjoxMTM2MjE0MjQ1LCJpc3MiOiJpc3MuZXhhbXBsZS5jb20iLCJqdGkiOiIxMjMiLCJuYmYiOjExMzYyMTQyNDUsInN1YiI6InN1YiJ9.RJ-olLFVasC75WVQjE2I10QUUicm0yS728Fn7C8P5Wj70gU42ckVneTbZZuK2EkyNDT6yge2ECeWTOZ5rRibdPGxPWy2t6momFLuFn8x8cEpGXvMANlqIdd6xN0mM2fEsJArKi71X_dR3CZP_xX92sTUP43-J3r5glJUYSJ2vKw",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := IssueToken(tt.args.signer, tt.args.claims)
			if (err != nil) != tt.wantErr {
				t.Errorf("IssueToken() error = %#v, wantErr %#v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("IssueToken() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func loadOrCreateKey() (*rsa.PrivateKey, error) {
	pkeyPath := "test-private.pem"
	f, err := os.Open(pkeyPath)
	if err != nil {
		pkey, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			return nil, err
		}
		if err := savePrivateKey(pkeyPath, pkey); err != nil {
			return nil, err
		}
		return pkey, nil
	}
	defer f.Close()
	k, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}
	return parseRSAPrivateKey(k)
}

func savePrivateKey(pkeyPath string, privKey *rsa.PrivateKey) error {
	f, err := os.Create(pkeyPath)
	if err != nil {
		return err
	}
	defer f.Close()
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	}
	if err := pem.Encode(f, block); err != nil {
		return err
	}
	return nil
}

func parseRSAPrivateKey(key []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, fmt.Errorf("invalid key format")
	}
	var (
		err    error
		parsed interface{}
	)
	parsed, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	}
	if pkey, ok := parsed.(*rsa.PrivateKey); ok {
		return pkey, nil
	}
	return nil, fmt.Errorf("key is not RSA key")
}
