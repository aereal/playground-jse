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

func TestIssueEncryptedToken(t *testing.T) {
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
	enc, err := NewEncrypter(privKey.Public())
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		signer    jose.Signer
		encrypter jose.Encrypter
		claims    Claims
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
				signer:    signer,
				encrypter: enc,
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
			want:    "eyJhbGciOiJSU0EtT0FFUCIsImN0eSI6IkpXVCIsImVuYyI6IkExMjhHQ00iLCJ0eXAiOiJKV1QifQ.g_AhYC1J95G1zRY8WH6qwhTrfsX2h-_BZ9NrTSa2h6Ewq7Ji-gftW8aRVr4QERc38WKEb9lfEVSpoaQ8pY93j6yMjarO8oueLZhXvulDVwCpaElWkiyx3E-_W5bL4sT-p2ARTms8EQIZMH09tB8wz-fBf54zfRDBvIaudEL9EcU.Q-R0NAHEno_BOqri.TQjBNMalw1Ble59tlMfEM9MpUxTrHR72FFKB6BG3TZXUJEVAGzxrjjOJfT6yatP68A3FZXxGKoROVp8NMjpk2sykmH_Ro1ZxVvrzVlF-RPJq8O3DJeJVWBgTWStqb2y7ms9RrHbbWwLPqYL_8cBpjrCQm0lW44PwFSk-itlapG4if3ncL8xi7Zr148hmWLRN9DLxYsrThXGDHpYyZ7iLkeyc-nJNdkBR6JL3JmUW8_i8NtVuaixFqOXVzJyfWE3__ECPNWo136T0P3QHJmIGNCnNOxBvexEA6hluwAoMQxRLvB0eDYH7pMz8KcYLmr8HmAa0gkxA8oTR14S-hMoBKxi4MLHqWqV5Ht45z4rx4nSdPj3FVLr1mJcSMKQhPeXU-ZQ4XBWRPK1Nlv_sMLXyAn38gdakansUR6FVlOj80r2YxL3f0kJf14-uhAVuMAhWuETOmXDEe4pljVp9vaxXECQbgQEnBpI3vtS6szWgP59QUvs1i2GjPxw.cE7LEhMsxcXWjXrf2qANfg",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := IssueEncryptedToken(tt.args.signer, tt.args.encrypter, tt.args.claims)
			if (err != nil) != tt.wantErr {
				t.Errorf("IssueEncryptedToken() error = %#v, wantErr %#v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("IssueEncryptedToken() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

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
