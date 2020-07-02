package key

import (
	"crypto/rsa"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

var (
	signingAlg = jose.RS512
)

type Claims = jwt.Claims

func IssueToken(signer jose.Signer, claims Claims) (string, error) {
	return jwt.Signed(signer).Claims(claims).CompactSerialize()
}

func NewSigner(privKey *rsa.PrivateKey) (jose.Signer, error) {
	opts := (&jose.SignerOptions{}).WithType("JWT")
	signingKey := jose.SigningKey{
		Algorithm: signingAlg,
		Key:       privKey,
	}
	return jose.NewSigner(signingKey, opts)
}
