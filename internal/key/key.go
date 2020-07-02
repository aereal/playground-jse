package key

import (
	"crypto"
	"crypto/rsa"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

var (
	signingAlg = jose.RS512
	encAlg     = jose.A128GCM
	recpAlg    = jose.RSA_OAEP
)

type Claims = jwt.Claims

func IssueToken(signer jose.Signer, claims Claims) (string, error) {
	return jwt.Signed(signer).Claims(claims).CompactSerialize()
}

func IssueEncryptedToken(signer jose.Signer, encrypter jose.Encrypter, claims Claims) (string, error) {
	builder := jwt.SignedAndEncrypted(signer, encrypter)
	return builder.Claims(claims).CompactSerialize()
}

func NewSigner(privKey *rsa.PrivateKey) (jose.Signer, error) {
	opts := (&jose.SignerOptions{}).WithType("JWT")
	signingKey := jose.SigningKey{
		Algorithm: signingAlg,
		Key:       privKey,
	}
	return jose.NewSigner(signingKey, opts)
}

func NewEncrypter(publicKey crypto.PublicKey) (jose.Encrypter, error) {
	opts := (&jose.EncrypterOptions{}).WithContentType("JWT").WithType("JWT")
	recp := jose.Recipient{
		Key:       publicKey,
		Algorithm: recpAlg,
	}
	return jose.NewEncrypter(encAlg, recp, opts)
}
