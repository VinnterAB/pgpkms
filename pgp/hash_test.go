package pgp

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"gotest.tools/v3/assert"
)

func TestSigningHash(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NilError(t, err)
	p256 := generateECDSAKey(t, elliptic.P256())
	p384 := generateECDSAKey(t, elliptic.P384())
	p521 := generateECDSAKey(t, elliptic.P521())

	tests := []struct {
		name      string
		pub       crypto.PublicKey
		requested crypto.Hash
		want      crypto.Hash
	}{
		{"RSA keeps SHA-1", &rsaKey.PublicKey, crypto.SHA1, crypto.SHA1},
		{"RSA keeps SHA-256", &rsaKey.PublicKey, crypto.SHA256, crypto.SHA256},
		{"RSA keeps SHA-512", &rsaKey.PublicKey, crypto.SHA512, crypto.SHA512},
		{"P-256 keeps SHA-256", &p256.PublicKey, crypto.SHA256, crypto.SHA256},
		{"P-256 raises SHA-1", &p256.PublicKey, crypto.SHA1, crypto.SHA256},
		{"P-256 lowers SHA-384", &p256.PublicKey, crypto.SHA384, crypto.SHA256},
		{"P-256 lowers SHA-512", &p256.PublicKey, crypto.SHA512, crypto.SHA256},
		{"P-384 raises SHA-256", &p384.PublicKey, crypto.SHA256, crypto.SHA384},
		{"P-384 keeps SHA-384", &p384.PublicKey, crypto.SHA384, crypto.SHA384},
		{"P-384 lowers SHA-512", &p384.PublicKey, crypto.SHA512, crypto.SHA384},
		{"P-521 raises SHA-256", &p521.PublicKey, crypto.SHA256, crypto.SHA512},
		{"P-521 raises SHA-384", &p521.PublicKey, crypto.SHA384, crypto.SHA512},
		{"P-521 keeps SHA-512", &p521.PublicKey, crypto.SHA512, crypto.SHA512},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, SigningHash(tc.pub, tc.requested), tc.want)
		})
	}
}

func TestExportAndSignUseCurveSizedHash(t *testing.T) {
	tests := []struct {
		curve elliptic.Curve
		want  crypto.Hash
	}{
		{elliptic.P256(), crypto.SHA256},
		{elliptic.P384(), crypto.SHA384},
		{elliptic.P521(), crypto.SHA512},
	}
	for _, tc := range tests {
		t.Run(tc.curve.Params().Name, func(t *testing.T) {
			priv := generateECDSAKey(t, tc.curve)
			kmsKey := newTestKMSPublicKey(t, &priv.PublicKey)

			exported, err := Export(kmsKey, priv, false, "Test", "", "test@example.com")
			assert.NilError(t, err)
			entities, err := openpgp.ReadKeyRing(exported)
			assert.NilError(t, err)
			assert.Equal(t, len(entities), 1)
			for _, identity := range entities[0].Identities {
				assert.Equal(t, identity.SelfSignature.Hash, tc.want)
			}

			sig, err := SignData(kmsKey, priv, []byte("data"), false, false, crypto.SHA256)
			assert.NilError(t, err)
			p, err := packet.Read(bytes.NewReader(sig))
			assert.NilError(t, err)
			signature, ok := p.(*packet.Signature)
			assert.Assert(t, ok, "expected a signature packet, got %T", p)
			assert.Equal(t, signature.Hash, tc.want)
		})
	}
}

func generateECDSAKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	assert.NilError(t, err)
	return priv
}
