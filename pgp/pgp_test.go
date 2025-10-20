package pgp

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmsTypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	kmslib "github.com/vinnterab/pgpkms/kms"
	"gotest.tools/v3/assert"
)

// MockSigner implements crypto.Signer using an RSA key for testing
type MockSigner struct {
	privateKey *rsa.PrivateKey
}

func NewMockSigner() *MockSigner {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	return &MockSigner{privateKey: privKey}
}

func (m *MockSigner) Public() crypto.PublicKey {
	return &m.privateKey.PublicKey
}

func (m *MockSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return m.privateKey.Sign(rand, digest, opts)
}

func TestExport(t *testing.T) {
	mockSigner := NewMockSigner()
	pubKey := mockSigner.Public().(*rsa.PublicKey)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	assert.NilError(t, err)

	keyId := "test-key-id"
	keyArn := "arn:aws:kms:us-east-1:123456789012:key/test-key-id"
	creationDate := time.Now()

	kmsPublicKey := &kmslib.PublicKey{
		Description: &kms.DescribeKeyOutput{
			KeyMetadata: &kmsTypes.KeyMetadata{
				KeyId:        &keyId,
				Arn:          &keyArn,
				CreationDate: &creationDate,
			},
		},
		Key: &kms.GetPublicKeyOutput{
			KeyId:     &keyId,
			PublicKey: pubKeyBytes,
			KeySpec:   kmsTypes.KeySpec("RSA_2048"), // Fixed KeySpec
		},
	}

	t.Run("Export with custom user ID", func(t *testing.T) {
		result, err := Export(kmsPublicKey, mockSigner, false, "John Doe", "Test Comment", "john@example.com")
		assert.NilError(t, err)
		assert.Assert(t, result.Len() > 0)
	})

	t.Run("Export with ASCII armor", func(t *testing.T) {
		result, err := Export(kmsPublicKey, mockSigner, true, "John Doe", "Test Comment", "john@example.com")
		assert.NilError(t, err)
		output := result.String()
		assert.Assert(t, strings.Contains(output, "-----BEGIN PGP PUBLIC KEY BLOCK-----"))
		assert.Assert(t, strings.Contains(output, "-----END PGP PUBLIC KEY BLOCK-----"))
	})

	t.Run("Export with default user ID", func(t *testing.T) {
		result, err := Export(kmsPublicKey, mockSigner, false, "", "", "")
		assert.NilError(t, err)
		assert.Assert(t, result.Len() > 0)
	})
}

func TestSerialize(t *testing.T) {
	mockSigner := NewMockSigner()
	pubKey := mockSigner.Public().(*rsa.PublicKey)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	assert.NilError(t, err)

	keyId := "test-key-id"
	keyArn := "arn:aws:kms:us-east-1:123456789012:key/test-key-id"
	creationDate := time.Now()

	kmsPublicKey := &kmslib.PublicKey{
		Description: &kms.DescribeKeyOutput{
			KeyMetadata: &kmsTypes.KeyMetadata{
				KeyId:        &keyId,
				Arn:          &keyArn,
				CreationDate: &creationDate,
			},
		},
		Key: &kms.GetPublicKeyOutput{
			KeyId:     &keyId,
			PublicKey: pubKeyBytes,
			KeySpec:   kmsTypes.KeySpec("RSA_2048"), // Fixed KeySpec
		},
	}

	t.Run("Serialize without armor", func(t *testing.T) {
		result, err := Export(kmsPublicKey, mockSigner, false, "Test User", "", "test@example.com")
		assert.NilError(t, err)
		output := result.String()
		assert.Assert(t, !strings.Contains(output, "-----BEGIN PGP PUBLIC KEY BLOCK-----"))
	})

	t.Run("Serialize with armor", func(t *testing.T) {
		result, err := Export(kmsPublicKey, mockSigner, true, "Test User", "", "test@example.com")
		assert.NilError(t, err)
		output := result.String()
		assert.Assert(t, strings.Contains(output, "-----BEGIN PGP PUBLIC KEY BLOCK-----"))
		assert.Assert(t, strings.Contains(output, "-----END PGP PUBLIC KEY BLOCK-----"))
	})
}
