package pgp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	kmslib "github.com/vinnterab/pgpkms/kms"
	"gotest.tools/v3/assert"
)

// MockSigner implements crypto.Signer for testing
type MockSigner struct {
	privateKey *ecdsa.PrivateKey
}

func NewMockSigner() *MockSigner {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return &MockSigner{privateKey: privateKey}
}

func (m *MockSigner) Public() crypto.PublicKey {
	return &m.privateKey.PublicKey
}

func (m *MockSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return m.privateKey.Sign(rand, digest, opts)
}

func TestExport(t *testing.T) {
	// Create a mock KMS public key
	mockSigner := NewMockSigner()
	pubKey := mockSigner.Public().(*ecdsa.PublicKey)

	// Marshal the public key for the mock KMS data
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	assert.NilError(t, err)

	// Create mock KMS key data
	keyId := "test-key-id"
	keyArn := "arn:aws:kms:us-east-1:123456789012:key/test-key-id"
	creationDate := time.Now()

	kmsPublicKey := &kmslib.PublicKey{
		Description: &kms.DescribeKeyOutput{
			KeyMetadata: &types.KeyMetadata{
				KeyId:        &keyId,
				Arn:          &keyArn,
				CreationDate: &creationDate,
			},
		},
		Key: &kms.GetPublicKeyOutput{
			KeyId:     &keyId,
			PublicKey: pubKeyBytes,
			KeySpec:   types.KeySpecEccNistP256,
		},
	}

	t.Run("Export with custom user ID", func(t *testing.T) {
		result, err := Export(kmsPublicKey, mockSigner, false, "John Doe", "Test Comment", "john@example.com")
		assert.NilError(t, err)
		assert.Assert(t, result != nil)
		assert.Assert(t, result.Len() > 0)
	})

	t.Run("Export with ASCII armor", func(t *testing.T) {
		result, err := Export(kmsPublicKey, mockSigner, true, "John Doe", "Test Comment", "john@example.com")
		assert.NilError(t, err)
		assert.Assert(t, result != nil)
		assert.Assert(t, result.Len() > 0)

		// Check for PGP armor headers
		output := result.String()
		assert.Assert(t, strings.Contains(output, "-----BEGIN PGP PUBLIC KEY BLOCK-----"))
		assert.Assert(t, strings.Contains(output, "-----END PGP PUBLIC KEY BLOCK-----"))
	})

	t.Run("Export with default user ID", func(t *testing.T) {
		result, err := Export(kmsPublicKey, mockSigner, false, "", "", "")
		assert.NilError(t, err)
		assert.Assert(t, result != nil)
		assert.Assert(t, result.Len() > 0)
	})
}

func TestSerialize(t *testing.T) {
	// Create a mock entity for testing serialization
	mockSigner := NewMockSigner()
	pubKey := mockSigner.Public().(*ecdsa.PublicKey)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	assert.NilError(t, err)

	keyId := "test-key-id"
	keyArn := "arn:aws:kms:us-east-1:123456789012:key/test-key-id"
	creationDate := time.Now()

	kmsPublicKey := &kmslib.PublicKey{
		Description: &kms.DescribeKeyOutput{
			KeyMetadata: &types.KeyMetadata{
				KeyId:        &keyId,
				Arn:          &keyArn,
				CreationDate: &creationDate,
			},
		},
		Key: &kms.GetPublicKeyOutput{
			KeyId:     &keyId,
			PublicKey: pubKeyBytes,
			KeySpec:   types.KeySpecEccNistP256,
		},
	}

	t.Run("Serialize without armor", func(t *testing.T) {
		result, err := Export(kmsPublicKey, mockSigner, false, "Test User", "", "test@example.com")
		assert.NilError(t, err)
		assert.Assert(t, result != nil)

		// Should be binary data without armor
		output := result.String()
		assert.Assert(t, !strings.Contains(output, "-----BEGIN PGP PUBLIC KEY BLOCK-----"))
	})

	t.Run("Serialize with armor", func(t *testing.T) {
		result, err := Export(kmsPublicKey, mockSigner, true, "Test User", "", "test@example.com")
		assert.NilError(t, err)
		assert.Assert(t, result != nil)

		// Should have armor headers
		output := result.String()
		assert.Assert(t, strings.Contains(output, "-----BEGIN PGP PUBLIC KEY BLOCK-----"))
		assert.Assert(t, strings.Contains(output, "-----END PGP PUBLIC KEY BLOCK-----"))
	})
}

func TestGetKeyInfo_ECDSA(t *testing.T) {
	mockSigner := NewMockSigner()
	pubKey := mockSigner.Public().(*ecdsa.PublicKey)
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	assert.NilError(t, err)

	keyId := "test-key-id"
	keyArn := "arn:aws:kms:us-east-1:123456789012:key/test-key-id"
	creationDate := time.Date(2026, 1, 13, 12, 0, 0, 0, time.UTC)

	kmsPublicKey := &kmslib.PublicKey{
		Description: &kms.DescribeKeyOutput{
			KeyMetadata: &types.KeyMetadata{
				KeyId:        &keyId,
				Arn:          &keyArn,
				CreationDate: &creationDate,
			},
		},
		Key: &kms.GetPublicKeyOutput{
			KeyId:     &keyId,
			PublicKey: pubKeyBytes,
			KeySpec:   types.KeySpecEccNistP256,
		},
	}

	info, err := GetKeyInfo(kmsPublicKey)
	assert.NilError(t, err)
	assert.Assert(t, info.Fingerprint != [20]byte{}, "Fingerprint should not be zero")
	assert.Assert(t, info.KeyId != 0, "KeyId should not be zero")
	assert.Equal(t, info.BitLength, uint16(256))
	assert.Equal(t, info.CreationTime, creationDate)
}

func TestGetKeyInfo_RSA(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NilError(t, err)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	assert.NilError(t, err)

	keyId := "test-rsa-key"
	keyArn := "arn:aws:kms:us-east-1:123456789012:key/test-rsa-key"
	creationDate := time.Date(2026, 1, 13, 12, 0, 0, 0, time.UTC)

	kmsPublicKey := &kmslib.PublicKey{
		Description: &kms.DescribeKeyOutput{
			KeyMetadata: &types.KeyMetadata{
				KeyId:        &keyId,
				Arn:          &keyArn,
				CreationDate: &creationDate,
			},
		},
		Key: &kms.GetPublicKeyOutput{
			KeyId:     &keyId,
			PublicKey: pubKeyBytes,
			KeySpec:   types.KeySpecRsa2048,
		},
	}

	info, err := GetKeyInfo(kmsPublicKey)
	assert.NilError(t, err)
	assert.Assert(t, info.Fingerprint != [20]byte{}, "Fingerprint should not be zero")
	assert.Assert(t, info.KeyId != 0, "KeyId should not be zero")
	assert.Equal(t, info.BitLength, uint16(2048))
	assert.Equal(t, info.CreationTime, creationDate)
}

func TestGetKeyInfo_InvalidKey(t *testing.T) {
	keyId := "test-bad-key"
	keyArn := "arn:aws:kms:us-east-1:123456789012:key/test-bad-key"
	creationDate := time.Date(2026, 1, 13, 12, 0, 0, 0, time.UTC)

	kmsPublicKey := &kmslib.PublicKey{
		Description: &kms.DescribeKeyOutput{
			KeyMetadata: &types.KeyMetadata{
				KeyId:        &keyId,
				Arn:          &keyArn,
				CreationDate: &creationDate,
			},
		},
		Key: &kms.GetPublicKeyOutput{
			KeyId:     &keyId,
			PublicKey: []byte("invalid key data"),
			KeySpec:   types.KeySpecEccNistP256,
		},
	}

	_, err := GetKeyInfo(kmsPublicKey)
	assert.ErrorContains(t, err, "failed to parse public key")
}
