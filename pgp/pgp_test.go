package pgp

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	kmslib "github.com/vinnterab/pgpkms/kms"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/clearsign"
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

// Helper function to create a mock KMS public key for testing
func createMockKMSPublicKey(t *testing.T, mockSigner *MockSigner) *kmslib.PublicKey {
	pubKey := mockSigner.Public().(*ecdsa.PublicKey)
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	assert.NilError(t, err)

	keyId := "test-key-id"
	keyArn := "arn:aws:kms:us-east-1:123456789012:key/test-key-id"
	creationDate := time.Now()

	return &kmslib.PublicKey{
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
}

// Helper function to extract public key from exported PGP key
func extractPGPPublicKey(t *testing.T, exportedKey *bytes.Buffer, armored bool) openpgp.EntityList {
	var keyReader io.Reader

	if armored {
		// Decode armored public key
		armorBlock, err := armor.Decode(exportedKey)
		assert.NilError(t, err)
		assert.Equal(t, armorBlock.Type, openpgp.PublicKeyType)
		keyReader = armorBlock.Body
	} else {
		keyReader = exportedKey
	}

	// Read the PGP public key
	entityList, err := openpgp.ReadKeyRing(keyReader)
	assert.NilError(t, err)
	assert.Equal(t, len(entityList), 1)

	return entityList
}

// TestSignatureValidation tests that generated signatures can be verified
func TestSignatureValidation(t *testing.T) {
	testData := []byte("Hello, World! This is a test message for PGP signing.")

	t.Run("Binary detached signature validation", func(t *testing.T) {
		mockSigner := NewMockSigner()
		kmsPublicKey := createMockKMSPublicKey(t, mockSigner)

		// Export the public key (binary format)
		exportedKey, err := Export(kmsPublicKey, mockSigner, false, "Test User", "Test Comment", "test@example.com")
		assert.NilError(t, err)

		// Extract the PGP public key
		publicKeyRing := extractPGPPublicKey(t, exportedKey, false)

		// Sign the data (binary detached signature)
		signature, err := SignData(kmsPublicKey, mockSigner, testData, false, false, crypto.SHA256)
		assert.NilError(t, err)
		assert.Assert(t, len(signature) > 0)

		// Verify the signature
		signatureReader := bytes.NewReader(signature)
		dataReader := bytes.NewReader(testData)

		entity, err := openpgp.CheckDetachedSignature(publicKeyRing, dataReader, signatureReader)
		assert.NilError(t, err)
		assert.Assert(t, entity != nil)

		// Verify the signer identity
		assert.Assert(t, len(entity.Identities) > 0)
		for _, identity := range entity.Identities {
			assert.Assert(t, strings.Contains(identity.UserId.Id, "Test User"))
			assert.Assert(t, strings.Contains(identity.UserId.Id, "test@example.com"))
		}
	})

	t.Run("Armored detached signature validation", func(t *testing.T) {
		mockSigner := NewMockSigner()
		kmsPublicKey := createMockKMSPublicKey(t, mockSigner)

		// Export the public key (armored format)
		exportedKey, err := Export(kmsPublicKey, mockSigner, true, "Test User", "Test Comment", "test@example.com")
		assert.NilError(t, err)

		// Extract the PGP public key
		publicKeyRing := extractPGPPublicKey(t, exportedKey, true)

		// Sign the data (armored detached signature)
		signature, err := SignData(kmsPublicKey, mockSigner, testData, false, true, crypto.SHA256)
		assert.NilError(t, err)
		assert.Assert(t, len(signature) > 0)

		// Verify armored signature format
		signatureStr := string(signature)
		assert.Assert(t, strings.Contains(signatureStr, "-----BEGIN PGP SIGNATURE-----"))
		assert.Assert(t, strings.Contains(signatureStr, "-----END PGP SIGNATURE-----"))

		// Verify the signature using armored signature verification
		signatureReader := bytes.NewReader(signature)
		dataReader := bytes.NewReader(testData)

		entity, err := openpgp.CheckArmoredDetachedSignature(publicKeyRing, dataReader, signatureReader)
		assert.NilError(t, err)
		assert.Assert(t, entity != nil)

		// Verify the signer identity
		assert.Assert(t, len(entity.Identities) > 0)
		for _, identity := range entity.Identities {
			assert.Assert(t, strings.Contains(identity.UserId.Id, "Test User"))
			assert.Assert(t, strings.Contains(identity.UserId.Id, "test@example.com"))
		}
	})

	t.Run("Multiple hash algorithms validation", func(t *testing.T) {
		mockSigner := NewMockSigner()
		kmsPublicKey := createMockKMSPublicKey(t, mockSigner)

		// Export the public key
		exportedKey, err := Export(kmsPublicKey, mockSigner, false, "Test User", "", "test@example.com")
		assert.NilError(t, err)
		publicKeyRing := extractPGPPublicKey(t, exportedKey, false)

		// Test different hash algorithms
		hashAlgorithms := []crypto.Hash{
			crypto.SHA1,
			crypto.SHA256,
			crypto.SHA384,
			crypto.SHA512,
		}

		for _, hashAlgo := range hashAlgorithms {
			t.Run(fmt.Sprintf("Hash algorithm %s", hashAlgo.String()), func(t *testing.T) {
				// Sign the data with specific hash algorithm
				signature, err := SignData(kmsPublicKey, mockSigner, testData, false, false, hashAlgo)
				assert.NilError(t, err)
				assert.Assert(t, len(signature) > 0)

				// Verify the signature
				signatureReader := bytes.NewReader(signature)
				dataReader := bytes.NewReader(testData)

				entity, err := openpgp.CheckDetachedSignature(publicKeyRing, dataReader, signatureReader)
				assert.NilError(t, err)
				assert.Assert(t, entity != nil)
			})
		}
	})

	t.Run("Clear-signed message validation", func(t *testing.T) {
		mockSigner := NewMockSigner()
		kmsPublicKey := createMockKMSPublicKey(t, mockSigner)

		// Export the public key
		exportedKey, err := Export(kmsPublicKey, mockSigner, false, "Test User", "", "test@example.com")
		assert.NilError(t, err)
		publicKeyRing := extractPGPPublicKey(t, exportedKey, false)

		// Sign the data (clear-sign format)
		signature, err := SignData(kmsPublicKey, mockSigner, testData, true, false, crypto.SHA256)
		assert.NilError(t, err)
		assert.Assert(t, len(signature) > 0)

		// Verify clear-signed message format
		signatureStr := string(signature)
		assert.Assert(t, strings.Contains(signatureStr, "-----BEGIN PGP SIGNED MESSAGE-----"))
		assert.Assert(t, strings.Contains(signatureStr, "-----BEGIN PGP SIGNATURE-----"))
		assert.Assert(t, strings.Contains(signatureStr, "-----END PGP SIGNATURE-----"))

		// Verify the clear-signed message contains the original data
		assert.Assert(t, strings.Contains(signatureStr, string(testData)))

		// Verify the clear-signed message using clearsign verification
		block, _ := clearsign.Decode(signature)
		assert.Assert(t, block != nil)

		// Check that the plaintext matches original data (clearsign may add a newline)
		plaintext := strings.TrimRight(string(block.Plaintext), "\n")
		assert.Equal(t, plaintext, string(testData))

		// Verify the signature on the cleartext
		entity, err := openpgp.CheckDetachedSignature(publicKeyRing, bytes.NewReader(block.Bytes), block.ArmoredSignature.Body)
		assert.NilError(t, err)
		assert.Assert(t, entity != nil)

		// Verify the signer identity
		assert.Assert(t, len(entity.Identities) > 0)
		for _, identity := range entity.Identities {
			assert.Assert(t, strings.Contains(identity.UserId.Id, "Test User"))
		}
	})

	t.Run("Invalid signature should fail verification", func(t *testing.T) {
		mockSigner := NewMockSigner()
		kmsPublicKey := createMockKMSPublicKey(t, mockSigner)

		// Export the public key
		exportedKey, err := Export(kmsPublicKey, mockSigner, false, "Test User", "", "test@example.com")
		assert.NilError(t, err)
		publicKeyRing := extractPGPPublicKey(t, exportedKey, false)

		// Sign the data
		signature, err := SignData(kmsPublicKey, mockSigner, testData, false, false, crypto.SHA256)
		assert.NilError(t, err)

		// Modify the signature to make it invalid
		invalidSignature := make([]byte, len(signature))
		copy(invalidSignature, signature)
		invalidSignature[len(invalidSignature)-1] ^= 0xFF // Flip last byte

		// Attempt to verify the invalid signature
		signatureReader := bytes.NewReader(invalidSignature)
		dataReader := bytes.NewReader(testData)

		_, err = openpgp.CheckDetachedSignature(publicKeyRing, dataReader, signatureReader)
		assert.Assert(t, err != nil) // Should fail verification
	})

	t.Run("Wrong data should fail verification", func(t *testing.T) {
		mockSigner := NewMockSigner()
		kmsPublicKey := createMockKMSPublicKey(t, mockSigner)

		// Export the public key
		exportedKey, err := Export(kmsPublicKey, mockSigner, false, "Test User", "", "test@example.com")
		assert.NilError(t, err)
		publicKeyRing := extractPGPPublicKey(t, exportedKey, false)

		// Sign the data
		signature, err := SignData(kmsPublicKey, mockSigner, testData, false, false, crypto.SHA256)
		assert.NilError(t, err)

		// Try to verify with different data
		wrongData := []byte("This is different data that should fail verification")
		signatureReader := bytes.NewReader(signature)
		dataReader := bytes.NewReader(wrongData)

		_, err = openpgp.CheckDetachedSignature(publicKeyRing, dataReader, signatureReader)
		assert.Assert(t, err != nil) // Should fail verification
	})
}
