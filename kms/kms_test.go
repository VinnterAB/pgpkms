package kms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"gotest.tools/v3/assert"
)

// MockClient implements the Client interface for testing
type MockClient struct {
	getKeyFunc func(keyId string) (*Key, error)
}

func (m *MockClient) GetKey(keyId string) (*Key, error) {
	if m.getKeyFunc != nil {
		return m.getKeyFunc(keyId)
	}

	// Default implementation - create a mock key
	privateKey, pubKeyBytes, err := createTestECDSAKey()
	if err != nil {
		return nil, err
	}

	keyArn := "arn:aws:kms:us-east-1:123456789012:key/" + keyId
	creationDate := time.Now()

	publicKey := &PublicKey{
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

	return &Key{
		PublicKey:  publicKey,
		PrivateKey: &TestSigner{privateKey: privateKey},
	}, nil
}

// TestSigner implements crypto.Signer for testing
type TestSigner struct {
	privateKey *ecdsa.PrivateKey
}

func (s *TestSigner) Public() crypto.PublicKey {
	return &s.privateKey.PublicKey
}

func (s *TestSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.privateKey.Sign(rand, digest, opts)
}

// Helper function to create a valid ECDSA public key for testing
func createTestECDSAKey() (*ecdsa.PrivateKey, []byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	return privateKey, pubKeyBytes, nil
}

// Helper function to create a valid RSA public key for testing
func createTestRSAKey() ([]byte, error) {
	// For simplicity, we'll create an ECDSA key and marshal it
	// In a real scenario, you'd create an RSA key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
}

func TestNewAWSKmsClient(t *testing.T) {
	// Create a minimal AWS config for testing
	cfg := aws.Config{
		Region: "us-east-1",
	}

	client := NewAWSKmsClient(cfg)
	assert.Assert(t, client != nil, "Client should not be nil")
	assert.Assert(t, client.client != nil, "Underlying KMS client should not be nil")
}

func TestPublicKey_GetKeyId(t *testing.T) {
	keyId := "test-key-id-12345"
	publicKey := &PublicKey{
		Description: &kms.DescribeKeyOutput{
			KeyMetadata: &types.KeyMetadata{
				KeyId: &keyId,
			},
		},
	}

	result := publicKey.GetKeyId()
	assert.Equal(t, result, keyId)
}

func TestMockClient_GetKey_Success(t *testing.T) {
	testKeyId := "test-key-id"

	mockClient := &MockClient{}
	key, err := mockClient.GetKey(testKeyId)

	assert.NilError(t, err)
	assert.Assert(t, key != nil)
	assert.Assert(t, key.PublicKey != nil)
	assert.Assert(t, key.PrivateKey != nil)
	assert.Equal(t, key.PublicKey.GetKeyId(), testKeyId)
}

func TestMockClient_GetKey_Error(t *testing.T) {
	testKeyId := "test-key-id"

	mockClient := &MockClient{
		getKeyFunc: func(keyId string) (*Key, error) {
			return nil, fmt.Errorf("mock error: key not found")
		},
	}

	_, err := mockClient.GetKey(testKeyId)
	assert.ErrorContains(t, err, "mock error")
}

func TestKMSSigner_Public(t *testing.T) {
	// Create test key data
	privateKey, pubKeyBytes, err := createTestECDSAKey()
	assert.NilError(t, err)

	publicKey := &PublicKey{
		Key: &kms.GetPublicKeyOutput{
			PublicKey: pubKeyBytes,
			KeySpec:   types.KeySpecEccNistP256,
		},
	}

	signer := &KMSSigner{
		keyId:     "test-key",
		publicKey: publicKey,
	}

	pubKey := signer.Public()
	assert.Assert(t, pubKey != nil)

	// Verify it's the same public key
	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	assert.Assert(t, ok, "Public key should be ECDSA")
	assert.Assert(t, ecdsaPubKey.Equal(&privateKey.PublicKey), "Public keys should match")
}

func TestKMSSigner_Public_InvalidKey(t *testing.T) {
	publicKey := &PublicKey{
		Key: &kms.GetPublicKeyOutput{
			PublicKey: []byte("invalid key data"),
			KeySpec:   types.KeySpecEccNistP256,
		},
	}

	signer := &KMSSigner{
		keyId:     "test-key",
		publicKey: publicKey,
	}

	// This should panic due to invalid key data
	defer func() {
		if r := recover(); r != nil {
			// Panic occurred as expected
		} else {
			t.Error("Expected panic did not occur")
		}
	}()
	signer.Public()
}
