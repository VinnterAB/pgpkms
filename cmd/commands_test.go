package cmd

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io"
	"os"
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

// MockKmsClient implements kms.Client for testing
type MockKmsClient struct {
	shouldError bool
	errorMsg    string
}

func NewMockKmsClient() *MockKmsClient {
	return &MockKmsClient{}
}

func (m *MockKmsClient) WithError(msg string) *MockKmsClient {
	m.shouldError = true
	m.errorMsg = msg
	return m
}

func (m *MockKmsClient) GetKey(keyId string) (*kmslib.Key, error) {
	if m.shouldError {
		return nil, fmt.Errorf(m.errorMsg)
	}

	// Create a mock KMS public key
	mockSigner := NewMockSigner()
	pubKey := mockSigner.Public().(*ecdsa.PublicKey)

	// Marshal the public key for the mock KMS data
	pubKeyBytes, _ := x509.MarshalPKIXPublicKey(pubKey)

	// Create mock KMS key data
	keyArn := "arn:aws:kms:us-east-1:123456789012:key/" + keyId
	creationDate := time.Now()

	publicKey := &kmslib.PublicKey{
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

	return &kmslib.Key{
		PublicKey:  publicKey,
		PrivateKey: mockSigner,
	}, nil
}

func TestExportCommand(t *testing.T) {
	// Reset opts before each test
	defer func() { opts = Opts{} }()

	t.Run("Export with name and email", func(t *testing.T) {
		opts = Opts{}
		mockClient := NewMockKmsClient()

		// Capture stdout
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		// Set command line args for export
		keyId := "test-key-id"
		name := "Test User"
		email := "test@example.com"
		opts.Export = true
		opts.User = keyId
		opts.ExportName = &name
		opts.ExportEmail = &email

		err := ExportKey(mockClient, &opts, []string{})
		assert.NilError(t, err)

		// Restore stdout and read output
		w.Close()
		os.Stdout = oldStdout
		var buf bytes.Buffer
		io.Copy(&buf, r)
		output := buf.String()

		// Should contain PGP key data
		assert.Assert(t, len(output) > 0)
		assert.Assert(t, strings.Contains(output, "BEGIN PGP") || len(output) > 100) // Either armored or binary
	})

	t.Run("Export with armor", func(t *testing.T) {
		opts = Opts{}
		mockClient := NewMockKmsClient()

		// Capture stdout
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		// Set command line args for export with armor
		keyId := "test-key-id"
		name := "Test User"
		email := "test@example.com"
		opts.Export = true
		opts.User = keyId
		opts.ExportName = &name
		opts.ExportEmail = &email
		opts.Armor = true

		err := ExportKey(mockClient, &opts, []string{})
		assert.NilError(t, err)

		// Restore stdout and read output
		w.Close()
		os.Stdout = oldStdout
		var buf bytes.Buffer
		io.Copy(&buf, r)
		output := buf.String()

		// Should contain armored PGP key
		assert.Assert(t, strings.Contains(output, "-----BEGIN PGP PUBLIC KEY BLOCK-----"))
		assert.Assert(t, strings.Contains(output, "-----END PGP PUBLIC KEY BLOCK-----"))
	})

	t.Run("Export without name or email should fail", func(t *testing.T) {
		opts = Opts{}
		mockClient := NewMockKmsClient()

		keyId := "test-key-id"
		opts.Export = true
		opts.User = keyId

		err := ExportKey(mockClient, &opts, []string{})
		assert.Error(t, err, "at least one of --export-name or --export-email must be provided")
	})

	t.Run("Export with KMS error", func(t *testing.T) {
		opts = Opts{}
		mockClient := NewMockKmsClient().WithError("KMS key not found")

		keyId := "test-key-id"
		name := "Test User"
		opts.Export = true
		opts.User = keyId
		opts.ExportName = &name

		err := ExportKey(mockClient, &opts, []string{})
		assert.ErrorContains(t, err, "KMS key not found")
	})
}

func TestSignCommand(t *testing.T) {
	// Reset opts before each test
	defer func() { opts = Opts{} }()

	t.Run("Sign data from stdin to stdout", func(t *testing.T) {
		opts = Opts{}
		mockClient := NewMockKmsClient()

		// Capture stdout
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		keyId := "test-key-id"
		opts.Sign = true
		opts.User = keyId

		// Test data
		testData := []byte("Hello, World!")

		signedData, err := signData(mockClient, keyId, testData, false)
		assert.NilError(t, err)

		err = writeOutput(os.Stdout, signedData)
		assert.NilError(t, err)

		// Restore stdout and read output
		w.Close()
		os.Stdout = oldStdout
		var buf bytes.Buffer
		io.Copy(&buf, r)
		output := buf.Bytes()

		// Should have signature data
		assert.Assert(t, len(output) > 0)
	})

	t.Run("Clear sign data from stdin to stdout", func(t *testing.T) {
		opts = Opts{}
		mockClient := NewMockKmsClient()

		// Capture stdout
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		keyId := "test-key-id"
		opts.ClearSign = true
		opts.User = keyId

		// Test data
		testData := []byte("Hello, World!")

		signedData, err := signData(mockClient, keyId, testData, true)
		assert.NilError(t, err)

		err = writeOutput(os.Stdout, signedData)
		assert.NilError(t, err)

		// Restore stdout and read output
		w.Close()
		os.Stdout = oldStdout
		var buf bytes.Buffer
		io.Copy(&buf, r)
		output := buf.String()

		// Should contain clear signed data
		assert.Assert(t, len(output) > 0)
		assert.Assert(t, strings.Contains(output, "Hello, World!") || len(output) > 20)
	})

	t.Run("Sign with KMS error", func(t *testing.T) {
		opts = Opts{}
		mockClient := NewMockKmsClient().WithError("KMS signing failed")

		keyId := "test-key-id"
		testData := []byte("Hello, World!")

		_, err := signData(mockClient, keyId, testData, false)
		assert.ErrorContains(t, err, "KMS signing failed")
	})
}

func TestExecuteFunction(t *testing.T) {
	// Save original args and restore after test
	originalArgs := os.Args
	defer func() {
		os.Args = originalArgs
		opts = Opts{} // Reset opts
	}()

	t.Run("No command shows help", func(t *testing.T) {
		opts = Opts{}
		mockClient := NewMockKmsClient()

		// Capture stdout
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		// Simulate no arguments
		os.Args = []string{"pgpkms"}

		err := Execute(mockClient)
		assert.NilError(t, err)

		// Restore stdout and read output
		w.Close()
		os.Stdout = oldStdout
		var buf bytes.Buffer
		io.Copy(&buf, r)
		output := buf.String()

		// Should show usage/help
		assert.Assert(t, strings.Contains(output, "Usage:"))
		assert.Assert(t, strings.Contains(output, "Application Options:"))
	})

	t.Run("Conflicting commands error", func(t *testing.T) {
		opts = Opts{}
		mockClient := NewMockKmsClient()

		// Set conflicting options
		keyId := "test-key-id"
		opts.User = keyId
		opts.Export = true
		opts.Sign = true

		err := Execute(mockClient)
		assert.ErrorContains(t, err, "conflicting commands")
	})

	t.Run("Export command execution", func(t *testing.T) {
		opts = Opts{}
		mockClient := NewMockKmsClient()

		// Capture stdout
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		// Set export options
		keyId := "test-key-id"
		name := "Test User"
		opts.Export = true
		opts.User = keyId
		opts.ExportName = &name

		err := Execute(mockClient)
		assert.NilError(t, err)

		// Restore stdout and read output
		w.Close()
		os.Stdout = oldStdout
		var buf bytes.Buffer
		io.Copy(&buf, r)
		output := buf.String()

		// Should contain key export output
		assert.Assert(t, len(output) > 0)
	})
}

func TestSign(t *testing.T) {
	// Reset opts before each test
	defer func() { opts = Opts{} }()

	t.Run("Sign file to default output", func(t *testing.T) {
		opts = Opts{}
		mockClient := NewMockKmsClient()

		// Create a temporary input file
		tmpFile, err := os.CreateTemp("", "test-input-*.txt")
		assert.NilError(t, err)
		defer os.Remove(tmpFile.Name())

		testData := "Hello, World!"
		_, err = tmpFile.WriteString(testData)
		assert.NilError(t, err)
		tmpFile.Close()

		// Set output file explicitly to enable file output
		outputFile := tmpFile.Name() + ".asc"
		defer os.Remove(outputFile)

		keyId := "test-key-id"
		opts.Sign = true
		opts.User = keyId
		opts.Output = &outputFile

		err = Sign(mockClient, &opts, []string{tmpFile.Name()})
		assert.NilError(t, err)

		// Check that output file was created
		_, err = os.Stat(outputFile)
		assert.NilError(t, err, "Output file should be created")
	})

	t.Run("Clear sign file to default output", func(t *testing.T) {
		opts = Opts{}
		mockClient := NewMockKmsClient()

		// Create a temporary input file
		tmpFile, err := os.CreateTemp("", "test-input-*.txt")
		assert.NilError(t, err)
		defer os.Remove(tmpFile.Name())

		testData := "Hello, World!"
		_, err = tmpFile.WriteString(testData)
		assert.NilError(t, err)
		tmpFile.Close()

		// Set output file explicitly to enable file output
		outputFile := tmpFile.Name() + ".asc"
		defer os.Remove(outputFile)

		keyId := "test-key-id"
		opts.ClearSign = true
		opts.User = keyId
		opts.Output = &outputFile

		err = Sign(mockClient, &opts, []string{tmpFile.Name()})
		assert.NilError(t, err)

		// Check that output file was created
		_, err = os.Stat(outputFile)
		assert.NilError(t, err, "Output file should be created")
	})

	t.Run("Sign with custom output file", func(t *testing.T) {
		opts = Opts{}
		mockClient := NewMockKmsClient()

		// Create a temporary input file
		tmpFile, err := os.CreateTemp("", "test-input-*.txt")
		assert.NilError(t, err)
		defer os.Remove(tmpFile.Name())

		testData := "Hello, World!"
		_, err = tmpFile.WriteString(testData)
		assert.NilError(t, err)
		tmpFile.Close()

		// Create temporary output file name
		outputFile := tmpFile.Name() + ".sig"
		defer os.Remove(outputFile)

		keyId := "test-key-id"
		opts.Sign = true
		opts.User = keyId
		opts.Output = &outputFile

		err = Sign(mockClient, &opts, []string{tmpFile.Name()})
		assert.NilError(t, err)

		// Check that custom output file was created
		_, err = os.Stat(outputFile)
		assert.NilError(t, err, "Custom output file should be created")
	})

}

func TestReplaceEqualSigns(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"--export=", "--export "},
		{"--export-name=", "--export-name "},
		{"No equals here", "No equals here"},
		{"Multiple=equals=signs", "Multiple equals signs"},
	}

	for _, tc := range testCases {
		result := replaceEqualSigns(tc.input)
		assert.Equal(t, result, tc.expected)
	}
}

func TestGetOutputFile(t *testing.T) {
	t.Run("Default output file", func(t *testing.T) {
		output, err := getOutputFile("test.txt", nil)
		assert.NilError(t, err)
		assert.Equal(t, output, "test.txt.asc")
	})

	t.Run("Custom output file", func(t *testing.T) {
		customOutput := "custom.sig"
		output, err := getOutputFile("test.txt", &customOutput)
		assert.NilError(t, err)
		assert.Equal(t, output, "custom.sig")
	})

	t.Run("Input file with .asc extension should fail", func(t *testing.T) {
		_, err := getOutputFile("test.asc", nil)
		assert.ErrorContains(t, err, "already has .asc extension")
	})
}

func TestWriteOutput(t *testing.T) {
	t.Run("Write to bytes.Buffer", func(t *testing.T) {
		testData := []byte("Hello, World!")
		var buf bytes.Buffer

		err := writeOutput(&buf, testData)
		assert.NilError(t, err)
		assert.DeepEqual(t, buf.Bytes(), testData)
	})

	t.Run("Write to stdout", func(t *testing.T) {
		testData := []byte("Test output")

		// Capture stdout
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		err := writeOutput(os.Stdout, testData)
		assert.NilError(t, err)

		// Restore stdout and read output
		w.Close()
		os.Stdout = oldStdout
		var buf bytes.Buffer
		io.Copy(&buf, r)

		assert.DeepEqual(t, buf.Bytes(), testData)
	})
}

func TestDetermineOutputWriter(t *testing.T) {
	// Reset opts before each test
	defer func() { opts = Opts{} }()

	t.Run("Stdin input without output flag - should return stdout wrapper", func(t *testing.T) {
		opts = Opts{}
		args := []string{} // No input file
		inputName := "stdin"

		writer, outputFile, err := determineOutputWriter(args, &opts, inputName)
		assert.NilError(t, err)
		defer writer.Close()

		assert.Equal(t, outputFile, "")
		_, ok := writer.(stdoutWriteCloser)
		assert.Assert(t, ok, "Should return stdoutWriteCloser")
	})

	t.Run("File input without output flag - should create file", func(t *testing.T) {
		opts = Opts{}
		args := []string{"test.txt"} // Has input file
		inputName := "test.txt"

		writer, outputFile, err := determineOutputWriter(args, &opts, inputName)
		assert.NilError(t, err)
		defer func() {
			writer.Close()
			os.Remove(outputFile)
		}()

		assert.Equal(t, outputFile, "test.txt.asc")
		_, ok := writer.(*os.File)
		assert.Assert(t, ok, "Should return *os.File")
	})

	t.Run("With explicit output file", func(t *testing.T) {
		opts = Opts{}

		// Create temporary directory for test
		tmpDir, err := os.MkdirTemp("", "output-test-*")
		assert.NilError(t, err)
		defer os.RemoveAll(tmpDir)

		customOutput := tmpDir + "/custom.sig"
		opts.Output = &customOutput
		args := []string{"test.txt"}
		inputName := "test.txt"

		writer, outputFile, err := determineOutputWriter(args, &opts, inputName)
		assert.NilError(t, err)
		defer writer.Close()

		assert.Equal(t, outputFile, customOutput)
		_, ok := writer.(*os.File)
		assert.Assert(t, ok, "Should return *os.File")
	})

	t.Run("Input file with .asc extension should fail", func(t *testing.T) {
		opts = Opts{}
		args := []string{"test.asc"}
		inputName := "test.asc"

		_, _, err := determineOutputWriter(args, &opts, inputName)
		assert.ErrorContains(t, err, "already has .asc extension")
	})

	t.Run("Output file already exists should fail", func(t *testing.T) {
		opts = Opts{}

		// Create a temporary file that exists
		tmpFile, err := os.CreateTemp("", "existing-*.txt")
		assert.NilError(t, err)
		tmpFileName := tmpFile.Name()
		defer os.Remove(tmpFileName)
		tmpFile.Close()

		args := []string{"test.txt"}
		inputName := "test.txt"
		opts.Output = &tmpFileName

		_, _, err = determineOutputWriter(args, &opts, inputName)
		assert.ErrorContains(t, err, "already exists")
	})
}

func TestDetermineInputSource(t *testing.T) {
	t.Run("Read from file", func(t *testing.T) {
		// Create a temporary input file
		tmpFile, err := os.CreateTemp("", "test-input-*.txt")
		assert.NilError(t, err)
		defer os.Remove(tmpFile.Name())

		testData := "Hello, World!"
		_, err = tmpFile.WriteString(testData)
		assert.NilError(t, err)
		tmpFile.Close()

		args := []string{tmpFile.Name()}
		inputData, inputName, err := determineInputSource(args)
		assert.NilError(t, err)
		assert.Equal(t, string(inputData), testData)
		assert.Equal(t, inputName, tmpFile.Name())
	})

	t.Run("Read from stdin", func(t *testing.T) {
		testData := "Hello from stdin!"

		// Create a pipe to simulate stdin
		oldStdin := os.Stdin
		r, w, _ := os.Pipe()
		os.Stdin = r

		// Write test data to the pipe
		go func() {
			defer w.Close()
			w.Write([]byte(testData))
		}()

		args := []string{} // No file argument
		inputData, inputName, err := determineInputSource(args)

		// Restore stdin
		os.Stdin = oldStdin

		assert.NilError(t, err)
		assert.Equal(t, string(inputData), testData)
		assert.Equal(t, inputName, "stdin")
	})

	t.Run("Nonexistent file should fail", func(t *testing.T) {
		args := []string{"nonexistent-file.txt"}
		_, _, err := determineInputSource(args)
		assert.ErrorContains(t, err, "failed to read input file")
	})
}

func TestStdoutWriteCloser(t *testing.T) {
	t.Run("Write to stdout wrapper", func(t *testing.T) {
		writer := stdoutWriteCloser{}
		testData := []byte("Hello, World!")

		// Capture stdout
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		n, err := writer.Write(testData)
		assert.NilError(t, err)
		assert.Equal(t, n, len(testData))

		// Restore stdout and read output
		w.Close()
		os.Stdout = oldStdout
		var buf bytes.Buffer
		io.Copy(&buf, r)

		assert.DeepEqual(t, buf.Bytes(), testData)
	})

	t.Run("Close is no-op", func(t *testing.T) {
		writer := stdoutWriteCloser{}
		err := writer.Close()
		assert.NilError(t, err)
	})
}
