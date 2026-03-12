package cmd

import (
	"bytes"
	"crypto"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"gotest.tools/v3/assert"
)

func TestStatusWriterEmit(t *testing.T) {
	r, w, err := os.Pipe()
	assert.NilError(t, err)
	defer r.Close()

	fd := int(w.Fd())
	sw := NewStatusWriter(&fd, false)

	sw.Emit("KEY_CONSIDERED", "ABCD1234", "0")
	sw.Emit("BEGIN_SIGNING", "H8")
	w.Close()

	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	assert.NilError(t, err)

	output := buf.String()
	assert.Assert(t, strings.Contains(output, "[GNUPG:] KEY_CONSIDERED ABCD1234 0\n"))
	assert.Assert(t, strings.Contains(output, "[GNUPG:] BEGIN_SIGNING H8\n"))
}

func TestStatusWriterEmitNoArgs(t *testing.T) {
	r, w, err := os.Pipe()
	assert.NilError(t, err)
	defer r.Close()

	fd := int(w.Fd())
	sw := NewStatusWriter(&fd, false)

	sw.Emit("GOODSIG")
	w.Close()

	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	assert.NilError(t, err)

	assert.Equal(t, buf.String(), "[GNUPG:] GOODSIG\n")
}

func TestStatusWriterInactive(t *testing.T) {
	sw := NewStatusWriter(nil, false)

	// Should not panic or do anything
	sw.Emit("KEY_CONSIDERED", "ABCD1234", "0")
	sw.Close()
}

func TestStatusWriterExitOnError(t *testing.T) {
	r, w, err := os.Pipe()
	assert.NilError(t, err)

	fd := int(w.Fd())
	sw := NewStatusWriter(&fd, true)

	// Close the write end so writing will fail
	w.Close()
	r.Close()

	var exitCode int
	var exitCalled bool
	sw.exitFunc = func(code int) {
		exitCode = code
		exitCalled = true
	}

	sw.Emit("TEST_CODE", "arg1")
	assert.Assert(t, exitCalled, "exitFunc should have been called")
	assert.Equal(t, exitCode, 2)
}

func TestStatusWriterNoExitOnError(t *testing.T) {
	r, w, err := os.Pipe()
	assert.NilError(t, err)

	fd := int(w.Fd())
	sw := NewStatusWriter(&fd, false)

	// Capture stderr before closing the pipe
	oldStderr := os.Stderr
	sr, sw2, _ := os.Pipe()
	os.Stderr = sw2

	// Close the pipe so writing will fail
	// Close sw.file directly since it wraps the same fd
	sw.file.Close()
	r.Close()

	sw.Emit("TEST_CODE", "arg1")

	sw2.Close()
	os.Stderr = oldStderr

	var buf bytes.Buffer
	io.Copy(&buf, sr)
	sr.Close()

	assert.Assert(t, strings.Contains(buf.String(), "status-fd write error"))
}

func TestStatusWriterClose(t *testing.T) {
	r, w, err := os.Pipe()
	assert.NilError(t, err)
	defer r.Close()

	fd := int(w.Fd())
	sw := NewStatusWriter(&fd, false)
	sw.Close()

	// Writing after close should fail — verify the fd is closed
	_, err = w.WriteString("test")
	assert.Assert(t, err != nil, "Write to closed fd should fail")
}

func TestSignWithStatusFd(t *testing.T) {
	defer func() { opts = Opts{} }()

	opts = Opts{}
	mockClient := NewMockKmsClient()

	// Create status fd pipe
	statusR, statusW, err := os.Pipe()
	assert.NilError(t, err)
	defer statusR.Close()

	fd := int(statusW.Fd())
	sw := NewStatusWriter(&fd, false)

	// Create a temporary input file
	tmpFile, err := os.CreateTemp("", "test-status-*.txt")
	assert.NilError(t, err)
	t.Cleanup(func() { os.Remove(tmpFile.Name()) })

	_, err = tmpFile.WriteString("Hello, World!")
	assert.NilError(t, err)
	tmpFile.Close()

	outputFile := tmpFile.Name() + ".asc"
	t.Cleanup(func() { os.Remove(outputFile) })

	keyId := "test-key-id"
	opts.Sign = true
	opts.DetachedSign = true
	opts.User = keyId
	opts.Output = &outputFile

	err = Sign(mockClient, &opts, []string{tmpFile.Name()}, sw)
	assert.NilError(t, err)

	statusW.Close()

	var buf bytes.Buffer
	io.Copy(&buf, statusR)
	output := buf.String()

	lines := strings.Split(strings.TrimSpace(output), "\n")
	assert.Assert(t, len(lines) >= 3, "Should have at least 3 status lines, got: %d\n%s", len(lines), output)

	assert.Assert(t, strings.HasPrefix(lines[0], "[GNUPG:] KEY_CONSIDERED"), "First line should be KEY_CONSIDERED, got: %s", lines[0])
	assert.Assert(t, strings.HasPrefix(lines[1], "[GNUPG:] BEGIN_SIGNING"), "Second line should be BEGIN_SIGNING, got: %s", lines[1])
	assert.Assert(t, strings.HasPrefix(lines[2], "[GNUPG:] SIG_CREATED"), "Third line should be SIG_CREATED, got: %s", lines[2])
}

func TestSignWithoutStatusFd(t *testing.T) {
	defer func() { opts = Opts{} }()

	opts = Opts{}
	mockClient := NewMockKmsClient()

	tmpFile, err := os.CreateTemp("", "test-nostatus-*.txt")
	assert.NilError(t, err)
	t.Cleanup(func() { os.Remove(tmpFile.Name()) })

	_, err = tmpFile.WriteString("Hello, World!")
	assert.NilError(t, err)
	tmpFile.Close()

	outputFile := tmpFile.Name() + ".asc"
	t.Cleanup(func() { os.Remove(outputFile) })

	keyId := "test-key-id"
	opts.Sign = true
	opts.User = keyId
	opts.Output = &outputFile

	err = Sign(mockClient, &opts, []string{tmpFile.Name()}, inactiveStatusWriter())
	assert.NilError(t, err)

	_, err = os.Stat(outputFile)
	assert.NilError(t, err, "Output file should be created")
}

func TestSigCreatedFormatDetached(t *testing.T) {
	defer func() { opts = Opts{} }()

	opts = Opts{}
	mockClient := NewMockKmsClient()

	statusR, statusW, err := os.Pipe()
	assert.NilError(t, err)
	defer statusR.Close()

	fd := int(statusW.Fd())
	sw := NewStatusWriter(&fd, false)

	tmpFile, err := os.CreateTemp("", "test-detached-*.txt")
	assert.NilError(t, err)
	t.Cleanup(func() { os.Remove(tmpFile.Name()) })

	_, err = tmpFile.WriteString("test data")
	assert.NilError(t, err)
	tmpFile.Close()

	outputFile := tmpFile.Name() + ".asc"
	t.Cleanup(func() { os.Remove(outputFile) })

	keyId := "test-key-id"
	opts.Sign = true
	opts.DetachedSign = true
	opts.User = keyId
	opts.Output = &outputFile

	err = Sign(mockClient, &opts, []string{tmpFile.Name()}, sw)
	assert.NilError(t, err)

	statusW.Close()

	var buf bytes.Buffer
	io.Copy(&buf, statusR)
	output := buf.String()

	// Find SIG_CREATED line
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "SIG_CREATED") {
			parts := strings.Fields(line)
			// [GNUPG:] SIG_CREATED D pubkeyAlgo hashAlgo 00 timestamp fingerprint
			assert.Assert(t, len(parts) >= 8, "SIG_CREATED should have enough fields: %s", line)
			assert.Equal(t, parts[2], "D", "Detached sign type should be D")
			assert.Equal(t, parts[5], "00", "Detached sign class should be 00")
			return
		}
	}
	t.Fatal("SIG_CREATED line not found in status output")
}

func TestSigCreatedFormatClearSign(t *testing.T) {
	defer func() { opts = Opts{} }()

	opts = Opts{}
	mockClient := NewMockKmsClient()

	statusR, statusW, err := os.Pipe()
	assert.NilError(t, err)
	defer statusR.Close()

	fd := int(statusW.Fd())
	sw := NewStatusWriter(&fd, false)

	tmpFile, err := os.CreateTemp("", "test-clearsign-*.txt")
	assert.NilError(t, err)
	t.Cleanup(func() { os.Remove(tmpFile.Name()) })

	_, err = tmpFile.WriteString("test data")
	assert.NilError(t, err)
	tmpFile.Close()

	outputFile := tmpFile.Name() + ".asc"
	t.Cleanup(func() { os.Remove(outputFile) })

	keyId := "test-key-id"
	opts.ClearSign = true
	opts.User = keyId
	opts.Output = &outputFile

	err = Sign(mockClient, &opts, []string{tmpFile.Name()}, sw)
	assert.NilError(t, err)

	statusW.Close()

	var buf bytes.Buffer
	io.Copy(&buf, statusR)
	output := buf.String()

	// Find SIG_CREATED line
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "SIG_CREATED") {
			parts := strings.Fields(line)
			assert.Assert(t, len(parts) >= 8, "SIG_CREATED should have enough fields: %s", line)
			assert.Equal(t, parts[2], "C", "Clear sign type should be C")
			assert.Equal(t, parts[5], "01", "Clear sign class should be 01")
			return
		}
	}
	t.Fatal("SIG_CREATED line not found in status output")
}

func TestGpgHashAlgoNumber(t *testing.T) {
	testCases := []struct {
		hash     crypto.Hash
		expected int
	}{
		{crypto.SHA1, 2},
		{crypto.SHA256, 8},
		{crypto.SHA384, 9},
		{crypto.SHA512, 10},
		{crypto.MD5, 0},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Hash %v", tc.hash), func(t *testing.T) {
			result := gpgHashAlgoNumber(tc.hash)
			assert.Equal(t, result, tc.expected)
		})
	}
}
