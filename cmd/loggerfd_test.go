package cmd

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"gotest.tools/v3/assert"
)

func TestLoggerWriterLog(t *testing.T) {
	r, w, err := os.Pipe()
	assert.NilError(t, err)
	defer r.Close()

	fd := int(w.Fd())
	lw := NewLoggerWriter(&fd)

	lw.Log("hello %s", "world")
	lw.Log("count %d", 42)
	w.Close()

	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	assert.NilError(t, err)

	output := buf.String()
	assert.Assert(t, strings.Contains(output, "hello world\n"))
	assert.Assert(t, strings.Contains(output, "count 42\n"))
}

func TestLoggerWriterInactive(t *testing.T) {
	lw := NewLoggerWriter(nil)

	// Should not panic or do anything
	lw.Log("this should be a no-op")
	lw.Close()
}

func TestLoggerWriterWriteError(t *testing.T) {
	r, w, err := os.Pipe()
	assert.NilError(t, err)

	fd := int(w.Fd())
	lw := NewLoggerWriter(&fd)

	// Capture stderr
	oldStderr := os.Stderr
	sr, sw2, _ := os.Pipe()
	os.Stderr = sw2

	// Close the fd so writing will fail
	lw.file.Close()
	r.Close()

	lw.Log("this should fail")

	sw2.Close()
	os.Stderr = oldStderr

	var buf bytes.Buffer
	io.Copy(&buf, sr)
	sr.Close()

	assert.Assert(t, strings.Contains(buf.String(), "logger-fd write error"))
}

func TestLoggerWriterClose(t *testing.T) {
	r, w, err := os.Pipe()
	assert.NilError(t, err)
	defer r.Close()

	fd := int(w.Fd())
	lw := NewLoggerWriter(&fd)
	lw.Close()

	// Writing after close should fail — verify the fd is closed
	_, err = w.WriteString("test")
	assert.Assert(t, err != nil, "Write to closed fd should fail")
}

func TestSignWithLoggerFd(t *testing.T) {
	defer func() { opts = Opts{} }()

	opts = Opts{}
	mockClient := NewMockKmsClient()

	// Create logger fd pipe
	loggerR, loggerW, err := os.Pipe()
	assert.NilError(t, err)
	defer loggerR.Close()

	fd := int(loggerW.Fd())
	lw := NewLoggerWriter(&fd)

	// Create a temporary input file
	tmpFile, err := os.CreateTemp("", "test-logger-*.txt")
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

	err = Sign(mockClient, &opts, []string{tmpFile.Name()}, inactiveStatusWriter(), lw)
	assert.NilError(t, err)

	loggerW.Close()

	var buf bytes.Buffer
	io.Copy(&buf, loggerR)
	output := buf.String()

	assert.Assert(t, strings.Contains(output, "signing data for key"), "Should contain signing log message")
	assert.Assert(t, strings.Contains(output, "signed"), "Should contain signed log message")
}

func TestSignWithoutLoggerFd(t *testing.T) {
	defer func() { opts = Opts{} }()

	opts = Opts{}
	mockClient := NewMockKmsClient()

	tmpFile, err := os.CreateTemp("", "test-nologger-*.txt")
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

	err = Sign(mockClient, &opts, []string{tmpFile.Name()}, inactiveStatusWriter(), inactiveLoggerWriter())
	assert.NilError(t, err)

	_, err = os.Stat(outputFile)
	assert.NilError(t, err, "Output file should be created")
}
