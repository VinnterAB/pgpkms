package cmd

import (
	"crypto"
	"fmt"
	"os"
	"strings"
)

// StatusWriter writes GPG status lines to a file descriptor.
// GPGME parses these lines to determine operation success.
type StatusWriter struct {
	file        *os.File
	active      bool
	exitOnError bool
	exitFunc    func(int)
}

// NewStatusWriter creates a StatusWriter for the given file descriptor.
// If fdNum is nil, the writer is inactive and Emit is a no-op.
func NewStatusWriter(fdNum *int, exitOnError bool) *StatusWriter {
	sw := &StatusWriter{
		exitOnError: exitOnError,
		exitFunc:    os.Exit,
	}
	if fdNum == nil {
		sw.active = false
		return sw
	}
	sw.file = os.NewFile(uintptr(*fdNum), "status-fd")
	sw.active = true
	return sw
}

// Emit writes a GPG status line in the format: [GNUPG:] CODE args...\n
// It is a no-op if the writer is inactive.
func (sw *StatusWriter) Emit(code string, args ...string) {
	if !sw.active {
		return
	}
	line := "[GNUPG:] " + code
	if len(args) > 0 {
		line += " " + strings.Join(args, " ")
	}
	line += "\n"
	_, err := sw.file.WriteString(line)
	if err != nil {
		if sw.exitOnError {
			sw.exitFunc(2)
			return
		}
		fmt.Fprintf(os.Stderr, "status-fd write error: %v\n", err)
	}
}

// Close closes the status fd if active.
func (sw *StatusWriter) Close() {
	if sw.active && sw.file != nil {
		_ = sw.file.Close()
	}
}

// gpgHashAlgoNumber returns the GPG numeric ID for a hash algorithm.
func gpgHashAlgoNumber(hash crypto.Hash) int {
	switch hash {
	case crypto.SHA1:
		return 2
	case crypto.SHA256:
		return 8
	case crypto.SHA384:
		return 9
	case crypto.SHA512:
		return 10
	default:
		return 0
	}
}
