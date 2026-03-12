package cmd

import (
	"fmt"
	"os"
)

// LoggerWriter writes plain text log messages to a file descriptor.
// GPGME reads these via gpgme_op_getauditlog() for diagnostic output.
type LoggerWriter struct {
	file   *os.File
	active bool
}

// NewLoggerWriter creates a LoggerWriter for the given file descriptor.
// If fdNum is nil, the writer is inactive and Log is a no-op.
func NewLoggerWriter(fdNum *int) *LoggerWriter {
	lw := &LoggerWriter{}
	if fdNum == nil {
		return lw
	}
	lw.file = os.NewFile(uintptr(*fdNum), "logger-fd")
	lw.active = true
	return lw
}

// Log writes a plain text log message followed by a newline.
// It is a no-op if the writer is inactive.
func (lw *LoggerWriter) Log(format string, args ...any) {
	if !lw.active {
		return
	}
	line := fmt.Sprintf(format, args...) + "\n"
	_, err := lw.file.WriteString(line)
	if err != nil {
		fmt.Fprintf(os.Stderr, "logger-fd write error: %v\n", err)
	}
}

// Close closes the logger fd if active.
func (lw *LoggerWriter) Close() {
	if lw.active && lw.file != nil {
		lw.file.Close()
	}
}
