package cmd

import (
	"crypto"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/vinnterab/pgpkms/kms"
	"github.com/vinnterab/pgpkms/pgp"
)

// parseDigestAlgo converts string to crypto.Hash
func parseDigestAlgo(algo string) (crypto.Hash, error) {
	switch strings.ToLower(algo) {
	case "", "sha256":
		return crypto.SHA256, nil
	case "sha1":
		return crypto.SHA1, nil
	case "sha384":
		return crypto.SHA384, nil
	case "sha512":
		return crypto.SHA512, nil
	default:
		return crypto.SHA256, fmt.Errorf("unsupported digest algorithm: %s", algo)
	}
}

func Sign(client kms.Client, opts *Opts, args []string, sw *StatusWriter, lw *LoggerWriter) error {
	if opts.ClearSignAlias {
		opts.ClearSign = true
	}

	if opts.ArmorAlias {
		opts.Armor = true
	}

	// Parse digest algorithm
	digestHash, err := parseDigestAlgo(opts.DigestAlgo)
	if err != nil {
		return err
	}

	// Determine input source
	inputData, inputName, err := determineInputSource(args, opts.EnableSpecialFilenames)
	if err != nil {
		return err
	}

	// Sign the data
	lw.Log("signing data for key %s", opts.User)
	result, err := signData(client, opts.User, inputData, opts.ClearSign, opts.Armor, digestHash)
	if err != nil {
		return err
	}
	lw.Log("signed %d bytes using %s", len(result.Data), result.Fingerprint)

	// Emit status lines
	hashAlgo := gpgHashAlgoNumber(digestHash)
	sw.Emit("KEY_CONSIDERED", result.Fingerprint, "0")
	sw.Emit("BEGIN_SIGNING", fmt.Sprintf("H%d", hashAlgo))

	// Determine output writer and write
	writer, err := determineOutputWriter(args, opts, inputName)
	if err != nil {
		return err
	}

	defer func() {
		if cerr := writer.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "error closing writer: %v\n", cerr)
		}
	}()

	err = writeOutput(writer, result.Data)
	if err != nil {
		return err
	}

	// Emit SIG_CREATED
	sigType := "D"
	sigClass := "00"
	if opts.ClearSign {
		sigType = "C"
		sigClass = "01"
	}
	timestamp := fmt.Sprintf("%d", time.Now().Unix())

	sw.Emit("SIG_CREATED", sigType, fmt.Sprintf("%d", result.PubkeyAlgo), fmt.Sprintf("%d", hashAlgo), sigClass, timestamp, result.Fingerprint)

	return nil
}

type signResult struct {
	Data        []byte
	Fingerprint string
	PubkeyAlgo  int
}

// signData signs the input data using KMS and returns the signed data along with key metadata
func signData(client kms.Client, keyId string, inputData []byte, clearSign, armor bool, digestHash crypto.Hash) (*signResult, error) {
	// Get KMS key
	key, err := client.GetKey(keyId)
	if err != nil {
		return nil, err
	}

	info, err := pgp.GetKeyInfo(key.PublicKey)
	if err != nil {
		return nil, err
	}

	// Sign the data
	signedData, err := pgp.SignData(key.PublicKey, key.PrivateKey, inputData, clearSign, armor, digestHash)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	return &signResult{
		Data:        signedData,
		Fingerprint: fmt.Sprintf("%X", info.Fingerprint),
		PubkeyAlgo:  pgpAlgoNumber(key.PublicKey.Key.KeySpec),
	}, nil
}

// determineInputSource reads input data from either stdin, a regular file, or a
// GPG special filename when explicitly enabled.
func determineInputSource(args []string, enableSpecialFilenames bool) ([]byte, string, error) {
	var inputData []byte
	var inputName string
	var err error

	// If we have no file as argument, we read from stdin
	if len(args) == 0 {
		inputData, err = io.ReadAll(os.Stdin)
		if err != nil {
			return nil, "", fmt.Errorf("failed to read from stdin: %w", err)
		}
		inputName = "stdin"
	} else {
		inputFile := args[0]
		if enableSpecialFilenames && strings.HasPrefix(inputFile, "-&") {
			fdNum, err := strconv.Atoi(inputFile[2:])
			if err != nil {
				return nil, "", fmt.Errorf("invalid file descriptor syntax %q: %w", inputFile, err)
			}
			f := os.NewFile(uintptr(fdNum), "input-fd")
			if f == nil {
				return nil, "", fmt.Errorf("invalid file descriptor: %d", fdNum)
			}
			inputData, err = io.ReadAll(f)
			_ = f.Close()
			if err != nil {
				return nil, "", fmt.Errorf("failed to read from file descriptor %d: %w", fdNum, err)
			}
			inputName = inputFile
		} else {
			inputData, err = os.ReadFile(inputFile)
			if err != nil {
				return nil, "", fmt.Errorf("failed to read input file: %w", err)
			}
			inputName = inputFile
		}
	}

	return inputData, inputName, nil
}

// writeOutput writes data to any io.Writer
func writeOutput(writer io.Writer, data []byte) error {
	_, err := writer.Write(data)
	return err
}

// stdoutWriteCloser wraps os.Stdout to implement io.WriteCloser
type stdoutWriteCloser struct{}

func (s stdoutWriteCloser) Write(p []byte) (n int, err error) {
	return os.Stdout.Write(p)
}

func (s stdoutWriteCloser) Close() error {
	// stdout doesn't need to be closed
	return nil
}

// determineOutputWriter decides whether to write to stdout or a file.
func determineOutputWriter(args []string, opts *Opts, inputName string) (io.WriteCloser, error) {
	// Write to stdout when reading from stdin or a special filename (file descriptor),
	// since GPGME expects the signature on stdout in these cases.
	if opts.Output == nil && (len(args) == 0 || strings.HasPrefix(inputName, "-&")) {
		return stdoutWriteCloser{}, nil
	}

	// Determine output file
	var outputFile string
	var err error

	if opts.Output != nil {
		outputFile = *opts.Output
	} else {
		outputFile, err = getOutputFile(inputName, nil)
		if err != nil {
			return nil, err
		}
	}

	// Check if output file already exists
	if _, err := os.Stat(outputFile); err == nil {
		return nil, fmt.Errorf("output file %s already exists", outputFile)
	}

	// Create and return the file
	file, err := os.Create(outputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %w", err)
	}

	return file, nil
}

func getOutputFile(inputFile string, outputOpt *string) (string, error) {
	if outputOpt != nil {
		return *outputOpt, nil
	}

	// Generate output filename by adding .asc extension
	if strings.HasSuffix(inputFile, ".asc") {
		return "", fmt.Errorf("input file already has .asc extension")
	}

	return inputFile + ".asc", nil
}
