package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/vinnterab/pgpkms/kms"
	"github.com/vinnterab/pgpkms/pgp"
)

func Sign(client kms.Client, opts *Opts, args []string) error {
	// Determine input source
	inputData, inputName, err := determineInputSource(args)
	if err != nil {
		return err
	}

	// Sign the data
	signedData, err := signData(client, opts.User, inputData, opts.ClearSign)
	if err != nil {
		return err
	}

	// Determine output writer and write
	writer, outputFile, err := determineOutputWriter(args, opts, inputName)
	if err != nil {
		return err
	}
	defer writer.Close()

	err = writeOutput(writer, signedData)
	if err != nil {
		return err
	}

	// Print status message if writing to file
	if outputFile != "" {
		fmt.Printf("Signed %s -> %s\n", inputName, outputFile)
	}

	return nil
}

// signData signs the input data using KMS and returns the signed data
func signData(client kms.Client, keyId string, inputData []byte, clearSign bool) ([]byte, error) {
	// Get KMS key
	key, err := client.GetKey(keyId)
	if err != nil {
		return nil, err
	}

	// Sign the data
	signedData, err := pgp.SignData(key.PublicKey, key.PrivateKey, inputData, clearSign)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	return signedData, nil
}

// determineInputSource reads input data from either stdin or file
func determineInputSource(args []string) ([]byte, string, error) {
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
		inputData, err = os.ReadFile(inputFile)
		if err != nil {
			return nil, "", fmt.Errorf("failed to read input file: %w", err)
		}
		inputName = inputFile
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

// determineOutputWriter decides whether to write to stdout or file and returns appropriate io.WriteCloser
func determineOutputWriter(args []string, opts *Opts, inputName string) (io.WriteCloser, string, error) {
	// If reading from stdin and no output file specified, write to stdout
	if len(args) == 0 && opts.Output == nil {
		return stdoutWriteCloser{}, "", nil
	}

	// Determine output file
	var outputFile string
	var err error

	if opts.Output != nil {
		outputFile = *opts.Output
	} else {
		outputFile, err = getOutputFile(inputName, nil)
		if err != nil {
			return nil, "", err
		}
	}

	// Check if output file already exists
	if _, err := os.Stat(outputFile); err == nil {
		return nil, "", fmt.Errorf("output file %s already exists", outputFile)
	}

	// Create and return the file
	file, err := os.Create(outputFile)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create output file: %w", err)
	}

	return file, outputFile, nil
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
