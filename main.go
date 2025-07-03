package main

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/vinnterab/pgpkms/cmd"
	"github.com/vinnterab/pgpkms/kms"
)

func main() {
	// Load AWS configuration
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load AWS config: %v\n", err)
		os.Exit(1)
	}

	// Initialize KMS client
	client := kms.NewAWSKmsClient(cfg)

	if err := cmd.Execute(client); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n\n", err)
	}
}
