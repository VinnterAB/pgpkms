# PGP KMS

A Go command-line tool that integrates AWS Key Management Service (KMS) with PGP cryptography, enabling you to use AWS KMS asymmetric keys for PGP signing operations and export KMS public keys as PGP-compatible key blocks.

This project is inspired by https://github.com/hf/kmspgp, but tries to mimic the gpg command line interface and implements clearsign.

## Features

- **Export KMS public keys** as PGP public key blocks
- **Sign data** using AWS KMS asymmetric keys with PGP formatting
- **Clear text signing** for human-readable signed messages
- **Flexible input/output** - works with files or stdin/stdout
- **ASCII armoring** support for text-safe output

## Installation

### Prerequisites

- Go 1.22.1 or later
- AWS credentials configured (via AWS CLI, environment variables, or IAM roles)
- AWS KMS asymmetric key (RSA or ECDSA) with `SIGN_VERIFY` usage

### Build from source

```bash
git clone https://github.com/vinnterab/pgpkms.git
cd pgpkms
go build -o pgpkms
```

## AWS KMS Key Requirements

Your AWS KMS key must be:
- **Asymmetric** (not symmetric)
- **Key usage**: `SIGN_VERIFY`
- **Key spec**: RSA or ECDSA (e.g., `RSA_2048`, `ECC_NIST_P256`)

## Usage

### Export PGP Public Key

Export a KMS public key as a PGP public key block:

```bash
# Export with name and email
pgpkms --export -u arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012 \
       --export-name "John Doe" \
       --export-email "john@example.com"

# Export with ASCII armor
pgpkms --export -u arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012 \
       --export-name "John Doe" \
       --export-email "john@example.com" \
       --armor
```

### Sign Files

Sign a file using a KMS key:

```bash
# Sign a file (creates input.txt.asc)
pgpkms --sign -u arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012 input.txt

# Sign with custom output file
pgpkms --sign -u arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012 \
       input.txt -o signature.sig

# Sign data from stdin to stdout
echo "Hello, World!" | pgpkms --sign -u arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012
```

### Clear Text Signing

Create human-readable signed messages:

```bash
# Clear sign a file
pgpkms --clear-sign -u arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012 message.txt

# Clear sign from stdin
echo "This is a test message" | pgpkms --clear-sign -u arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012
```

## Command Line Options

```
Usage:
  pgpkms [OPTIONS]

Application Options:
  -a, --armor           Use ASCII Armoured format for the output
      --export          Export a public part of a KMS key in a PGP Key Block
      --export-name     Name to use for the exported PGP key (used with --export)
      --export-email    Email to use for the exported PGP key (used with --export)
      --export-comment  Comment to use for the exported PGP key (used with --export)
      --sign            Sign a file using KMS key
      --clear-sign      Create a clear text signature using KMS key
  -o, --output          Output file (default: input file + .asc)
  -u, --local-user      The key ID to use

Help Options:
  -h, --help            Show this help message
```

## Examples

### Complete Workflow

1. **Create a KMS key** (if you don't have one):
   ```bash
   aws kms create-key \
     --description "PGP signing key" \
     --key-usage SIGN_VERIFY \
     --key-spec RSA_2048
   ```

2. **Export the public key**:
   ```bash
   pgpkms --export arn:aws:kms:us-east-1:123456789012:key/your-key-id \
          --export-name "Your Name" \
          --export-email "your.email@example.com" \
          --armor > publickey.asc
   ```

3. **Sign a document**:
   ```bash
   pgpkms --sign arn:aws:kms:us-east-1:123456789012:key/your-key-id document.txt
   ```

4. **Verify the signature** (using standard PGP tools):
   ```bash
   gpg --import publickey.asc
   gpg --verify document.txt.asc
   ```

### Integration with CI/CD

Use pgpkms in CI/CD pipelines for secure artifact signing:

```bash
# Sign release artifacts
pgpkms --sign $KMS_KEY_ARN release.tar.gz

# Create detached signature
pgpkms --sign $KMS_KEY_ARN release.tar.gz -o release.tar.gz.sig
```

## AWS Authentication

pgpkms uses the standard AWS SDK credential chain:

1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
2. AWS credentials file (`~/.aws/credentials`)
3. IAM roles (for EC2 instances)
4. AWS CLI profiles

### Required IAM Permissions

Your AWS credentials need the following KMS permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "kms:GetPublicKey",
                "kms:DescribeKey",
                "kms:Sign"
            ],
            "Resource": "arn:aws:kms:*:*:key/*"
        }
    ]
}
```

## Architecture

The project is organized into clean, focused packages:

- **`main.go`** - Entry point and AWS configuration
- **`cmd/`** - Command-line interface and argument parsing
- **`kms/`** - AWS KMS integration and key management
- **`pgp/`** - PGP key and signature generation

## Development

### Running Tests

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run tests verbosely
go test -v ./...
```

### Code Quality

```bash
# Format code
go fmt ./...

# Lint code
go vet ./...

# Build
go build -o pgpkms
```

## Security Considerations

- **Key Management**: KMS keys are stored securely in AWS and never leave the service
- **Audit Trail**: All KMS operations are logged in AWS CloudTrail
- **Access Control**: Use IAM policies to control who can use which keys
- **Key Rotation**: Consider using KMS automatic key rotation for enhanced security

## Limitations

- Only supports asymmetric KMS keys with `SIGN_VERIFY` usage
- Cannot generate new KMS keys (use AWS CLI or Console)
- PGP signatures are not timestamped (KMS limitation)

## Contributing

Contributions are welcome! Please ensure:

1. Code is properly formatted (`go fmt`)
2. All tests pass (`go test ./...`)
3. Code passes static analysis (`go vet`)
4. New features include appropriate tests

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Troubleshooting

### Common Issues

**"Key not found" errors**:
- Verify the KMS key ARN is correct
- Ensure your AWS credentials have access to the key
- Check that the key exists in the correct AWS region

**"Invalid key usage" errors**:
- Ensure the KMS key has `SIGN_VERIFY` usage
- Verify the key is asymmetric (not symmetric)

**Permission errors**:
- Check IAM permissions for `kms:GetPublicKey`, `kms:DescribeKey`, and `kms:Sign`
- Verify the key policy allows your principal to use the key

**Output file errors**:
- Ensure the output directory is writable
- Check that the output file doesn't already exist (pgpkms won't overwrite)
