package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"

	flags "github.com/jessevdk/go-flags"
	"github.com/vinnterab/pgpkms/kms"
)

var opts Opts

func Usage() string {
	return "USAGE"
}

func replaceEqualSigns(helptext string) string {
	return strings.ReplaceAll(helptext, "=", " ")
}

func Execute(client kms.Client) error {
	parser := flags.NewParser(&opts, flags.Default&^flags.PrintErrors)

	args, err := parser.Parse()
	if err != nil {
		if flagsErr, ok := err.(*flags.Error); ok {
			if flagsErr.Type == flags.ErrHelp {
				// Print custom help without = characters
				help := flagsErr.Message
				help = replaceEqualSigns(help)
				fmt.Print(help)
				return nil
			}
		}
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	if opts.Version {
		fmt.Print(VersionString())
		return nil
	}

	sw := NewStatusWriter(opts.StatusFd, opts.ExitOnStatusWriteError)
	defer sw.Close()

	lw := NewLoggerWriter(opts.LoggerFd)
	defer lw.Close()

	if opts.ListSecretKeys {
		if opts.Export || opts.Sign || opts.ClearSign || opts.DetachedSign {
			return errors.New("conflicting commands")
		}
		return ListSecretKeys(client, &opts, args, sw, lw)
	}

	if opts.ArmorAlias {
		opts.Armor = true
	}

	if opts.ClearSignAlias {
		opts.ClearSign = true
	}

	if opts.Detach {
		opts.DetachedSign = true
	}

	if opts.DetachedSign && opts.ClearSign {
		return errors.New("conflicting commands")
	}

	if opts.DetachedSign {
		opts.Sign = true
	}

	if opts.Export && (opts.Sign || opts.ClearSign) {
		return errors.New("conflicting commands")
	}

	// these require a key
	if (opts.Export || opts.Sign || opts.ClearSign) && opts.User == "" {
		return errors.New("specify the key id with -u/--local-user ")
	}

	// Resolve friendly key identifiers to KMS ARN
	if opts.User != "" {
		resolved, err := ResolveKeyId(client, opts.User)
		if err != nil {
			return err
		}
		opts.User = resolved
	}

	if opts.Export {
		return ExportKey(client, &opts, args, sw, lw)
	}

	if opts.Sign || opts.ClearSign {
		return Sign(client, &opts, args, sw, lw)
	}

	// No command provided, show usage
	var helpBuf strings.Builder
	parser.WriteHelp(&helpBuf)
	help := helpBuf.String()
	help = replaceEqualSigns(help)
	fmt.Print(help)
	return nil
}
