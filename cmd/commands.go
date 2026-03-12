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

var validCharsets = map[string]bool{
	"utf-8":       true,
	"iso-8859-1":  true,
	"iso-8859-2":  true,
	"iso-8859-15": true,
	"koi8-r":      true,
}

func validateCharset(charset string) error {
	if !validCharsets[strings.ToLower(charset)] {
		return fmt.Errorf("invalid charset: %s", charset)
	}
	return nil
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
		fmt.Fprintf(os.Stderr, "%s", err)
		os.Exit(1)
	}

	if opts.Version {
		fmt.Print(VersionString())
		return nil
	}

	if opts.Charset != nil {
		if err := validateCharset(*opts.Charset); err != nil {
			return err
		}
	}

	sw := NewStatusWriter(opts.StatusFd, opts.ExitOnStatusWriteError)
	defer sw.Close()

	lw := NewLoggerWriter(opts.LoggerFd)
	defer lw.Close()

	if opts.ListSecretKeys {
		if opts.Export || opts.Sign || opts.ClearSign || opts.DetachedSign {
			return errors.New("conflicting commands")
		}
		return ListSecretKeys(client, &opts, sw, lw)
	}

	if opts.ArmorAlias {
		opts.Armor = true
	}

	if opts.ClearSignAlias {
		opts.ClearSign = true
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
