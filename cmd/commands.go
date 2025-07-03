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
		os.Exit(1)
	}

	if opts.Export != nil && (opts.Sign != nil || opts.ClearSign != nil) {
		return errors.New("conflicting commands")
	}

	if opts.Export != nil {
		return ExportKey(client, &opts, args)
	}

	if opts.ClearSign != nil {
		return ClearSign(client, &opts, args)
	}

	if opts.Sign != nil {
		return Sign(client, &opts, args)
	}

	// No command provided, show usage
	var helpBuf strings.Builder
	parser.WriteHelp(&helpBuf)
	help := helpBuf.String()
	help = replaceEqualSigns(help)
	fmt.Print(help)
	return nil
}
