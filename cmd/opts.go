package cmd

type Opts struct {
	DetachedSign           bool    `short:"b" long:"detach-sign" description:"Make a detched signature"`
	Armor                  bool    `short:"a" long:"armor" description:"Use ASCII Armoured format for the output"`
	ArmorAlias             bool    `long:"armour" description:"Alias for --armor"`
	Export                 bool    `long:"export" description:"Export a public part of a KMS key in a PGP Key Block"`
	ExportName             *string `long:"export-name" description:"Name to use for the exported PGP key (used with --export)"`
	ExportEmail            *string `long:"export-email" description:"Email to use for the exported PGP key (used with --export)"`
	ExportComment          *string `long:"export-comment" description:"Comment to use for the exported PGP key (used with --export)"`
	Sign                   bool    `short:"s" long:"sign" description:"Sign a file using KMS key"`
	ClearSign              bool    `long:"clear-sign" description:"Create a clear text signature using KMS key"`
	ClearSignAlias         bool    `long:"clearsign"  description:"Alias for --clear-sign"`
	Output                 *string `short:"o" long:"output" description:"Output file (default: input file + .asc)"`
	User                   string  `short:"u" long:"local-user" description:"The key ID to use"`
	DigestAlgo             string  `long:"digest-algo" description:"Digest algorithm to use (sha1, sha256, sha384, sha512)" default:"sha256"`
	ListSecretKeys         bool    `short:"K" long:"list-secret-keys" description:"List secret keys"`
	WithColons             bool    `long:"with-colons" description:"Print key listings delimited by colons"`
	Version                bool    `long:"version" description:"Display version information"`
	StatusFd               *int    `long:"status-fd" description:"Write status info to this file descriptor"`
	EnableProgressFilter   bool    `long:"enable-progress-filter" description:"Enable progress indicator reporting"`
	ExitOnStatusWriteError bool    `long:"exit-on-status-write-error" description:"Exit if writing to status-fd fails"`
	LoggerFd               *int    `long:"logger-fd" description:"Write log info to this file descriptor"`
	Charset                *string `long:"charset" description:"Character set for display (accepted for GPG compatibility)"`
	Batch                  bool    `long:"batch" description:"Batch mode (accepted for GPG compatibility)"`
	NoTTY                  bool    `long:"no-tty" description:"No TTY (accepted for GPG compatibility)"`
	NoGreeting             bool    `long:"no-greeting" description:"No greeting (accepted for GPG compatibility)"`
	NoSkComments           bool    `long:"no-sk-comments" description:"No secret key comments (accepted for GPG compatibility)"`
	HomeDir                *string `long:"homedir" description:"GPG home directory (accepted for GPG compatibility)"`
	LcCtype                *string `long:"lc-ctype" description:"Locale ctype (accepted for GPG compatibility)"`
}
