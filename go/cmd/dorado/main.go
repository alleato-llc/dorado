// Command dorado applies Threefish in CTR mode over files or stdin, streaming in
// constant memory: bare raw-key CTR, or a password-derived authenticated
// container. This is the Go port of the dorado CLI (GUI excluded).
package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/alleato-llc/dorado/go/engine"
	"golang.org/x/term"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "encrypt":
		err = cmdCrypt(os.Args[2:], true)
	case "decrypt":
		err = cmdCrypt(os.Args[2:], false)
	case "inspect":
		err = cmdInspect(os.Args[2:])
	case "--version", "-version", "version":
		fmt.Println("dorado", version)
		return
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: dorado <command> [flags]

Commands:
  encrypt   encrypt input with Threefish-CTR
  decrypt   decrypt input (the same operation as encrypt)
  inspect   print a password file's non-secret parameters

Supply the key directly with --key/--key-file (raw, unauthenticated CTR), or
derive it from a password with --password/--password-stdin (authenticated
container). Run "dorado encrypt -h" for the full flag list.
`)
	os.Exit(2)
}

type opts struct {
	key, keyFile, iv, tweak     string
	password, passwordStdin     bool
	variant, kdf, mac           string
	argonMem, argonTime, argonP uint
	scryptLogN, scryptR, scryptP uint
	pbkdf2Rounds, chunkKiB      uint
	label, expectLabel          string
	in, out                     string
}

func parse(argv []string) (*opts, error) {
	fs := flag.NewFlagSet("dorado", flag.ContinueOnError)
	o := &opts{}
	fs.StringVar(&o.key, "key", "", "key as hex (raw-key mode); length selects the variant")
	fs.StringVar(&o.keyFile, "key-file", "", "read the key (as hex) from a file (raw-key mode)")
	fs.StringVar(&o.iv, "iv", "", "initial counter as hex (raw-key mode)")
	fs.StringVar(&o.tweak, "tweak", strings.Repeat("00", 16), "tweak as hex, 16 bytes")
	fs.BoolVar(&o.password, "password", false, "derive the key from an interactive password")
	fs.BoolVar(&o.passwordStdin, "password-stdin", false, "read the password from stdin (data from --in)")
	fs.StringVar(&o.variant, "variant", "256", "256|512|1024 (password mode)")
	fs.StringVar(&o.kdf, "kdf", "argon2id", "argon2id|scrypt|pbkdf2")
	fs.StringVar(&o.mac, "mac", "skein", "skein|hmac-sha256|blake3")
	fs.UintVar(&o.argonMem, "argon2-mem-mib", 64, "Argon2id memory cost in MiB")
	fs.UintVar(&o.argonTime, "argon2-time", 3, "Argon2id iterations")
	fs.UintVar(&o.argonP, "argon2-par", 1, "Argon2id lanes")
	fs.UintVar(&o.scryptLogN, "scrypt-logn", 15, "scrypt log2(N)")
	fs.UintVar(&o.scryptR, "scrypt-r", 8, "scrypt r")
	fs.UintVar(&o.scryptP, "scrypt-p", 1, "scrypt p")
	fs.UintVar(&o.pbkdf2Rounds, "pbkdf2-rounds", 600000, "PBKDF2 iterations")
	fs.UintVar(&o.chunkKiB, "chunk-kib", 64, "authenticated chunk size in KiB")
	fs.StringVar(&o.label, "label", "", "label to bind into the file (encrypt)")
	fs.StringVar(&o.expectLabel, "expect-label", "", "require this label on decrypt")
	fs.StringVar(&o.in, "in", "", "input file (stdin if omitted)")
	fs.StringVar(&o.out, "out", "", "output file (stdout if omitted)")
	if err := fs.Parse(argv); err != nil {
		return nil, err
	}
	return o, nil
}

func (o *opts) passwordMode() bool { return o.password || o.passwordStdin }

func (o *opts) variantValue() (engine.Variant, error) {
	switch o.variant {
	case "256":
		return engine.T256, nil
	case "512":
		return engine.T512, nil
	case "1024":
		return engine.T1024, nil
	}
	return 0, fmt.Errorf("unknown variant %q", o.variant)
}

func (o *opts) kdfParams() (engine.KDFParams, error) {
	switch o.kdf {
	case "argon2id":
		return engine.KDFParams{Kind: engine.Argon2id, MCost: uint32(o.argonMem) * 1024, TCost: uint32(o.argonTime), PCost: uint32(o.argonP)}, nil
	case "scrypt":
		return engine.KDFParams{Kind: engine.Scrypt, LogN: uint8(o.scryptLogN), R: uint32(o.scryptR), P: uint32(o.scryptP)}, nil
	case "pbkdf2":
		return engine.KDFParams{Kind: engine.Pbkdf2, Rounds: uint32(o.pbkdf2Rounds), Prf: engine.PrfHMACSHA256}, nil
	}
	return engine.KDFParams{}, fmt.Errorf("unknown kdf %q", o.kdf)
}

func (o *opts) macValue() (engine.MacID, error) {
	switch o.mac {
	case "skein":
		return engine.MacSkein, nil
	case "hmac-sha256":
		return engine.MacHMAC, nil
	case "blake3":
		return engine.MacBLAKE3, nil
	}
	return 0, fmt.Errorf("unknown mac %q", o.mac)
}

func cmdCrypt(argv []string, encrypt bool) error {
	o, err := parse(argv)
	if err != nil {
		return err
	}
	creds := 0
	for _, set := range []bool{o.key != "", o.keyFile != "", o.password, o.passwordStdin} {
		if set {
			creds++
		}
	}
	if creds != 1 {
		return fmt.Errorf("provide exactly one of --key, --key-file, --password, --password-stdin")
	}
	if !o.passwordMode() {
		return runRaw(o)
	}
	if o.iv != "" {
		return fmt.Errorf("--iv is not used in password mode; the IV is generated and stored")
	}
	if o.passwordStdin && o.in == "" {
		return fmt.Errorf("with --password-stdin, pass the data via --in")
	}
	password, err := readPassword(o, encrypt)
	if err != nil {
		return err
	}
	defer wipe(password) // best-effort; Go cannot guarantee a wipe (see README)
	in, closeIn, err := openIn(o.in)
	if err != nil {
		return err
	}
	defer closeIn()
	out, closeOut, err := openOut(o.out)
	if err != nil {
		return err
	}
	defer closeOut()

	if encrypt {
		variant, err := o.variantValue()
		if err != nil {
			return err
		}
		kdf, err := o.kdfParams()
		if err != nil {
			return err
		}
		mac, err := o.macValue()
		if err != nil {
			return err
		}
		tweak, err := parseTweak(o.tweak)
		if err != nil {
			return err
		}
		po := engine.PasswordOptions{Variant: variant, KDF: kdf, Mac: mac, Tweak: tweak, ChunkSize: uint32(o.chunkKiB) * 1024}
		if o.label != "" {
			po.Label = []byte(o.label)
		}
		return engine.EncryptPasswordStream(password, po, in, out)
	}
	var expect []byte
	if o.expectLabel != "" {
		expect = []byte(o.expectLabel)
	}
	return engine.DecryptPasswordStreamExpecting(password, expect, in, out)
}

func runRaw(o *opts) error {
	keyHex := o.key
	if keyHex == "" {
		data, err := os.ReadFile(o.keyFile)
		if err != nil {
			return fmt.Errorf("key-file: %w", err)
		}
		keyHex = string(data)
	}
	key, err := dehex(keyHex)
	if err != nil {
		return fmt.Errorf("key: %w", err)
	}
	defer wipe(key)
	var variant engine.Variant
	switch len(key) {
	case 32:
		variant = engine.T256
	case 64:
		variant = engine.T512
	case 128:
		variant = engine.T1024
	default:
		return fmt.Errorf("key must be 32, 64, or 128 bytes, got %d", len(key))
	}
	if o.iv == "" {
		return fmt.Errorf("--iv is required with --key/--key-file")
	}
	iv, err := dehex(o.iv)
	if err != nil {
		return fmt.Errorf("iv: %w", err)
	}
	tweak, err := parseTweak(o.tweak)
	if err != nil {
		return err
	}
	in, closeIn, err := openIn(o.in)
	if err != nil {
		return err
	}
	defer closeIn()
	out, closeOut, err := openOut(o.out)
	if err != nil {
		return err
	}
	defer closeOut()
	return engine.RawCTRStream(variant, key, tweak[:], iv, in, out)
}

func cmdInspect(argv []string) error {
	o, err := parse(argv)
	if err != nil {
		return err
	}
	in, closeIn, err := openIn(o.in)
	if err != nil {
		return err
	}
	defer closeIn()
	info, err := engine.Inspect(in)
	if err != nil {
		return err
	}
	fmt.Print(formatInfo(info))
	return nil
}

func readPassword(o *opts, confirm bool) ([]byte, error) {
	if o.passwordStdin {
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		return []byte(strings.TrimRight(line, "\r\n")), nil
	}
	fmt.Fprint(os.Stderr, "Password: ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	if confirm {
		fmt.Fprint(os.Stderr, "Confirm password: ")
		again, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, err
		}
		if string(pw) != string(again) {
			return nil, fmt.Errorf("passwords do not match")
		}
	}
	if len(pw) == 0 {
		return nil, fmt.Errorf("password must not be empty")
	}
	return pw, nil
}

func openIn(path string) (io.Reader, func(), error) {
	if path == "" {
		return os.Stdin, func() {}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { f.Close() }, nil
}

func openOut(path string) (io.Writer, func(), error) {
	if path == "" {
		return os.Stdout, func() {}, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { f.Close() }, nil
}

// dehex decodes hex, ignoring all whitespace (matching the Rust parse_hex).
func dehex(s string) ([]byte, error) {
	return hex.DecodeString(strings.Join(strings.Fields(s), ""))
}

// wipe best-effort zeroes a secret buffer. Go cannot guarantee the secret is
// gone (the GC may have copied it, and the write may be elided); see README.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func parseTweak(s string) ([16]byte, error) {
	var t [16]byte
	b, err := dehex(s)
	if err != nil {
		return t, fmt.Errorf("tweak: %w", err)
	}
	if len(b) != 16 {
		return t, fmt.Errorf("tweak must be 16 bytes, got %d", len(b))
	}
	copy(t[:], b)
	return t, nil
}

func formatInfo(info *engine.ContainerInfo) string {
	variant := map[engine.Variant]string{engine.T256: "Threefish-256", engine.T512: "Threefish-512", engine.T1024: "Threefish-1024"}[info.Variant]
	var kdf string
	switch info.KDF.Kind {
	case engine.Argon2id:
		kdf = fmt.Sprintf("Argon2id (memory %d KiB, iterations %d, lanes %d)", info.KDF.MCost, info.KDF.TCost, info.KDF.PCost)
	case engine.Scrypt:
		kdf = fmt.Sprintf("scrypt (log2(N) %d, r %d, p %d)", info.KDF.LogN, info.KDF.R, info.KDF.P)
	case engine.Pbkdf2:
		kdf = fmt.Sprintf("PBKDF2-HMAC-SHA256 (rounds %d)", info.KDF.Rounds)
	}
	mac := map[engine.MacID]string{engine.MacSkein: "Skein-512", engine.MacHMAC: "HMAC-SHA256", engine.MacBLAKE3: "BLAKE3 (keyed)"}[info.Mac]
	label := "(none)"
	if len(info.Label) > 0 {
		label = string(info.Label)
	}
	return fmt.Sprintf(
		"format:   dorado password container (DRDO v%d)\nvariant:  %s\nkdf:      %s\nmac:      %s\nchunk:    %d bytes\nsalt:     %d bytes\ntweak:    %x\nlabel:    %s\n",
		info.Version, variant, kdf, mac, info.ChunkSize, info.SaltLen, info.Tweak, label)
}
