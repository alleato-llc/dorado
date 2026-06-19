// Command gyotaku is a standalone Skein-512 hashing tool, the Skein equivalent
// of sha256sum. The name is the Japanese art of printing a fish in ink, a
// fingerprint of the fish. This is the Go port of the dorado-gyotaku CLI.
package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/alleato-llc/dorado/go/skein"
)

func main() {
	bits := flag.Int("bits", 256, "output length in bits (a multiple of 8)")
	tag := flag.Bool("tag", false, `print BSD-style "SKEIN-512 (file) = digest" output`)
	check := flag.Bool("c", false, "read digests from the FILES and verify them (like sha256sum -c)")
	flag.Parse()

	if err := run(*bits, *tag, *check, flag.Args()); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(bits int, tag, check bool, files []string) error {
	if check {
		if tag {
			return fmt.Errorf("--tag cannot be combined with -c")
		}
		if len(files) == 0 {
			return fmt.Errorf("-c needs at least one checksum file")
		}
		return runCheck(files)
	}
	if bits <= 0 || bits%8 != 0 {
		return fmt.Errorf("--bits must be a positive multiple of 8")
	}
	outLen := bits / 8

	if len(files) == 0 {
		digest, err := digestReader(os.Stdin, outLen)
		if err != nil {
			return err
		}
		if tag {
			fmt.Println(tagLine(digest, "-"))
		} else {
			fmt.Println(digest)
		}
		return nil
	}
	for _, path := range files {
		digest, err := digestFile(path, outLen)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		fmt.Println(formatLine(tag, digest, path))
	}
	return nil
}

// digestReader stream-hashes a reader, in constant memory.
func digestReader(r io.Reader, outLen int) (string, error) {
	h := skein.New(outLen)
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func digestFile(path string, outLen int) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	return digestReader(f, outLen)
}

func formatLine(tag bool, digest, name string) string {
	if tag {
		return tagLine(digest, name)
	}
	return digest + "  " + name
}

func tagLine(digest, name string) string {
	return "SKEIN-512 (" + name + ") = " + digest
}

func runCheck(files []string) error {
	var checked, failed int
	for _, list := range files {
		f, err := os.Open(list)
		if err != nil {
			return fmt.Errorf("%s: %w", list, err)
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			digest, name, ok := parseCheckLine(line)
			if !ok {
				f.Close()
				return fmt.Errorf("%s: malformed line: %s", list, line)
			}
			checked++
			got, err := digestFile(name, len(digest)/2)
			if err != nil {
				fmt.Printf("%s: FAILED open or read\n", name)
				failed++
				continue
			}
			if strings.EqualFold(got, digest) {
				fmt.Printf("%s: OK\n", name)
			} else {
				fmt.Printf("%s: FAILED\n", name)
				failed++
			}
		}
		f.Close()
	}
	if checked == 0 {
		return fmt.Errorf("no digests found to verify")
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d digests did NOT match", failed, checked)
	}
	return nil
}

// parseCheckLine accepts both "digest  name" and "SKEIN-512 (name) = digest".
func parseCheckLine(line string) (digest, name string, ok bool) {
	if algo, rest, found := strings.Cut(line, " ("); found {
		_ = algo
		if nm, dg, found := strings.Cut(rest, ") = "); found {
			dg = strings.TrimSpace(dg)
			if isEvenHex(dg) {
				return dg, nm, true
			}
		}
	}
	dg, rest, found := strings.Cut(line, " ")
	if !found || !isEvenHex(dg) {
		// try two-space form already covered by single-space cut + trim
		return "", "", false
	}
	nm := strings.TrimPrefix(strings.TrimSpace(rest), "*")
	return dg, nm, true
}

func isEvenHex(s string) bool {
	if s == "" || len(s)%2 != 0 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
