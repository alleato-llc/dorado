package engine

import (
	"bytes"
	"errors"
	"testing"
)

// deriveFromKeyVector is one known-answer vector from
// docs/fixtures/derive-from-key.md, generated from and verified against the
// Rust reference implementation: deriving outLen bytes from the given key and
// domain under the given PRF must match byte-for-byte.
type deriveFromKeyVector struct {
	name   string
	prf    KDFPrf
	keyHex string
	domain string
	outLen int
	outHex string
}

var deriveFromKeyVectors = []deriveFromKeyVector{
	{
		name:   "skein_32key_enc_32out",
		prf:    KDFPrfSkein512,
		keyHex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		domain: "dorado/fixture/enc",
		outLen: 32,
		outHex: "b638c503342dbd51bdfa8906b1cc6b18d7e54252b95e460c522ab3cd939802c6",
	},
	{
		// Same key, different domain and length: the output must be
		// computationally unrelated to skein_32key_enc_32out (domain
		// separation), and a longer outLen is a different Skein output-length
		// configuration, not a truncation or extension of the shorter one.
		name:   "skein_32key_mac_64out",
		prf:    KDFPrfSkein512,
		keyHex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		domain: "dorado/fixture/mac",
		outLen: 64,
		outHex: "6ae3f6f7518e9a4c8a7be8269deb848186beb64b5b43f0bafef81bce4b27d40ef227e2064b941069cc6225cad0a39fcc22aba08fb87f3ba8aacdf4b70b100da6",
	},
	{
		// A non-32-byte key: the Skein-512 PRF accepts a key of any length.
		name:   "skein_16key_enc_32out",
		prf:    KDFPrfSkein512,
		keyHex: "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5",
		domain: "dorado/fixture/enc",
		outLen: 32,
		outHex: "3990e038c7235e62480afe99712203225194afb93910df4101447098e630d0e4",
	},
	{
		// The empty domain is valid (the DRDOkdrv prefix alone is the message).
		name:   "skein_32key_empty_domain_32out",
		prf:    KDFPrfSkein512,
		keyHex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		domain: "",
		outLen: 32,
		outHex: "5bba4214745b3932c1fc620c660b60a4058613ff2bd9d80224d472cd810f7a99",
	},
	{
		name:   "blake3_32key_enc_32out",
		prf:    KDFPrfBLAKE3,
		keyHex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		domain: "dorado/fixture/enc",
		outLen: 32,
		outHex: "8266bd0cfb0d73715aa841fe008c311a44d6b36e0aa01b94f13a90783fe62e1d",
	},
	{
		name:   "blake3_32key_mac_64out",
		prf:    KDFPrfBLAKE3,
		keyHex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		domain: "dorado/fixture/mac",
		outLen: 64,
		outHex: "ea38a1780192707518d15003262a66c245680a579762a7d863cc33078f2f6eaa9a5086f70d00eb7c6cd12fdc7872e5a2023e63c28087631ce835d7e9c7264290",
	},
}

// TestDeriveFromKeyKnownAnswerVectors hardcodes the six cross-language
// known-answer vectors from docs/fixtures/derive-from-key.md, generated from
// and verified against the Rust reference implementation.
func TestDeriveFromKeyKnownAnswerVectors(t *testing.T) {
	for _, v := range deriveFromKeyVectors {
		t.Run(v.name, func(t *testing.T) {
			key := mustHex(t, v.keyHex)
			want := mustHex(t, v.outHex)
			out := make([]byte, v.outLen)
			DeriveFromKeyWith(v.prf, key, v.domain, out)
			if !bytes.Equal(out, want) {
				t.Fatalf("output mismatch\n got: %x\nwant: %x", out, want)
			}
		})
	}
}

func TestDeriveFromKeyDeterministicAndDomainSeparated(t *testing.T) {
	master := bytes.Repeat([]byte{0x42}, 32)
	a := make([]byte, 32)
	b := make([]byte, 32)
	DeriveFromKey(master, "myapp/index", a)
	DeriveFromKey(master, "myapp/index", b)
	if !bytes.Equal(a, b) {
		t.Fatal("same key + domain must give the same bytes")
	}

	c := make([]byte, 32)
	DeriveFromKey(master, "myapp/data", c)
	if bytes.Equal(a, c) {
		t.Fatal("a different domain must give a different key")
	}

	other := bytes.Repeat([]byte{0x43}, 32)
	d := make([]byte, 32)
	DeriveFromKey(other, "myapp/index", d)
	if bytes.Equal(a, d) {
		t.Fatal("a different master must give a different key")
	}

	// Children reveal nothing about each other or the master: at minimum,
	// none of them may equal the master or one another.
	if bytes.Equal(a, master) || bytes.Equal(c, master) {
		t.Fatal("a child never equals the master")
	}
}

func TestDeriveFromKeySupportsArbitraryOutputLengths(t *testing.T) {
	// The 1024-bit variant's raw mode needs 128-byte keys; Skein's output
	// length is free, so longer outputs must work and must not merely
	// prefix-extend shorter ones (the length is bound into the hash).
	master := bytes.Repeat([]byte{0x42}, 32)
	short := make([]byte, 32)
	long := make([]byte, 128)
	DeriveFromKey(master, "myapp/index", short)
	DeriveFromKey(master, "myapp/index", long)
	if bytes.Equal(short, long[:32]) {
		t.Fatal("output length is part of Skein's config, not a truncation")
	}
}

func TestDeriveFromKeyDefaultMatchesSkeinPrf(t *testing.T) {
	// DeriveFromKey is defined as DeriveFromKeyWith(KDFPrfSkein512, ..); the
	// two must be byte-for-byte identical so the default is never a silent
	// change.
	master := bytes.Repeat([]byte{0x42}, 32)
	a := make([]byte, 32)
	b := make([]byte, 32)
	DeriveFromKey(master, "myapp/index", a)
	DeriveFromKeyWith(KDFPrfSkein512, master, "myapp/index", b)
	if !bytes.Equal(a, b) {
		t.Fatal("DeriveFromKey must equal DeriveFromKeyWith(KDFPrfSkein512, ..)")
	}
}

func TestDeriveFromKeyWithBLAKE3DeterministicDomainSeparatedAndDistinct(t *testing.T) {
	master := bytes.Repeat([]byte{0x42}, 32)
	a := make([]byte, 32)
	b := make([]byte, 32)
	DeriveFromKeyWith(KDFPrfBLAKE3, master, "myapp/index", a)
	DeriveFromKeyWith(KDFPrfBLAKE3, master, "myapp/index", b)
	if !bytes.Equal(a, b) {
		t.Fatal("same key + domain must give the same bytes")
	}

	c := make([]byte, 32)
	DeriveFromKeyWith(KDFPrfBLAKE3, master, "myapp/data", c)
	if bytes.Equal(a, c) {
		t.Fatal("a different domain must give a different key")
	}
	if bytes.Equal(a, master) {
		t.Fatal("a child never equals the master")
	}

	// The two PRFs are independent functions: the same key/domain under Skein
	// and under BLAKE3 must not coincide.
	sk := make([]byte, 32)
	DeriveFromKeyWith(KDFPrfSkein512, master, "myapp/index", sk)
	if bytes.Equal(a, sk) {
		t.Fatal("BLAKE3 and Skein fan-outs must differ")
	}
}

func TestDeriveFromKeyWithBLAKE3SupportsArbitraryOutputLengths(t *testing.T) {
	// BLAKE3 is an XOF, so any output length works and a longer output is the
	// prefix-extension of a shorter one (unlike Skein, where the length is
	// bound into the hash).
	master := bytes.Repeat([]byte{0x42}, 32)
	short := make([]byte, 32)
	long := make([]byte, 128)
	DeriveFromKeyWith(KDFPrfBLAKE3, master, "myapp/index", short)
	DeriveFromKeyWith(KDFPrfBLAKE3, master, "myapp/index", long)
	if !bytes.Equal(short, long[:32]) {
		t.Fatal("BLAKE3 is an XOF: a shorter output is the prefix of a longer one")
	}
}

func TestDeriveFromKeyWithBLAKE3RejectsNon32ByteKey(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected a panic for a non-32-byte BLAKE3 key")
		}
	}()
	out := make([]byte, 32)
	DeriveFromKeyWith(KDFPrfBLAKE3, make([]byte, 16), "myapp/index", out)
}

func TestDeriveFromPasswordDeterministicAndSaltSensitive(t *testing.T) {
	params := KDFParams{Kind: Pbkdf2, Rounds: 1000, Prf: PrfHMACSHA256}
	a, err := DeriveFromPassword(params, []byte("password"), []byte("saltsalt"), 32)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveFromPassword(params, []byte("password"), []byte("saltsalt"), 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("same inputs must give the same key")
	}
	c, err := DeriveFromPassword(params, []byte("password"), []byte("different"), 32)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, c) {
		t.Fatal("a different salt must give a different key")
	}
}

func TestValidateAcceptsSaneAndRejectsAbsurdParams(t *testing.T) {
	// Defaults are fine.
	if err := validate(KDFParams{Kind: Argon2id, MCost: 64 * 1024, TCost: 3, PCost: 1}); err != nil {
		t.Fatal(err)
	}
	if err := validate(KDFParams{Kind: Pbkdf2, Rounds: 600_000, Prf: PrfHMACSHA256}); err != nil {
		t.Fatal(err)
	}

	// Absurd costs (as a crafted header might carry) are rejected, as
	// ErrInvalidParams.
	absurd := []KDFParams{
		{Kind: Argon2id, MCost: 1 << 30, TCost: 3, PCost: 1}, // ~1 TiB
		{Kind: Argon2id, MCost: 1024, TCost: 1000, PCost: 1},
		{Kind: Argon2id, MCost: 1024, TCost: 3, PCost: 1000},
		{Kind: Scrypt, LogN: 40, R: 8, P: 1},
		{Kind: Scrypt, LogN: 15, R: 1000, P: 1},
		{Kind: Scrypt, LogN: 15, R: 8, P: 1000},
		{Kind: Pbkdf2, Rounds: 1<<32 - 1, Prf: PrfHMACSHA256},
	}
	for _, p := range absurd {
		if err := validate(p); !errors.Is(err, ErrInvalidParams) {
			t.Fatalf("validate(%+v) = %v, want ErrInvalidParams", p, err)
		}
	}
}

func TestValidateRejectsZeroPbkdf2Rounds(t *testing.T) {
	// Zero rounds would "derive" an all-zero key without error, so a header
	// carrying it is invalid, matching the Rust reference.
	err := validate(KDFParams{Kind: Pbkdf2, Rounds: 0, Prf: PrfHMACSHA256})
	if !errors.Is(err, ErrInvalidParams) {
		t.Fatalf("want ErrInvalidParams, got %v", err)
	}
	if err.Error() != "invalid parameters: pbkdf2 rounds must be nonzero" {
		t.Fatalf("unexpected message: %q", err.Error())
	}
}
