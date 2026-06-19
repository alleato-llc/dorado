# Glossary

Plain-language definitions of the cryptography and engineering terms used in
dorado, aimed at a technical reader who is comfortable with bits and bytes but is
not a cryptographer. Each entry says what the term means in general and, where
relevant, how dorado uses it. None of this is a security claim; dorado is an
educational, unaudited project.

For how these pieces fit together, see `overview.md` (conceptual) and `spec.md`
(the byte-level format).

## The cipher and modes

**Plaintext / ciphertext.** Plaintext is the original, readable data. Ciphertext
is the scrambled output. Encryption turns plaintext into ciphertext under a key;
decryption reverses it with the same key.

**Key.** A secret value (here, a fixed-size run of high-entropy random bytes, for
example 32 bytes) that controls the scrambling. The same key encrypts and decrypts,
which is what "symmetric" means. Anyone holding the key can read the data, so
protecting the key is the entire game.

**Block cipher.** An algorithm that encrypts a single fixed-size chunk of data (a
"block") under a key, reversibly. Think of it as a keyed, invertible shuffle of
exactly one block's worth of bytes. By itself it can only handle one block.
Threefish is a block cipher; it is the actual algorithm dorado implements.

**Block / block size.** The fixed amount of data a block cipher processes at once.
Threefish comes in 32-, 64-, and 128-byte block sizes (the 256, 512, and 1024-bit
variants).

**Tweakable block cipher / tweak.** A block cipher with an extra, non-secret input
called a tweak that varies the encryption, a bit like a second key you do not have
to keep secret. It lets one key produce different permutations for different
positions or contexts. Threefish takes a 16-byte tweak.

**Mode of operation.** A standard recipe that wraps a block cipher so it can handle
data of any length, not just one block. The cipher handles a block; the mode
decides how to chain blocks together. Modes are generic: the same mode works with
AES, Threefish, or any block cipher. CTR is the mode dorado uses.

**CTR (counter mode).** A mode that turns a block cipher into a stream cipher. It
encrypts a counter (0, 1, 2, ...) to produce a pseudorandom keystream, then XORs
that keystream into the data. To decrypt, you regenerate the same keystream and XOR
it back out. It handles any length and needs no padding. The one hard rule: never
start the counter at the same value (IV) twice under the same key, or the keystream
repeats and leaks information.

**Keystream.** The pseudorandom byte sequence that a stream cipher (or CTR)
produces and XORs with the data. The same keystream both encrypts and decrypts.

**Stream cipher.** A cipher that generates a keystream and XORs it with the data,
rather than operating on fixed blocks. CTR makes a block cipher behave like one.

**IV / nonce / counter.** The starting value CTR feeds into the cipher. "Nonce"
means "number used once." It is not secret, but it must be unique for each message
under a given key. In dorado the IV is one block wide.

**XOR.** Bitwise exclusive-or, the reversible combine operation: `a XOR b XOR b`
gives back `a`. CTR encrypts by XORing the keystream into the data and decrypts by
XORing the same keystream back out.

**ARX.** Add-Rotate-XOR: a cipher design built only from modular addition, bit
rotation by fixed amounts, and XOR, with no lookup tables. Threefish is ARX. A
useful consequence is that it has no secret-dependent table lookups or branches,
which tends to make it run in constant time (see below).

## Passwords and key derivation

**Password versus key.** A password is a human-memorable, low-entropy string. A key
is full-entropy bytes of an exact size. A password is not a key and cannot be used
directly as one. A KDF converts the first into the second.

**KDF (key derivation function).** A function that stretches a password (plus a
salt) into a proper cryptographic key of the required length. A good password KDF
is deliberately slow and memory-hungry, so that guessing billions of candidate
passwords is expensive. dorado supports three: Argon2id, scrypt, and PBKDF2.

**Salt.** A random, non-secret value mixed into the KDF so that the same password
produces a different key every time. This defeats precomputed lookup tables and
makes each derivation unique. The salt is stored alongside the ciphertext and read
back at decryption time.

**Memory-hard.** A property of a KDF where each guess requires a large amount of
RAM, not just CPU time. This makes mass guessing on GPUs and custom hardware much
more expensive. Argon2 and scrypt are memory-hard; PBKDF2 is not.

**Argon2 / Argon2id.** The modern recommended password KDF, winner of the Password
Hashing Competition. Argon2id is the balanced variant dorado defaults to.

**scrypt.** An older memory-hard password KDF, still solid and widely supported.

**PBKDF2.** An older, CPU-only password KDF with no memory hardness. Still used
where FIPS or legacy compatibility is required.

**Cost parameters / iterations.** The knobs that set how slow and expensive a KDF
is (PBKDF2's iteration count, Argon2's memory and pass counts, scrypt's `N`).
Higher values are harder to brute-force and slower for you. They are stored in the
file header so decryption reproduces the same derivation.

## Authentication and integrity

**Confidentiality.** Keeping data secret from anyone without the key. Encryption
provides this. On its own it does not guarantee the data was not altered.

**Integrity / authentication.** Assurance that data was not modified (integrity)
and came from someone holding the key (authenticity). Encryption alone does not
provide this; you need a MAC.

**MAC (message authentication code).** A short tag computed from the data and a
secret key. Anyone with the key can recompute it to confirm the data is unchanged
and genuine; an attacker without the key cannot forge a valid tag. dorado uses
HMAC-SHA256.

**HMAC.** A specific, well-studied way to build a MAC out of a hash function (here
SHA-256). You compute `HMAC(key, data)` and get a tag.

**Encrypt-then-MAC.** The safe order for combining encryption and a MAC: encrypt
the data, then compute the MAC over the ciphertext. On decryption, verify the MAC
first and only decrypt if it passes. dorado's password files do this for every
chunk, which is also why a wrong password is reported cleanly instead of producing
garbage.

**Associated data.** Data that the MAC authenticates but does not encrypt, for
example a file header. Tampering with it is still detected even though it stays
readable.

**AEAD (authenticated encryption with associated data).** A construction that
provides confidentiality and integrity together, optionally binding associated
data. dorado's password mode is effectively a hand-built streaming AEAD (CTR plus
HMAC); it does not use a standalone AEAD primitive.

**Tag / authentication tag.** The MAC output stored with the data and checked on
decryption. In dorado each chunk ends with a 32-byte tag.

## Hashing and the wider family

**Hash function.** A one-way function that maps any-length input to a fixed-size
digest, such that you cannot reverse it or find two inputs with the same digest. It
is used for integrity checks and fingerprints. Skein is a hash function; dorado
does not implement it yet.

**Skein / UBI.** Skein is the hash function Threefish was built to power, a finalist
in the NIST SHA-3 competition. UBI (Unique Block Iteration) is the chaining mode
that turns repeated Threefish calls into Skein. Threefish is the engine; Skein is
the car built around it.

**Blowfish / Twofish / Threefish.** Three block ciphers from Bruce Schneier's
lineage. The names count up, but they are distinct designs, not versions of one
another.

## Engineering terms used in dorado

**Endianness (little-endian / big-endian).** The byte order used to store a
multi-byte number. Little-endian puts the least significant byte first; big-endian
puts the most significant byte first. It matters whenever you convert between bytes
and numbers. Threefish treats its words as little-endian; the file format's integer
fields are big-endian.

**Wrapping arithmetic.** Integer math that silently wraps around on overflow
(modulo 2 to the 64th) instead of erroring. Ciphers depend on this; dorado uses
wrapping addition and subtraction throughout the cipher.

**Constant-time.** Code whose running time does not depend on secret values, so an
attacker cannot learn the key by measuring timing. ARX ciphers with no
secret-dependent branches or lookups tend to behave this way. dorado treats this as
a property of the design, not a guarantee.

**Zeroize.** Explicitly wiping secrets (keys, passwords, derived key material) from
memory once they are no longer needed, so they do not linger. dorado does this for
the CLI's secrets.

**Test vector / known-answer test (KAT).** A published input-and-expected-output
pair from an authority, used to confirm an implementation matches the specification
exactly. dorado embeds official Threefish vectors for each block size.

**Differential testing.** Checking your implementation against a second,
independent one over many random inputs; if they ever disagree, at least one has a
bug. dorado tests against the RustCrypto `threefish` crate.

**Fuzzing.** Feeding a function many automatically generated, malformed inputs to
hunt for crashes, panics, or hangs. It is a testing technique, not shipped code.
Proposed for dorado's header and frame parser.
