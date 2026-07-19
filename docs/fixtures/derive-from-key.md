# Key-based derivation (`derive_from_key`): cross-language known-answer vectors

Generated from the Rust reference implementation
(`dorado-engine::kdf::derive_from_key_with`), which is the baseline for these
vectors per the top-level `CLAUDE.md`. Every other port's test suite should
hardcode these as known-answer tests: derive `out_len` bytes from the given
key and domain under the given PRF and confirm the output matches
byte-for-byte.

The construction is one domain-separated keyed hash:

```
out = PRF(key = caller_key, out_len = out_len,
          msg = "DRDOkdrv" || domain_utf8)
```

where PRF is either the Skein-512 keyed (MAC-mode) hash at the requested
output length (the default; accepts a key of any length) or the BLAKE3 keyed
hash (requires a 32-byte key, BLAKE3's keyed mode being defined only for a
256-bit key). The fixed `DRDOkdrv` prefix domain-separates this derivation
from every other keyed use in the engine (`DRDOrawE`/`DRDOrawM` in the
raw-key split, `DRDOchnk`/`DRDOrwFr` in the frame MACs). The default,
PRF-less form (`derive_from_key`) is defined as the Skein-512 case and must
match those vectors byte-for-byte.

This is library API only: nothing here touches the on-disk container format.
A password must never take this path (there is no stretching); that is
`derive_from_password`'s job.

All values are hex-encoded except `domain`, which is the literal UTF-8 string
between the quotes.

## Vector: skein_32key_enc_32out

- prf: skein512
- key: `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`
- domain: `"dorado/fixture/enc"`
- out_len: 32
- out: `b638c503342dbd51bdfa8906b1cc6b18d7e54252b95e460c522ab3cd939802c6`

## Vector: skein_32key_mac_64out

Same key, different domain and length: the output must be computationally
unrelated to `skein_32key_enc_32out` (domain separation), and a longer
`out_len` is a different Skein output-length configuration, not a truncation
or extension of the shorter one.

- prf: skein512
- key: `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`
- domain: `"dorado/fixture/mac"`
- out_len: 64
- out: `6ae3f6f7518e9a4c8a7be8269deb848186beb64b5b43f0bafef81bce4b27d40ef227e2064b941069cc6225cad0a39fcc22aba08fb87f3ba8aacdf4b70b100da6`

## Vector: skein_16key_enc_32out

A non-32-byte key: the Skein-512 PRF accepts a key of any length.

- prf: skein512
- key: `a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5`
- domain: `"dorado/fixture/enc"`
- out_len: 32
- out: `3990e038c7235e62480afe99712203225194afb93910df4101447098e630d0e4`

## Vector: skein_32key_empty_domain_32out

The empty domain is valid (the `DRDOkdrv` prefix alone is the message).

- prf: skein512
- key: `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`
- domain: `""`
- out_len: 32
- out: `5bba4214745b3932c1fc620c660b60a4058613ff2bd9d80224d472cd810f7a99`

## Vector: blake3_32key_enc_32out

- prf: blake3
- key: `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`
- domain: `"dorado/fixture/enc"`
- out_len: 32
- out: `8266bd0cfb0d73715aa841fe008c311a44d6b36e0aa01b94f13a90783fe62e1d`

## Vector: blake3_32key_mac_64out

- prf: blake3
- key: `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`
- domain: `"dorado/fixture/mac"`
- out_len: 64
- out: `ea38a1780192707518d15003262a66c245680a579762a7d863cc33078f2f6eaa9a5086f70d00eb7c6cd12fdc7872e5a2023e63c28087631ce835d7e9c7264290`
