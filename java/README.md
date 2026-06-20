# dorado (Java)

A Java port of dorado, matching the Rust reference (`../rust`) and the Go and
TypeScript ports. Same from-scratch primitives against the same official vectors,
the same on-disk container format (byte-for-byte cross-compatible with the other
ports), and the same streaming construction. It is an **SDK only** (a library, no
CLI and no GUI).

Like the Rust reference and the Go port, it **streams** over
`InputStream`/`OutputStream` in constant memory, so inputs larger than RAM are
fine; `byte[]` convenience wrappers are provided. Java's `long` is a native 64-bit
two's-complement integer, so the Threefish ARX needs no big-integer workaround.
Educational and unaudited; for real data prefer a vetted library.

## Layout

- `src/main/java/com/alleato/dorado/Threefish.java`, `Skein.java`, `Blake3.java` —
  the from-scratch primitives (Threefish 256/512/1024 + CTR, Skein-512, BLAKE3),
  verified against the same vectors as the Rust reference.
- `src/main/java/com/alleato/dorado/engine/` — the construction: `Format` (the
  container header), `Kdf` (Argon2id, scrypt, PBKDF2 via Bouncy Castle), `Mac` (the
  MAC menu; HMAC-SHA256 from the JDK), and `Engine` (the streaming password
  container, raw CTR, and inspect). `DoradoException` marks a bad or
  failed-authentication container.

The cipher and hashes are from-scratch; only the KDFs are a dependency
(`org.bouncycastle:bcprov-jdk18on`), matching the other ports' use of a KDF library.

## Use

```
./gradlew test     # the full JUnit suite (KATs, every KDF/MAC/variant, security
                   # properties, and cross-compat fixtures made by the Rust CLI)
./gradlew build    # compile + test + jar
```

```java
import com.alleato.dorado.engine.Engine;
import com.alleato.dorado.engine.Engine.PasswordOptions;

byte[] password = "correct horse battery staple".getBytes();
PasswordOptions opts = Engine.defaultOptions();           // Threefish-256, Argon2id, Skein-512
byte[] container = Engine.encryptPassword(password, opts, plaintext);
byte[] recovered = Engine.decryptPassword(password, container);

// Or stream in constant memory:
Engine.encryptPasswordStream(password, opts, inputStream, outputStream);
Engine.decryptPasswordStream(password, inputStream, outputStream);
```

## Cross-compatibility

The container bytes are identical to the Rust/Go/TypeScript ports: each can decrypt
the others' `.mahi` files. `CrossCompatTest` decrypts fixtures produced by the Rust
reference (in `src/test/resources/crosscompat/`) covering every KDF, MAC, and
variant plus a labeled and a multi-frame file; the reverse direction (the Rust and
Go CLIs decrypting Java's output) is verified during development.
