// dorado CLI (Node): encrypt/decrypt/inspect, raw-key and password modes. Port
// of the Rust/Go CLIs (GUI excluded). In-memory, matching the wire format.
import { readFileSync, writeFileSync } from "node:fs";
import { parseArgs } from "node:util";
import readline from "node:readline";
import process from "node:process";
import * as engine from "../engine/engine";
import * as fmt from "../engine/format";
import { wasmBackend } from "../engine/wasm-backend";
import { type Secret, secureFrom, wipe } from "./secret";
import { hexToBytes, utf8, bytesToHex, fromUtf8 } from "../bytes";

const options = {
  key: { type: "string" },
  "key-file": { type: "string" },
  iv: { type: "string" },
  unauthenticated: { type: "boolean", default: false },
  tweak: { type: "string", default: "00".repeat(16) },
  password: { type: "boolean", default: false },
  "password-stdin": { type: "boolean", default: false },
  variant: { type: "string", default: "256" },
  kdf: { type: "string", default: "argon2id" },
  mac: { type: "string", default: "skein" },
  "argon2-mem-mib": { type: "string", default: "64" },
  "argon2-time": { type: "string", default: "3" },
  "argon2-par": { type: "string", default: "1" },
  "scrypt-logn": { type: "string", default: "15" },
  "scrypt-r": { type: "string", default: "8" },
  "scrypt-p": { type: "string", default: "1" },
  "pbkdf2-rounds": { type: "string", default: "600000" },
  "chunk-kib": { type: "string", default: "64" },
  label: { type: "string" },
  "expect-label": { type: "string" },
  in: { type: "string" },
  out: { type: "string" },
  version: { type: "boolean", default: false },
  help: { type: "boolean", short: "h", default: false },
} as const;

const USAGE = `usage: dorado <encrypt|decrypt|inspect> [flags]

Apply Threefish in CTR mode, authenticated (encrypt-then-MAC) by default:
raw-key (--key/--key-file) or a password-derived authenticated container
(--password/--password-stdin). Raw-key mode splits the key into independent
encryption and MAC subkeys, so a tampered, corrupted, or wrong-key stream is
rejected on decrypt; add --unauthenticated to fall back to bare CTR instead
(no authentication, output length equals input length exactly) — a
deliberate, expert opt-out, since a corrupted or tampered byte in that mode
silently decrypts to a flipped plaintext byte with no error of any kind.

  --variant 256|512|1024     block size (password mode)
  --kdf argon2id|scrypt|pbkdf2   key derivation
  --mac skein|hmac-sha256|blake3 authentication (password and raw-key modes)
  --unauthenticated          raw-key mode: bare CTR, no tamper detection
  --chunk-kib N              authenticated chunk size (password and raw-key modes)
  --label / --expect-label   bind/require a non-secret label
  --in FILE / --out FILE      default stdin/stdout
  --version                  print version and exit
  -h, --help                 print this help and exit
`;

type Opts = { [K in keyof typeof options]?: string | boolean };

const int = (s: string) => {
  const n = parseInt(s, 10);
  if (!Number.isInteger(n)) throw new Error(`invalid number ${s}`);
  return n;
};
const str = (v: string | boolean | undefined) => (typeof v === "string" ? v : "");

function variantOf(o: Opts): fmt.Variant {
  const m: Record<string, fmt.Variant> = { "256": fmt.T256, "512": fmt.T512, "1024": fmt.T1024 };
  const v = m[str(o.variant)];
  if (v === undefined) throw new Error(`unknown variant ${o.variant}`);
  return v;
}
function macOf(o: Opts): fmt.MacId {
  const m: Record<string, fmt.MacId> = { skein: fmt.MAC_SKEIN, "hmac-sha256": fmt.MAC_HMAC, blake3: fmt.MAC_BLAKE3 };
  const v = m[str(o.mac)];
  if (v === undefined) throw new Error(`unknown mac ${o.mac}`);
  return v;
}
function kdfOf(o: Opts): fmt.KDFParams {
  switch (str(o.kdf)) {
    case "argon2id":
      return { kind: fmt.KDF_ARGON2ID, mCost: int(str(o["argon2-mem-mib"])) * 1024, tCost: int(str(o["argon2-time"])), pCost: int(str(o["argon2-par"])) };
    case "scrypt":
      return { kind: fmt.KDF_SCRYPT, logN: int(str(o["scrypt-logn"])), r: int(str(o["scrypt-r"])), p: int(str(o["scrypt-p"])) };
    case "pbkdf2":
      return { kind: fmt.KDF_PBKDF2, rounds: int(str(o["pbkdf2-rounds"])) };
  }
  throw new Error(`unknown kdf ${o.kdf}`);
}

function readInput(o: Opts): Uint8Array {
  return new Uint8Array(readFileSync(o.in ? str(o.in) : 0));
}
function writeOutput(o: Opts, data: Uint8Array): void {
  if (o.out) writeFileSync(str(o.out), data);
  else process.stdout.write(Buffer.from(data));
}
function dehex(s: string): Uint8Array {
  return hexToBytes(s.replace(/\s/g, ""));
}

function promptPassword(prompt: string): Promise<string> {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    process.stderr.write(prompt);
    (rl as unknown as { _writeToOutput: (s: string) => void })._writeToOutput = () => {};
    rl.question("", (ans) => {
      rl.close();
      process.stderr.write("\n");
      resolve(ans);
    });
  });
}

async function readPassword(o: Opts, confirm: boolean): Promise<Secret> {
  if (o["password-stdin"]) {
    const raw = new Uint8Array(readFileSync(0));
    const all = fromUtf8(raw);
    wipe(raw);
    return secureFrom(utf8(all.split(/\r?\n/)[0]));
  }
  const pw = await promptPassword("Password: ");
  if (confirm) {
    const again = await promptPassword("Confirm password: ");
    if (pw !== again) throw new Error("passwords do not match");
  }
  if (pw.length === 0) throw new Error("password must not be empty");
  // utf8(pw) is an ordinary heap buffer; secureFrom copies it into a guarded
  // buffer and wipes that copy. The JS string `pw` itself cannot be wiped.
  return secureFrom(utf8(pw));
}

function passwordMode(o: Opts): boolean {
  return !!o.password || !!o["password-stdin"];
}

async function cmdCrypt(o: Opts, encrypt: boolean): Promise<void> {
  const creds = [o.key, o["key-file"], o.password, o["password-stdin"]].filter(Boolean).length;
  if (creds !== 1) throw new Error("provide exactly one of --key, --key-file, --password, --password-stdin");

  if (!passwordMode(o)) {
    let keyHex = str(o.key);
    if (!keyHex) keyHex = readFileSync(str(o["key-file"]), "utf8");
    const key = dehex(keyHex);
    const variant = ({ 32: fmt.T256, 64: fmt.T512, 128: fmt.T1024 } as Record<number, fmt.Variant>)[key.length];
    if (variant === undefined) throw new Error(`key must be 32, 64, or 128 bytes, got ${key.length}`);
    if (!o.iv) throw new Error("--iv is required with --key/--key-file");
    try {
      const tweak = dehex(str(o.tweak));
      const iv = dehex(str(o.iv));
      let out: Uint8Array;
      if (o.unauthenticated) {
        // Bare CTR: symmetric, so encrypt and decrypt are the same operation.
        out = engine.rawCTR(variant, key, tweak, iv, readInput(o), wasmBackend);
      } else {
        // Authenticated (the default): encrypt-then-MAC is not symmetric, so
        // the subcommand selects the direction.
        const chunkSize = int(str(o["chunk-kib"])) * 1024;
        out = encrypt
          ? await engine.encryptRawAuthenticatedBytes(variant, key, tweak, iv, macOf(o), chunkSize, readInput(o), wasmBackend)
          : await engine.decryptRawAuthenticatedBytes(variant, key, tweak, iv, macOf(o), chunkSize, readInput(o), wasmBackend);
      }
      writeOutput(o, out);
    } finally {
      wipe(key);
    }
    return;
  }
  if (o.iv) throw new Error("--iv is not used in password mode; the IV is generated and stored");
  if (o.unauthenticated) throw new Error("--unauthenticated is not used in password mode, which is always authenticated");
  if (o["password-stdin"] && !o.in) throw new Error("with --password-stdin, pass the data via --in");

  const password = await readPassword(o, encrypt);
  try {
    if (encrypt) {
      const opts: engine.PasswordOptions = {
        variant: variantOf(o),
        kdf: kdfOf(o),
        mac: macOf(o),
        tweak: dehex(str(o.tweak)),
        chunkSize: int(str(o["chunk-kib"])) * 1024,
        label: o.label ? utf8(str(o.label)) : new Uint8Array(0),
      };
      const plaintext = readInput(o);
      try {
        writeOutput(o, await engine.encryptPasswordBytes(password.bytes, opts, plaintext, wasmBackend));
      } finally {
        wipe(plaintext);
      }
    } else {
      const expect = o["expect-label"] ? utf8(str(o["expect-label"])) : undefined;
      writeOutput(o, await engine.decryptPasswordBytes(password.bytes, readInput(o), expect, wasmBackend));
    }
  } finally {
    password.wipe();
  }
}

function cmdInspect(o: Opts): void {
  const info = engine.inspect(readInput(o));
  const variant = { [fmt.T256]: "Threefish-256", [fmt.T512]: "Threefish-512", [fmt.T1024]: "Threefish-1024" }[info.variant];
  let kdf = "";
  if (info.kdf.kind === fmt.KDF_ARGON2ID) kdf = `Argon2id (memory ${info.kdf.mCost} KiB, iterations ${info.kdf.tCost}, lanes ${info.kdf.pCost})`;
  else if (info.kdf.kind === fmt.KDF_SCRYPT) kdf = `scrypt (log2(N) ${info.kdf.logN}, r ${info.kdf.r}, p ${info.kdf.p})`;
  else kdf = `PBKDF2-HMAC-SHA256 (rounds ${info.kdf.rounds})`;
  const mac = { [fmt.MAC_SKEIN]: "Skein-512", [fmt.MAC_HMAC]: "HMAC-SHA256", [fmt.MAC_BLAKE3]: "BLAKE3 (keyed)" }[info.mac];
  const label = info.label.length > 0 ? fromUtf8(info.label) : "(none)";
  process.stdout.write(
    `format:   dorado password container (DRDO v${info.version})\n` +
      `variant:  ${variant}\nkdf:      ${kdf}\nmac:      ${mac}\n` +
      `chunk:    ${info.chunkSize} bytes\nsalt:     ${info.saltLen} bytes\n` +
      `tweak:    ${bytesToHex(info.tweak)}\nlabel:    ${label}\n`,
  );
}

async function main(): Promise<void> {
  const { values, positionals } = parseArgs({ options, allowPositionals: true });
  const o = values as Opts;
  if (o.help) {
    process.stdout.write(USAGE);
    return;
  }
  if (o.version) {
    console.log("dorado 0.1.0");
    return;
  }
  switch (positionals[0]) {
    case "encrypt":
      await cmdCrypt(o, true);
      break;
    case "decrypt":
      await cmdCrypt(o, false);
      break;
    case "inspect":
      cmdInspect(o);
      break;
    default:
      throw new Error("usage: dorado <encrypt|decrypt|inspect> [flags]");
  }
}

main().catch((e) => {
  console.error("error:", e instanceof Error ? e.message : e);
  process.exit(1);
});
