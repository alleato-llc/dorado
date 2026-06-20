// The in-browser demo: encrypt a message to a password container and decrypt it
// back, entirely client-side, using the TypeScript engine (`@ts/`) on top of the
// WASM build of the verified Rust cipher. The container bytes are byte-for-byte
// identical to the ones the Rust/Go/TS CLIs produce, so a file made here decrypts
// with `dorado decrypt` and vice versa.

import { useEffect, useState } from "preact/hooks";
import * as engine from "@ts/engine/engine";
import * as fmt from "@ts/engine/format";
import { utf8, fromUtf8 } from "@ts/bytes";
import { browserBackend, ensureWasm } from "../lib/backend";

const VARIANTS: [string, fmt.Variant][] = [
  ["Threefish-256", fmt.T256],
  ["Threefish-512", fmt.T512],
  ["Threefish-1024", fmt.T1024],
];
const MACS: [string, fmt.MacId][] = [
  ["Skein-512", fmt.MAC_SKEIN],
  ["HMAC-SHA256", fmt.MAC_HMAC],
  ["BLAKE3 (keyed)", fmt.MAC_BLAKE3],
];
const KDFS = ["argon2id", "scrypt", "pbkdf2"] as const;
type Kdf = (typeof KDFS)[number];

// Deliberately light cost parameters so the demo stays snappy in a browser tab.
// The real CLIs default much higher; these are for illustration only.
function kdfParams(kdf: Kdf): fmt.KDFParams {
  if (kdf === "scrypt") return { kind: fmt.KDF_SCRYPT, logN: 14, r: 8, p: 1 };
  if (kdf === "argon2id") return { kind: fmt.KDF_ARGON2ID, mCost: 16 * 1024, tCost: 2, pCost: 1 };
  return { kind: fmt.KDF_PBKDF2, rounds: 100_000 };
}

function toBase64(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s);
}

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

export default function Demo() {
  const [ready, setReady] = useState(false);
  const [message, setMessage] = useState("Threefish, from scratch, in your browser.");
  const [password, setPassword] = useState("correct horse battery staple");
  const [variant, setVariant] = useState<fmt.Variant>(fmt.T256);
  const [mac, setMac] = useState<fmt.MacId>(fmt.MAC_SKEIN);
  const [kdf, setKdf] = useState<Kdf>("argon2id");
  const [tamper, setTamper] = useState(false);

  const [container, setContainer] = useState<Uint8Array | null>(null);
  const [recovered, setRecovered] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    ensureWasm().then(
      () => setReady(true),
      (e) => setError(`failed to load the WASM cipher: ${errMsg(e)}`),
    );
  }, []);

  async function onEncrypt() {
    setBusy(true);
    setError("");
    setRecovered("");
    setContainer(null);
    try {
      const opts: engine.PasswordOptions = {
        variant,
        kdf: kdfParams(kdf),
        mac,
        tweak: new Uint8Array(16),
        chunkSize: fmt.DEFAULT_CHUNK_BYTES,
        label: new Uint8Array(0),
      };
      const c = await engine.encryptPasswordBytes(utf8(password), opts, utf8(message), browserBackend);
      setContainer(c);
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setBusy(false);
    }
  }

  async function onDecrypt() {
    if (!container) return;
    setBusy(true);
    setError("");
    setRecovered("");
    try {
      const data = container.slice();
      if (tamper && data.length > 0) {
        // Flip one byte of the last chunk's ciphertext to show the MAC reject it.
        data[data.length - 8] ^= 0x01;
      }
      const pt = await engine.decryptPasswordBytes(utf8(password), data, undefined, browserBackend);
      setRecovered(fromUtf8(pt));
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setBusy(false);
    }
  }

  const info = container ? engine.inspect(container) : null;
  const kdfLabel = (k: fmt.KDFParams) =>
    k.kind === fmt.KDF_ARGON2ID
      ? `Argon2id (${k.mCost! / 1024} MiB, t=${k.tCost}, p=${k.pCost})`
      : k.kind === fmt.KDF_SCRYPT
        ? `scrypt (log2N=${k.logN}, r=${k.r}, p=${k.p})`
        : `PBKDF2-HMAC-SHA256 (${k.rounds} rounds)`;
  const variantName = VARIANTS.find(([, v]) => v === (info?.variant ?? -1))?.[0] ?? "";
  const macName = MACS.find(([, m]) => m === (info?.mac ?? -1))?.[0] ?? "";

  return (
    <div class="demo">
      <div class="demo-controls">
        <label class="demo-field demo-wide">
          <span>Message</span>
          <textarea rows={3} value={message} onInput={(e) => setMessage(e.currentTarget.value)} />
        </label>
        <label class="demo-field demo-wide">
          <span>Password</span>
          <input type="text" value={password} onInput={(e) => setPassword(e.currentTarget.value)} />
        </label>
        <label class="demo-field">
          <span>Cipher</span>
          <select value={String(variant)} onChange={(e) => setVariant(Number(e.currentTarget.value) as fmt.Variant)}>
            {VARIANTS.map(([name, v]) => (
              <option value={String(v)}>{name}</option>
            ))}
          </select>
        </label>
        <label class="demo-field">
          <span>MAC</span>
          <select value={String(mac)} onChange={(e) => setMac(Number(e.currentTarget.value) as fmt.MacId)}>
            {MACS.map(([name, m]) => (
              <option value={String(m)}>{name}</option>
            ))}
          </select>
        </label>
        <label class="demo-field">
          <span>KDF</span>
          <select value={kdf} onChange={(e) => setKdf(e.currentTarget.value as Kdf)}>
            {KDFS.map((k) => (
              <option value={k}>{k}</option>
            ))}
          </select>
        </label>
      </div>

      <div class="demo-actions">
        <button class="btn primary" disabled={!ready || busy} onClick={onEncrypt}>
          {ready ? "Encrypt" : "Loading cipher..."}
        </button>
        <button class="btn ghost" disabled={!ready || busy || !container} onClick={onDecrypt}>
          Decrypt
        </button>
        <label class="demo-check">
          <input type="checkbox" checked={tamper} onChange={(e) => setTamper(e.currentTarget.checked)} />
          <span>tamper before decrypt</span>
        </label>
      </div>

      {info && (
        <div class="demo-out">
          <div class="demo-meta">
            <span>
              <b>{container!.length}</b> bytes
            </span>
            <span>{variantName}</span>
            <span>{macName}</span>
            <span>{kdfLabel(info.kdf)}</span>
            <span>DRDO v{info.version}</span>
          </div>
          <code class="demo-b64 mono">{toBase64(container!)}</code>
        </div>
      )}

      {recovered && (
        <div class="demo-result demo-ok">
          <b>Decrypted:</b> {recovered}
        </div>
      )}
      {error && (
        <div class="demo-result demo-err">
          <b>Rejected:</b> {error}
        </div>
      )}

      <p class="demo-note">
        Runs entirely in your browser. The container bytes are identical to the CLI's, so this file decrypts with{" "}
        <code>dorado decrypt</code>. Cost parameters here are deliberately low for speed; this is a demo,{" "}
        <strong>not a secure tool</strong>. The Rust and Go builds work the same way but handle secrets more
        carefully (<a href="#implementations">see the comparison below</a>).
      </p>
    </div>
  );
}
