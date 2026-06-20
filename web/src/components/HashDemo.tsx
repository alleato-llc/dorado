// The in-browser hashing demo (the gyotaku tool, client-side). It Skein-512
// hashes the typed message live, over the WASM build of the verified Rust cipher,
// at a selectable output length. The digest is byte-for-byte what `gyotaku` prints
// for the same input and `--bits`.

import { useEffect, useState } from "preact/hooks";
import { utf8, bytesToHex } from "@ts/bytes";
import { browserBackend, ensureWasm } from "../lib/backend";

const SIZES = [256, 512, 1024] as const;
type Bits = (typeof SIZES)[number];

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

export default function HashDemo() {
  const [ready, setReady] = useState(false);
  const [message, setMessage] = useState("Threefish, from scratch, in your browser.");
  const [bits, setBits] = useState<Bits>(256);
  const [digest, setDigest] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    ensureWasm().then(
      () => setReady(true),
      (e) => setError(`failed to load the WASM cipher: ${errMsg(e)}`),
    );
  }, []);

  // Hash live: Skein is fast, so recompute on every change once the cipher is up.
  useEffect(() => {
    if (!ready) return;
    try {
      setDigest(bytesToHex(browserBackend.skeinHash(bits / 8, utf8(message))));
      setError("");
    } catch (e) {
      setError(errMsg(e));
    }
  }, [ready, message, bits]);

  return (
    <div class="demo">
      <div class="demo-controls">
        <label class="demo-field demo-wide">
          <span>Message</span>
          <textarea rows={2} value={message} onInput={(e) => setMessage(e.currentTarget.value)} />
        </label>
        <label class="demo-field">
          <span>Output length</span>
          <select value={String(bits)} onChange={(e) => setBits(Number(e.currentTarget.value) as Bits)}>
            {SIZES.map((b) => (
              <option value={String(b)}>{b}-bit</option>
            ))}
          </select>
        </label>
      </div>

      {digest && (
        <div class="demo-out">
          <div class="demo-meta">
            <span>Skein-512</span>
            <span>
              <b>{bits}</b>-bit
            </span>
            <span>{bits / 8} bytes</span>
          </div>
          <code class="demo-b64 mono">{digest}</code>
        </div>
      )}

      {!ready && !error && <p class="demo-note">Loading cipher...</p>}
      {error && (
        <div class="demo-result demo-err">
          <b>Error:</b> {error}
        </div>
      )}

      <p class="demo-note">
        Updates as you type. This is the same digest <code>gyotaku --bits {bits}</code> prints for the same input.
      </p>
    </div>
  );
}
