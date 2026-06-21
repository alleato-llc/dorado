// gyotaku: standalone Skein-512 hashing CLI (Node). Port of the Rust/Go tool.
import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import process from "node:process";
import * as skein from "../skein";
import { bytesToHex } from "../bytes";

function readStdin(): Uint8Array {
  return new Uint8Array(readFileSync(0));
}

function digest(data: Uint8Array, outLen: number): string {
  return bytesToHex(skein.hash(outLen, data));
}

function tagLine(d: string, name: string): string {
  return `SKEIN-512 (${name}) = ${d}`;
}

function isEvenHex(s: string): boolean {
  return s.length > 0 && s.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(s);
}

function parseCheckLine(line: string): [string, string] | null {
  const bsd = line.match(/^.+ \((.+)\) = ([0-9a-fA-F]+)$/);
  if (bsd && isEvenHex(bsd[2])) return [bsd[2], bsd[1]];
  const sp = line.indexOf(" ");
  if (sp < 0) return null;
  const d = line.slice(0, sp);
  if (!isEvenHex(d)) return null;
  const name = line.slice(sp + 1).trimStart().replace(/^\*/, "");
  return [d, name];
}

function runCheck(files: string[]): void {
  let checked = 0,
    failed = 0;
  for (const list of files) {
    for (const raw of readFileSync(list, "utf8").split("\n")) {
      const line = raw.trim();
      if (line === "" || line.startsWith("#")) continue;
      const parsed = parseCheckLine(line);
      if (!parsed) throw new Error(`${list}: malformed line: ${line}`);
      const [expected, name] = parsed;
      checked++;
      try {
        const got = digest(new Uint8Array(readFileSync(name)), expected.length / 2);
        if (got.toLowerCase() === expected.toLowerCase()) console.log(`${name}: OK`);
        else {
          console.log(`${name}: FAILED`);
          failed++;
        }
      } catch {
        console.log(`${name}: FAILED open or read`);
        failed++;
      }
    }
  }
  if (checked === 0) throw new Error("no digests found to verify");
  if (failed > 0) throw new Error(`${failed} of ${checked} digests did NOT match`);
}

const USAGE = `usage: gyotaku [flags] [FILE...]

Hash files (or stdin when no FILE is given) with Skein-512, like sha256sum.

  --bits N      output length in bits, a multiple of 8 (default 256)
  --tag         BSD-style output: "SKEIN-512 (file) = digest"
  -c, --check   read digests from the FILEs and verify them
  --version     print version and exit
  -h, --help    print this help and exit
`;

function main(): void {
  const { values, positionals } = parseArgs({
    options: {
      bits: { type: "string", default: "256" },
      tag: { type: "boolean", default: false },
      c: { type: "boolean", short: "c", default: false },
      check: { type: "boolean", default: false },
      version: { type: "boolean", default: false },
      help: { type: "boolean", short: "h", default: false },
    },
    allowPositionals: true,
  });
  if (values.help) {
    process.stdout.write(USAGE);
    return;
  }
  if (values.version) {
    console.log("gyotaku 0.1.0");
    return;
  }
  if (values.c || values.check) {
    if (values.tag) throw new Error("--tag cannot be combined with -c");
    if (positionals.length === 0) throw new Error("-c needs at least one checksum file");
    runCheck(positionals);
    return;
  }
  const bits = parseInt(values.bits, 10);
  if (!Number.isInteger(bits) || bits <= 0 || bits % 8 !== 0) throw new Error("--bits must be a positive multiple of 8");
  const outLen = bits / 8;

  if (positionals.length === 0) {
    const d = digest(readStdin(), outLen);
    console.log(values.tag ? tagLine(d, "-") : d);
    return;
  }
  for (const path of positionals) {
    const d = digest(new Uint8Array(readFileSync(path)), outLen);
    console.log(values.tag ? tagLine(d, path) : `${d}  ${path}`);
  }
}

try {
  main();
} catch (e) {
  console.error("error:", e instanceof Error ? e.message : e);
  process.exit(1);
}
