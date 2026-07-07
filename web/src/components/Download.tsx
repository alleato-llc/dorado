import { useEffect, useState } from "preact/hooks";
import type { DownloadUrls } from "../lib/releases";

// Platform-aware download control. The build-time resolver (src/lib/releases.ts)
// passes the resolved per-platform URLs in as props; this island only detects
// the visitor's OS/arch client-side and picks which button to lead with.
//
// Progressive enhancement (client:load in index.astro): the server-rendered
// (pre-hydration) and JS-off state is "unknown" -> a full all-platforms list,
// so it's useful with no JavaScript.

type OS = "mac" | "windows" | "linux" | "unknown";
type Arch = "x64" | "arm64";

interface NavigatorUAData {
  platform?: string;
  getHighEntropyValues?: (hints: string[]) => Promise<{ architecture?: string }>;
}

function detectOS(): OS {
  if (typeof navigator === "undefined") return "unknown";
  const ua = navigator.userAgent;
  // No CLI build for phones/tablets -> fall through to the list.
  if (/android|iphone|ipad|ipod/i.test(ua)) return "unknown";
  const uaData = (navigator as unknown as { userAgentData?: NavigatorUAData }).userAgentData;
  const plat = (uaData?.platform ?? navigator.platform ?? "").toLowerCase();
  if (/mac/.test(plat) || /mac os x/i.test(ua)) return "mac";
  if (/win/.test(plat) || /windows/i.test(ua)) return "windows";
  if (/linux|x11/.test(plat) || /linux/i.test(ua)) return "linux";
  return "unknown";
}

export default function Download(urls: DownloadUrls) {
  const [os, setOS] = useState<OS>("unknown");
  const [arch, setArch] = useState<Arch>("x64");

  useEffect(() => {
    setOS(detectOS());
    // Arch only matters on macOS (separate arm64/x86_64 binaries, no universal
    // binary). Prefer the high-entropy UA hint; fall back to the UA string;
    // default x64.
    const uaData = (navigator as unknown as { userAgentData?: NavigatorUAData }).userAgentData;
    if (uaData?.getHighEntropyValues) {
      uaData
        .getHighEntropyValues(["architecture"])
        .then((v) => {
          if (v.architecture === "arm") setArch("arm64");
        })
        .catch(() => {});
    } else if (/arm64|aarch64/i.test(navigator.userAgent)) {
      setArch("arm64");
    }
  }, []);

  if (os === "mac") {
    const primary = arch === "arm64" ? urls.macosArm64 : urls.macosX64;
    const other = arch === "arm64"
      ? { href: urls.macosX64, label: "Intel" }
      : { href: urls.macosArm64, label: "Apple Silicon" };
    return (
      <>
        <a class="btn primary" href={primary}>Download for macOS</a>
        <p class="demo-note">
          Other Mac? <a href={other.href}>{other.label} build</a> ·{" "}
          <a href={urls.releasesPage}>all downloads</a>
        </p>
      </>
    );
  }

  if (os === "windows") {
    return (
      <>
        <a class="btn primary" href={urls.windowsX64}>Download for Windows</a>
        <p class="demo-note"><a href={urls.releasesPage}>all downloads</a></p>
      </>
    );
  }

  if (os === "linux") {
    return (
      <>
        <a class="btn primary" href={urls.linuxX64}>Download for Linux</a>
        <p class="demo-note"><a href={urls.releasesPage}>all downloads</a></p>
      </>
    );
  }

  // Unknown / no-JS: a full, static all-platforms list.
  return (
    <>
      <a class="btn primary" href={urls.releasesPage}>See all downloads</a>
      <p class="demo-note">
        <a href={urls.macosArm64}>macOS (Apple Silicon)</a> ·{" "}
        <a href={urls.macosX64}>macOS (Intel)</a> ·{" "}
        <a href={urls.linuxX64}>Linux</a> ·{" "}
        <a href={urls.windowsX64}>Windows</a>
      </p>
    </>
  );
}
