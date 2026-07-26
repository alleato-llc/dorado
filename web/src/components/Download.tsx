import { useEffect, useRef, useState } from "preact/hooks";
import type { CliUrls, DownloadUrls, GuiUrls } from "../lib/releases";

// The hero download controls. Two OS-aware dropdowns (Desktop apps, Command
// line tools) plus a "View the source" link. The build-time resolver
// (src/lib/releases.ts) passes the per-platform URLs in as props; this island
// only detects the visitor's OS/arch client-side and points each menu item at
// the right build.
//
// Progressive enhancement (client:load in index.astro): the server-rendered
// (pre-hydration) and JS-off state is "unknown", which renders a flat set of
// links to the Releases page instead of dropdowns (a menu toggle needs JS to
// open), so the section is still useful with no JavaScript.

type OS = "mac" | "windows" | "linux" | "unknown";
type Arch = "x64" | "arm64";

interface NavigatorUAData {
  platform?: string;
  getHighEntropyValues?: (hints: string[]) => Promise<{ architecture?: string }>;
}

function detectOS(): OS {
  if (typeof navigator === "undefined") return "unknown";
  const ua = navigator.userAgent;
  // No desktop/CLI build for phones/tablets, so fall through to the list.
  if (/android|iphone|ipad|ipod/i.test(ua)) return "unknown";
  const uaData = (navigator as unknown as { userAgentData?: NavigatorUAData }).userAgentData;
  const plat = (uaData?.platform ?? navigator.platform ?? "").toLowerCase();
  if (/mac/.test(plat) || /mac os x/i.test(ua)) return "mac";
  if (/win/.test(plat) || /windows/i.test(ua)) return "windows";
  if (/linux|x11/.test(plat) || /linux/i.test(ua)) return "linux";
  return "unknown";
}

interface MenuItem {
  name: string;
  sub: string;
  href: string;
}

// One dropdown: a styled button that reveals a menu of downloads. Closes on
// outside click, on Escape, and after a pick.
function DownloadMenu(props: {
  label: string;
  primary?: boolean;
  items: MenuItem[];
  allHref: string;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  return (
    <div class="dl-menu" ref={ref}>
      <button
        type="button"
        class={`btn ${props.primary ? "primary" : "ghost"} dl-toggle`}
        aria-haspopup="true"
        aria-expanded={open}
        onClick={() => setOpen(!open)}
      >
        {props.label}
        <span class={`dl-caret${open ? " is-open" : ""}`} aria-hidden="true">
          ▾
        </span>
      </button>
      {open && (
        <div class="dl-panel" role="menu">
          {props.items.map((it) => (
            <a class="dl-item" role="menuitem" href={it.href} onClick={() => setOpen(false)}>
              <span class="dl-name">{it.name}</span>
              <span class="dl-sub">{it.sub}</span>
            </a>
          ))}
          <a class="dl-all" role="menuitem" href={props.allHref}>
            All platforms and versions
          </a>
        </div>
      )}
    </div>
  );
}

export default function Download(props: DownloadUrls & { repo: string; docsHref: string }) {
  const [os, setOS] = useState<OS>("unknown");
  const [arch, setArch] = useState<Arch>("x64");

  useEffect(() => {
    setOS(detectOS());
    // Arch only matters for the CLI on macOS (separate arm64/x86_64 binaries; no
    // universal CLI binary). The GUI's macOS dmg is universal. Prefer the
    // high-entropy UA hint, fall back to the UA string, default x64.
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

  // Pre-hydration / no-JS / undetected: a flat, dropdown-free layout that points
  // at the Releases page (which lists every platform), so it works with no JS.
  if (os === "unknown") {
    return (
      <>
        <div class="cta">
          <a class="btn primary" href={props.releasesPage}>
            Download for Desktop
          </a>
          <a class="btn ghost" href={props.releasesPage}>
            Download CLI
          </a>
          <a class="btn ghost" href={props.repo}>
            View the source
          </a>
        </div>
        <p class="demo-note">
          <a href={props.releasesPage}>All platforms and downloads</a> ·{" "}
          <a href={props.docsHref}>read the docs</a>
        </p>
      </>
    );
  }

  const osLabel = os === "mac" ? "macOS" : os === "windows" ? "Windows" : "Linux";
  const guiSub =
    os === "mac" ? "macOS · universal" : os === "windows" ? "Windows · x86_64" : "Linux · x86_64";
  const cliSub =
    os === "mac"
      ? `macOS · ${arch === "arm64" ? "Apple Silicon" : "Intel"}`
      : os === "windows"
        ? "Windows · x86_64"
        : "Linux · x86_64";

  const guiHref = (u: GuiUrls): string =>
    os === "windows" ? u.windows : os === "linux" ? u.linux : u.macUniversal;
  const cliHref = (u: CliUrls): string => {
    if (os === "windows") return u.windows;
    if (os === "linux") return u.linux;
    return arch === "arm64" ? u.macArm64 : u.macX64;
  };

  const desktopItems: MenuItem[] = [
    { name: "dorado", sub: `encrypt / decrypt · ${guiSub}`, href: guiHref(props.desktopDorado) },
    { name: "gyotaku", sub: `hashing · ${guiSub}`, href: guiHref(props.desktopGyotaku) },
  ];
  const cliItems: MenuItem[] = [
    { name: "dorado", sub: `encrypt / decrypt · ${cliSub}`, href: cliHref(props.cliDorado) },
    { name: "gyotaku", sub: `hashing · ${cliSub}`, href: cliHref(props.cliGyotaku) },
  ];

  return (
    <>
      <div class="cta">
        <DownloadMenu
          primary
          label="Download for Desktop"
          items={desktopItems}
          allHref={props.releasesPage}
        />
        <DownloadMenu label="Download CLI" items={cliItems} allHref={props.releasesPage} />
        <a class="btn ghost" href={props.repo}>
          View the source
        </a>
      </div>
      <p class="demo-note">
        {osLabel} detected · <a href={props.releasesPage}>all platforms</a> ·{" "}
        <a href={props.docsHref}>read the docs</a>
      </p>
    </>
  );
}
