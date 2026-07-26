// Build-time resolution of the Rust release track's download URLs.
//
// Mirrors soroban's site/src/lib/releases.ts. Runs in Astro frontmatter, i.e. at
// BUILD time (Node). It makes a single HTTP request to the Releases API for the
// newest `rust-v*` tag (the only release track dorado has, see
// ../.github/workflows/release.yml) and reads the asset names off it.
//
// It resolves four groups, matching salpa's naming (see ../../rust/*.yaml):
//   - desktop GUIs: a SIGNED UNIVERSAL macOS dmg (`Dorado-<version>.dmg`, one
//     binary for both arches) plus bare `*-gui-<os>-x86_64[.exe]` for Linux and
//     Windows. No macOS arch split here, since the dmg is universal.
//   - CLIs: bare `<tool>-<os>-<arch>[.exe]`, with a real macOS arm64/x86_64
//     split (there is no universal CLI binary).
//
// A `release: published` trigger on deploy-site.yml re-runs the build so the
// resolved URLs stay fresh. On ANY failure (offline local build, rate limit, no
// release yet, missing asset) each URL falls back to the Releases page, which
// always exists, so the site build can never break on this.
//
// The repo is public, so the resolved asset URLs and the Releases-page fallback
// are reachable by any visitor.

const REPO = "alleato-llc/dorado";
const API = `https://api.github.com/repos/${REPO}/releases`;
const RELEASES_PAGE = `https://github.com/${REPO}/releases`;

/** A desktop app: one universal macOS dmg, plus x86_64 Linux/Windows binaries. */
export interface GuiUrls {
  macUniversal: string;
  linux: string;
  windows: string;
}

/** A CLI tool: macOS split by arch, plus x86_64 Linux/Windows binaries. */
export interface CliUrls {
  macArm64: string;
  macX64: string;
  linux: string;
  windows: string;
}

export interface DownloadUrls {
  desktopDorado: GuiUrls;
  desktopGyotaku: GuiUrls;
  cliDorado: CliUrls;
  cliGyotaku: CliUrls;
  /** Catch-all: the Releases page, used as the ultimate fallback. */
  releasesPage: string;
}

interface Asset {
  name: string;
  browser_download_url: string;
}
interface Release {
  tag_name: string;
  html_url: string;
  published_at: string;
  draft: boolean;
  assets: Asset[];
}

async function fetchReleases(): Promise<Release[]> {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "User-Agent": "dorado-site-build",
  };
  // A token (present in CI) lifts the unauthenticated 60/hr rate limit. The
  // repo is public, so it is no longer required; the build works without it,
  // just against the lower anonymous limit.
  const token = process.env.GITHUB_TOKEN;
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(API, { headers });
  if (!res.ok) throw new Error(`GitHub Releases API ${res.status}`);
  return (await res.json()) as Release[];
}

/** Newest non-draft release whose tag matches the track predicate. */
function newest(releases: Release[], match: (tag: string) => boolean): Release | undefined {
  return releases
    .filter((r) => !r.draft && match(r.tag_name))
    .sort((a, b) => Date.parse(b.published_at) - Date.parse(a.published_at))[0];
}

/** First asset URL matching the pattern, else the release's own page, else the list. */
function pick(rel: Release | undefined, pattern: RegExp): string {
  const hit = rel?.assets.find((a) => pattern.test(a.name));
  return hit?.browser_download_url ?? rel?.html_url ?? RELEASES_PAGE;
}

export async function resolveDownloads(): Promise<DownloadUrls> {
  try {
    const releases = await fetchReleases();
    const rust = newest(releases, (t) => /^rust-v\d/.test(t));
    return {
      desktopDorado: {
        macUniversal: pick(rust, /^Dorado-.*\.dmg$/i),
        linux: pick(rust, /^dorado-gui-linux-x86_64$/i),
        windows: pick(rust, /^dorado-gui-windows-x86_64\.exe$/i),
      },
      desktopGyotaku: {
        macUniversal: pick(rust, /^Gyotaku-.*\.dmg$/i),
        linux: pick(rust, /^gyotaku-gui-linux-x86_64$/i),
        windows: pick(rust, /^gyotaku-gui-windows-x86_64\.exe$/i),
      },
      cliDorado: {
        macArm64: pick(rust, /^dorado-macos-arm64$/i),
        macX64: pick(rust, /^dorado-macos-x86_64$/i),
        linux: pick(rust, /^dorado-linux-x86_64$/i),
        windows: pick(rust, /^dorado-windows-x86_64\.exe$/i),
      },
      cliGyotaku: {
        macArm64: pick(rust, /^gyotaku-macos-arm64$/i),
        macX64: pick(rust, /^gyotaku-macos-x86_64$/i),
        linux: pick(rust, /^gyotaku-linux-x86_64$/i),
        windows: pick(rust, /^gyotaku-windows-x86_64\.exe$/i),
      },
      releasesPage: RELEASES_PAGE,
    };
  } catch (err) {
    // Never fail the build on a download-link lookup: every URL degrades to the
    // Releases page, which always resolves (once the repo is readable).
    console.warn(`[releases] using Releases-page fallback: ${err}`);
    const gui: GuiUrls = { macUniversal: RELEASES_PAGE, linux: RELEASES_PAGE, windows: RELEASES_PAGE };
    const cli: CliUrls = {
      macArm64: RELEASES_PAGE,
      macX64: RELEASES_PAGE,
      linux: RELEASES_PAGE,
      windows: RELEASES_PAGE,
    };
    return {
      desktopDorado: gui,
      desktopGyotaku: gui,
      cliDorado: cli,
      cliGyotaku: cli,
      releasesPage: RELEASES_PAGE,
    };
  }
}
