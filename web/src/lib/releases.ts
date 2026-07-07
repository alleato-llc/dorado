// Build-time resolution of the Rust CLI release track's download URLs.
//
// Mirrors soroban's site/src/lib/releases.ts. Runs in Astro frontmatter, i.e. at
// BUILD time (Node). It makes a single HTTP request to the Releases API for the
// newest `rust-v*` tag (the only release track dorado has — see
// ../.github/workflows/release.yml) and reads the four `dorado` platform binary
// names off it (`dorado-<os>-<arch>[.exe]`, salpa's bare-binary naming
// convention — see ../../rust/salpa-dorado.yaml). `gyotaku` ships the same way
// but isn't wired into the download button; it's reachable from the Releases
// page link every button falls back to. A `release: published` trigger on
// deploy-site.yml re-runs the build so the resolved URLs stay fresh. On ANY
// failure (offline local build, rate limit, no release yet, missing asset) it
// falls back to a GitHub URL that always exists, so the site build can never
// break on this.
//
// The repo is currently private: even the fallback Releases-page link 404s for
// a visitor without repo access, same as every other github.com/alleato-llc/dorado
// link already on this page. That's expected while the repo stays private, not a
// bug in this resolver.

const REPO = "alleato-llc/dorado";
const API = `https://api.github.com/repos/${REPO}/releases`;
const RELEASES_PAGE = `https://github.com/${REPO}/releases`;

export interface DownloadUrls {
  linuxX64: string;
  macosArm64: string;
  macosX64: string;
  windowsX64: string;
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
  // A token (present in CI) lifts the unauthenticated 60/hr rate limit — and,
  // since this repo is private, is actually REQUIRED there: an unauthenticated
  // request to a private repo's API 404s regardless of rate limit.
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
      linuxX64: pick(rust, /^dorado-linux-x86_64$/i),
      macosArm64: pick(rust, /^dorado-macos-arm64$/i),
      macosX64: pick(rust, /^dorado-macos-x86_64$/i),
      windowsX64: pick(rust, /^dorado-windows-x86_64\.exe$/i),
      releasesPage: RELEASES_PAGE,
    };
  } catch (err) {
    // Never fail the build on a download-link lookup — every URL degrades to
    // the Releases page, which always resolves (once the repo is readable).
    console.warn(`[releases] using Releases-page fallback: ${err}`);
    return {
      linuxX64: RELEASES_PAGE,
      macosArm64: RELEASES_PAGE,
      macosX64: RELEASES_PAGE,
      windowsX64: RELEASES_PAGE,
      releasesPage: RELEASES_PAGE,
    };
  }
}
