import { lookup } from "node:dns/promises";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, extname, join, relative, resolve, sep } from "node:path";
import { createHash } from "node:crypto";
import net from "node:net";

export interface MirrorOptions {
  outDir: string;
  maxPages?: number;
  maxDepth?: number;
  maxFileBytes?: number;
  maxTotalBytes?: number;
  timeoutMs?: number;
  concurrency?: number;
  allowPrivate?: boolean;
}

export interface MirroredPage {
  url: string;
  localPath: string;
  status: number;
  bytes: number;
  contentType: string;
}

export interface MirrorReport {
  startUrl: string;
  outDir: string;
  pages: MirroredPage[];
  skipped: Array<{ url: string; reason: string }>;
  errors: Array<{ url: string; error: string }>;
  totalBytes: number;
}

const DEFAULTS = {
  maxPages: 100,
  maxDepth: 5,
  maxFileBytes: 25 * 1024 * 1024,
  maxTotalBytes: 100 * 1024 * 1024,
  timeoutMs: 15000,
  concurrency: 4,
};

export type ResolvedMirrorOptions = typeof DEFAULTS & MirrorOptions;

/** Mirrors a website below its origin, rewriting references to relative local paths. */
export async function mirrorSite(startUrl: string, options: MirrorOptions): Promise<MirrorReport> {
  const opts: ResolvedMirrorOptions = { ...DEFAULTS, ...options };
  const start = new URL(startUrl);
  if (start.protocol !== "http:" && start.protocol !== "https:") {
    throw new Error(`Unsupported protocol: ${start.protocol}`);
  }
  const origin = start.origin;
  const outDir = resolve(opts.outDir);
  await mkdir(outDir, { recursive: true });

  if (!opts.allowPrivate) {
    await assertPublicHost(start.hostname);
  }

  const report: MirrorReport = {
    startUrl: start.toString(),
    outDir,
    pages: [],
    skipped: [],
    errors: [],
    totalBytes: 0,
  };

  const queue: Array<{ url: URL; depth: number }> = [{ url: start, depth: 0 }];
  const visited = new Set<string>();

  const worker = async (): Promise<void> => {
    while (report.pages.length < opts.maxPages && report.totalBytes < opts.maxTotalBytes) {
      const item = queue.shift();
      if (!item) return;
      const { url, depth } = item;
      const key = normalizeCacheKey(url);
      if (visited.has(key)) continue;
      visited.add(key);

      try {
        const response = await fetchWithGuards(url, opts, origin);
        if (!response) {
          report.skipped.push({ url: url.toString(), reason: "blocked, cross-origin or unreachable" });
          continue;
        }
        const contentType = (response.headers.get("content-type") ?? "").split(";")[0]!.trim().toLowerCase();
        const bytes = await readResponseBodyCapped(response, opts.maxFileBytes);
        if (bytes === null) {
          report.skipped.push({ url: url.toString(), reason: "exceeds per-file cap or unreadable body" });
          continue;
        }
        report.totalBytes += bytes.byteLength;

        const localPath = localPathFor(outDir, url);
        await mkdir(dirname(localPath), { recursive: true });

        if (isHtml(contentType, url)) {
          const html = new TextDecoder("utf-8").decode(bytes);
          await writeFile(localPath, rewriteHtml(html, url, origin));
          for (const link of extractUrls(html, url, origin)) {
            if (depth + 1 <= opts.maxDepth && queue.length < opts.maxPages * 4) {
              queue.push({ url: link, depth: depth + 1 });
            }
          }
        } else if (isCss(contentType, url)) {
          const css = new TextDecoder("utf-8").decode(bytes);
          await writeFile(localPath, rewriteCss(css, url, origin));
          for (const link of extractCssUrls(css, url, origin)) {
            if (depth + 1 <= opts.maxDepth) queue.push({ url: link, depth: depth + 1 });
          }
        } else {
          await writeFile(localPath, bytes);
        }

        report.pages.push({
          url: url.toString(),
          localPath: relative(outDir, localPath),
          status: response.status,
          bytes: bytes.byteLength,
          contentType,
        });
      } catch (error) {
        report.errors.push({ url: url.toString(), error: (error as Error).message });
      }
    }
  };

  const workers = Array.from({ length: opts.concurrency }, () => worker());
  await Promise.all(workers);

  await writeFile(join(outDir, "reverso-mirror-report.json"), JSON.stringify(report, null, 2));
  return report;
}

function normalizeCacheKey(url: URL): string {
  const copy = new URL(url.toString());
  copy.hash = "";
  return copy.toString();
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

async function fetchWithGuards(url: URL, opts: ResolvedMirrorOptions, origin: string): Promise<Response | null> {
  let current = url;
  for (let hop = 0; hop <= 5; hop++) {
    if (!opts.allowPrivate) {
      try {
        await assertPublicHost(current.hostname);
      } catch {
        return null;
      }
    }
    const response = await fetch(current, {
      redirect: "manual",
      signal: AbortSignal.timeout(opts.timeoutMs),
      headers: { "user-agent": "reverso/1.0.0 (+https://github.com/nekonaru/reverso)" },
    });
    if (!REDIRECT_STATUSES.has(response.status)) {
      if (!response.ok) return null;
      return response;
    }
    const location = response.headers.get("location");
    if (!location) return null;
    const next = new URL(location, current);
    if (next.protocol !== "http:" && next.protocol !== "https:") return null;
    if (next.origin !== origin) return null; // stay within the mirrored origin
    current = next;
  }
  return null;
}

/** Reads a response body without ever buffering more than `maxBytes`. */
async function readResponseBodyCapped(response: Response, maxBytes: number): Promise<Uint8Array | null> {
  const contentLength = Number(response.headers.get("content-length") ?? "0");
  if (Number.isFinite(contentLength) && contentLength > maxBytes) {
    await response.body?.cancel().catch(() => undefined);
    return null;
  }
  if (!response.body) return new Uint8Array(0);
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => undefined);
        return null;
      }
      chunks.push(value);
    }
  } catch {
    return null;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}

/** Blocks loopback, private, link-local and reserved addresses unless explicitly allowed. */
export async function assertPublicHost(hostname: string): Promise<void> {
  if (net.isIP(hostname)) {
    assertPublicIp(hostname);
    return;
  }
  const addresses = await lookup(hostname, { all: true });
  if (addresses.length === 0) throw new Error(`DNS lookup returned no addresses for ${hostname}`);
  for (const address of addresses) assertPublicIp(address.address);
}

export function assertPublicIp(ip: string): void {
  if (net.isIPv4(ip)) {
    const parts = ip.split(".").map(Number) as [number, number, number, number];
    const [a, b, c] = parts;
    const blocked =
      a === 0 || a === 10 || a === 127 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 192 && b === 0) ||
      (a === 198 && (b === 18 || b === 19 || b === 51)) ||
      (a === 203 && b === 0 && c === 113) ||
      a >= 224;
    if (blocked) throw new Error(`Refusing to fetch private or reserved address: ${ip}`);
    return;
  }
  if (net.isIPv6(ip)) {
    const normalized = ip.toLowerCase();
    const mapped = normalized.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return assertPublicIp(mapped[1]!);
    if (normalized === "::" || normalized === "::1" ||
        normalized.startsWith("fc") || normalized.startsWith("fd") ||
        normalized.startsWith("fe80") || normalized.startsWith("2001:db8")) {
      throw new Error(`Refusing to fetch private or reserved address: ${ip}`);
    }
  }
}

/** Maps a URL to a relative local path (POSIX separators), safe against traversal. */
export function relativeLocalPath(url: URL): string {
  let pathname: string;
  try {
    pathname = decodeURIComponent(url.pathname);
  } catch {
    pathname = url.pathname;
  }
  if (pathname.endsWith("/")) pathname += "index.html";
  else if (!extname(pathname)) pathname += ".html";
  const segments = pathname.split("/").filter((s) => s.length > 0 && s !== "." && s !== "..");
  let rel = segments.join("/");
  if (url.search) {
    const hash = createHash("sha256").update(url.search).digest("hex").slice(0, 8);
    const ext = extname(rel);
    rel = ext ? `${rel.slice(0, rel.length - ext.length)}__${hash}${ext}` : `${rel}__${hash}`;
  }
  return rel || "index.html";
}

/** Maps a URL to a safe absolute local file path below `outDir`. */
export function localPathFor(outDir: string, url: URL): string {
  const resolved = resolve(outDir, relativeLocalPath(url));
  const relToOut = relative(outDir, resolved);
  if (relToOut.startsWith("..") || relToOut.includes(`..${sep}`)) {
    throw new Error(`Refusing to write outside output directory: ${url}`);
  }
  return resolved;
}

function isHtml(contentType: string, url: URL): boolean {
  return contentType.includes("text/html") || contentType === "application/xhtml+xml" ||
    (contentType === "" && !extname(url.pathname));
}

function isCss(contentType: string, url: URL): boolean {
  return contentType.includes("text/css") || extname(url.pathname).toLowerCase() === ".css";
}

function extractUrls(html: string, base: URL, origin: string): URL[] {
  const urls = new Set<URL>();
  const attrPattern = /(?:href|src|action|poster)\s*=\s*["']([^"'#][^"']*)["']/gi;
  const srcsetPattern = /srcset\s*=\s*["']([^"']+)["']/gi;
  const cssUrlPattern = /url\(\s*['"]?([^)'"]+)['"]?\s*\)/gi;

  const addUrl = (raw: string): void => {
    const resolved = resolveUrl(raw, base);
    if (resolved && resolved.origin === origin) {
      resolved.hash = "";
      urls.add(resolved);
    }
  };

  for (const match of html.matchAll(attrPattern)) addUrl(match[1]!);
  for (const match of html.matchAll(srcsetPattern)) {
    for (const part of match[1]!.split(",")) {
      const candidate = part.trim().split(/\s+/)[0];
      if (candidate) addUrl(candidate);
    }
  }
  for (const match of html.matchAll(cssUrlPattern)) addUrl(match[1]!);

  return [...urls];
}

function extractCssUrls(css: string, base: URL, origin: string): URL[] {
  const urls = new Set<URL>();
  for (const match of css.matchAll(/url\(\s*['"]?([^)'"]+)['"]?\s*\)/gi)) {
    const resolved = resolveUrl(match[1]!.trim(), base);
    if (resolved && resolved.origin === origin) {
      resolved.hash = "";
      urls.add(resolved);
    }
  }
  return [...urls];
}

function resolveUrl(raw: string, base: URL): URL | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;
  try {
    const resolved = new URL(trimmed, base);
    if (resolved.protocol !== "http:" && resolved.protocol !== "https:") return null;
    return resolved;
  } catch {
    return null;
  }
}

function rewriteHtml(html: string, base: URL, origin: string): string {
  return html
    .replace(/((?:href|src|action|poster)\s*=\s*["'])([^"'#][^"']*)(["'])/gi, (_whole, prefix: string, raw: string, suffix: string) =>
      prefix + rewriteReference(raw, base, origin) + suffix)
    .replace(/(srcset\s*=\s*["'])([^"']+)(["'])/gi, (_whole, prefix: string, raw: string, suffix: string) => {
      const rewritten = raw.split(",").map((part) => {
        const tokens = part.trim().split(/\s+/);
        if (tokens[0]) tokens[0] = rewriteReference(tokens[0], base, origin);
        return tokens.join(" ");
      }).join(", ");
      return prefix + rewritten + suffix;
    });
}

function rewriteCss(css: string, base: URL, origin: string): string {
  return css.replace(/url\(\s*(['"]?)([^)'"]+)\1\s*\)/gi, (_whole, quote: string, raw: string) =>
    `url(${quote}${rewriteReference(raw.trim(), base, origin)}${quote})`);
}

function rewriteReference(raw: string, base: URL, origin: string): string {
  const trimmed = raw.trim();
  const resolved = resolveUrl(trimmed, base);
  if (!resolved || resolved.origin !== origin) return raw;
  const fromLocal = `/${relativeLocalPath(base)}`;
  const toLocal = `/${relativeLocalPath(resolved)}`;
  let rel = posixRelative(posixDir(fromLocal), toLocal);
  if (!rel.startsWith(".")) rel = `./${rel}`;
  return rel;
}

function posixRelative(fromDir: string, toPath: string): string {
  const from = fromDir.split("/").filter(Boolean);
  const to = toPath.split("/").filter(Boolean);
  while (from.length > 0 && to.length > 0 && from[0] === to[0]) {
    from.shift();
    to.shift();
  }
  return [...from.map(() => ".."), ...to].join("/");
}

function posixDir(path: string): string {
  const normalized = path.replace(/\\/g, "/");
  const index = normalized.lastIndexOf("/");
  return index <= 0 ? "/" : normalized.slice(0, index);
}
