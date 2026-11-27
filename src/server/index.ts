/** Zero-dependency HTTP service: static site, analysis API, job queue and remote MCP. */
import { createServer, type IncomingMessage, type ServerResponse, type Server } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { extname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { realpathSync } from "node:fs";
import { randomUUID as uuid } from "node:crypto";
import { VERSION } from "../version.js";
import { runBrowserTool, type BrowserTool } from "../browser/index.js";
import { handleMessage, type JsonRpcMessage } from "../mcp/server.js";
import { DEFAULT_RULES } from "../rules/defaults.js";

const MAX_BODY_BYTES = Number(process.env["REVERSO_MAX_BODY_BYTES"] ?? 8 * 1024 * 1024);
const API_KEY = process.env["REVERSO_API_KEY"] ?? "";
const RATE_LIMIT = Number(process.env["REVERSO_RATE_LIMIT"] ?? 120);
const RATE_WINDOW_MS = 60_000;
const JOB_TTL_MS = 10 * 60_000;
const MAX_JOBS = 200;
const SITE_DIR = resolve(fileURLToPath(new URL("../../site/", import.meta.url)));
const VALID_TOOLS = new Set<BrowserTool | "ooxml">([
  "analyze", "format", "entropy", "strings", "layout", "hardening", "archive", "js",
  "wasm", "dex", "pcap", "jwt", "find-bytes", "hex", "diff", "match", "fuzzy",
  "pdf", "pyinstaller", "lnk", "evm", "dotnet", "ooxml",
]);

interface Job {
  id: string;
  tool: BrowserTool;
  status: "done" | "error";
  result?: unknown;
  error?: string;
  createdAt: number;
  expiresAt: number;
}

const jobs = new Map<string, Job>();
const sessions = new Map<string, number>();
const rateBuckets = new Map<string, { count: number; resetAt: number }>();

const CONTENT_TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".webmanifest": "application/manifest+json",
};

function json(res: ServerResponse, status: number, value: unknown, extra: Record<string, string> = {}): void {
  const body = JSON.stringify(value, (_key, item) => (typeof item === "bigint" ? item.toString() : item));
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body),
    ...corsHeaders(),
    ...extra,
  });
  res.end(body);
}

function corsHeaders(): Record<string, string> {
  return {
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET, POST, OPTIONS",
    "access-control-allow-headers": "content-type, x-api-key, mcp-protocol-version, mcp-session-id",
    "access-control-expose-headers": "mcp-session-id, mcp-protocol-version, retry-after",
  };
}

/** Pure rate-limit helper, exported for deterministic tests. */
export function checkRateLimit(
  map: Map<string, { count: number; resetAt: number }>,
  key: string,
  now: number,
  max: number,
  windowMs: number,
): { allowed: boolean; retryAfter: number } {
  const bucket = map.get(key);
  if (!bucket || bucket.resetAt <= now) {
    map.set(key, { count: 1, resetAt: now + windowMs });
    return { allowed: true, retryAfter: 0 };
  }
  bucket.count += 1;
  if (bucket.count > max) {
    return { allowed: false, retryAfter: Math.max(1, Math.ceil((bucket.resetAt - now) / 1000)) };
  }
  return { allowed: true, retryAfter: 0 };
}

function pruneExpired(): void {
  const now = Date.now();
  for (const [id, job] of jobs) if (job.expiresAt <= now) jobs.delete(id);
  for (const [id, created] of sessions) if (created + 30 * 60_000 <= now) sessions.delete(id);
  for (const [key, bucket] of rateBuckets) if (bucket.resetAt <= now) rateBuckets.delete(key);
}

function accessAllowed(req: IncomingMessage, res: ServerResponse, pathname: string): boolean {
  if (!pathname.startsWith("/api") && pathname !== "/mcp") return true;
  if (API_KEY && req.headers["x-api-key"] !== API_KEY) {
    json(res, 401, { error: "Missing or invalid API key" });
    return false;
  }
  const ip = typeof req.headers["x-forwarded-for"] === "string"
    ? req.headers["x-forwarded-for"].split(",")[0]!.trim()
    : req.socket.remoteAddress ?? "unknown";
  const limit = checkRateLimit(rateBuckets, ip, Date.now(), RATE_LIMIT, RATE_WINDOW_MS);
  if (!limit.allowed) {
    json(res, 429, { error: "Rate limit exceeded" }, { "retry-after": String(limit.retryAfter) });
    return false;
  }
  return true;
}

async function readBody(req: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const piece = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array);
    total += piece.length;
    if (total > MAX_BODY_BYTES) {
      const error = new Error("Body too large");
      (error as Error & { status?: number }).status = 413;
      throw error;
    }
    chunks.push(piece);
  }
  return Buffer.concat(chunks);
}

function requestTool(url: URL, body: Buffer): unknown {
  const tool = url.searchParams.get("tool") as BrowserTool;
  if (!VALID_TOOLS.has(tool)) {
    throw new Error(`Unknown or missing tool. Choose one of: ${[...VALID_TOOLS].join(", ")}`);
  }
  return runBrowserTool({
    tool,
    bytes: new Uint8Array(body),
    label: url.searchParams.get("label") ?? "upload.bin",
    arg: url.searchParams.get("arg") ?? undefined,
  });
}

async function serveStatic(pathname: string, res: ServerResponse): Promise<void> {
  let relative: string;
  try {
    relative = decodeURIComponent(pathname === "/" ? "/index.html" : pathname).replace(/^\/+/, "");
  } catch {
    json(res, 400, { error: "Invalid path" });
    return;
  }
  const filePath = resolve(SITE_DIR, relative);
  const rel = relativePath(SITE_DIR, filePath);
  if (rel.startsWith("..") || rel.includes(`..${sep}`)) {
    json(res, 403, { error: "Forbidden" });
    return;
  }
  try {
    const fileStat = await stat(filePath);
    if (!fileStat.isFile()) throw new Error("Not a file");
    const body = await readFile(filePath);
    res.writeHead(200, {
      "content-type": CONTENT_TYPES[extname(filePath).toLowerCase()] ?? "application/octet-stream",
      "content-length": body.length,
      "cache-control": "public, max-age=300",
      ...corsHeaders(),
    });
    res.end(body);
  } catch {
    json(res, 404, { error: "Not found" });
  }
}

function relativePath(from: string, to: string): string {
  const a = from.split(/[\\/]/).filter(Boolean);
  const b = to.split(/[\\/]/).filter(Boolean);
  while (a.length > 0 && b.length > 0 && a[0] === b[0]) {
    a.shift();
    b.shift();
  }
  return [...a.map(() => ".."), ...b].join("/");
}

async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
  pruneExpired();

  if (req.method === "OPTIONS") {
    res.writeHead(204, corsHeaders());
    res.end();
    return;
  }

  if (req.method === "GET" && url.pathname === "/health") {
    json(res, 200, {
      status: "ok",
      version: VERSION,
      service: "reverso-online",
      schemaVersion: "2.0",
      jobs: jobs.size,
      auth: API_KEY ? "required" : "none",
    });
    return;
  }

  if (!accessAllowed(req, res, url.pathname)) return;

  if (req.method === "GET" && url.pathname === "/api/rules") {
    json(res, 200, { count: DEFAULT_RULES.length, rules: DEFAULT_RULES });
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/analyze") {
    try {
      const body = await readBody(req);
      json(res, 200, { schemaVersion: "2.0", tool: url.searchParams.get("tool"), bytes: body.length, result: requestTool(url, body) });
    } catch (error) {
      const status = (error as Error & { status?: number }).status ?? 400;
      json(res, status, { error: (error as Error).message });
    }
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/jobs") {
    try {
      if (jobs.size >= MAX_JOBS) {
        json(res, 503, { error: "Job queue full. Try again shortly." });
        return;
      }
      const body = await readBody(req);
      const tool = url.searchParams.get("tool") as BrowserTool;
      if (!VALID_TOOLS.has(tool)) {
        json(res, 400, { error: "Unknown or missing tool" });
        return;
      }
      const id = uuid();
      const now = Date.now();
      const job: Job = { id, tool, status: "done", result: requestTool(url, body), createdAt: now, expiresAt: now + JOB_TTL_MS };
      jobs.set(id, job);
      json(res, 202, { id, status: job.status, pollUrl: `/api/jobs/${id}`, expiresAt: job.expiresAt });
    } catch (error) {
      const status = (error as Error & { status?: number }).status ?? 400;
      json(res, status, { error: (error as Error).message });
    }
    return;
  }

  const jobMatch = url.pathname.match(/^\/api\/jobs\/([a-f0-9-]{36})$/);
  if (req.method === "GET" && jobMatch) {
    const job = jobs.get(jobMatch[1]!);
    if (!job) {
      json(res, 404, { error: "Job not found or expired" });
      return;
    }
    json(res, 200, {
      id: job.id,
      tool: job.tool,
      status: job.status,
      ...(job.result !== undefined ? { result: job.result } : {}),
      ...(job.error ? { error: job.error } : {}),
    });
    return;
  }

  if (req.method === "POST" && url.pathname === "/mcp") {
    try {
      const body = await readBody(req);
      const message = JSON.parse(body.toString("utf8")) as JsonRpcMessage;
      const suppliedSession = req.headers["mcp-session-id"];
      if (typeof suppliedSession === "string" && suppliedSession && !sessions.has(suppliedSession)) {
        json(res, 400, { error: "Unknown MCP session" });
        return;
      }
      const isInitialize = message.method === "initialize";
      const sessionId = isInitialize ? uuid() : typeof suppliedSession === "string" ? suppliedSession : "";
      if (isInitialize) sessions.set(sessionId, Date.now());
      const response = await handleMessage(message);
      const headers: Record<string, string> = {
        "mcp-protocol-version": "2025-06-18",
        ...(sessionId ? { "mcp-session-id": sessionId } : {}),
      };
      if (!response) {
        res.writeHead(202, { ...corsHeaders(), ...headers });
        res.end();
        return;
      }
      const acceptsSse = (req.headers["accept"] ?? "").includes("text/event-stream");
      if (acceptsSse) {
        res.writeHead(200, {
          "content-type": "text/event-stream; charset=utf-8",
          "cache-control": "no-cache",
          ...corsHeaders(),
          ...headers,
        });
        res.end(`event: message\ndata: ${JSON.stringify(response)}\n\n`);
        return;
      }
      json(res, 200, response, headers);
    } catch (error) {
      const status = (error as Error & { status?: number }).status ?? 400;
      json(res, status, { error: (error as Error).message });
    }
    return;
  }

  if (req.method === "GET") {
    await serveStatic(url.pathname, res);
    return;
  }

  json(res, 405, { error: "Method not allowed" });
}

export function createHttpServer(): Server {
  const server = createServer((req, res) => {
    void handleRequest(req, res).catch((error) => {
      json(res, 500, { error: (error as Error).message });
    });
  });
  server.requestTimeout = 60_000;
  return server;
}

/** Starts the HTTP service. Used by `npm start` and the container. */
export function startServer(): void {
  const port = Number(process.env["PORT"] ?? 3000);
  const host = process.env["HOST"] ?? "0.0.0.0";
  const server = createHttpServer();
  server.listen(port, host, () => {
    console.log(`Reverso online service v${VERSION} listening on http://${host}:${port}`);
  });
}

function safeReal(path: string): string {
  try {
    return realpathSync(path);
  } catch {
    return resolve(path);
  }
}

const invokedAsScript = process.argv[1] !== undefined
  && safeReal(fileURLToPath(import.meta.url)) === safeReal(process.argv[1]);
if (invokedAsScript) startServer();
