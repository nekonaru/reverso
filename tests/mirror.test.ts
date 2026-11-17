import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { createServer, type Server } from "node:http";
import { mkdtemp, rm, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { AddressInfo } from "node:net";
import { mirrorSite, localPathFor, relativeLocalPath, assertPublicIp } from "../src/web/mirror.js";

describe("localPathFor", () => {
  it("maps directory URLs to index.html", () => {
    const path = localPathFor("/out", new URL("https://example.com/docs/"));
    expect(path).toBe(resolve("/out", "docs", "index.html"));
  });

  it("keeps known extensions and appends .html for missing ones", () => {
    expect(localPathFor("/out", new URL("https://example.com/a/b.css"))).toBe(resolve("/out", "a", "b.css"));
    expect(localPathFor("/out", new URL("https://example.com/a/b"))).toBe(resolve("/out", "a", "b.html"));
  });

  it("neutralizes path traversal", () => {
    const path = localPathFor("/out", new URL("https://example.com/../../etc/passwd"));
    expect(path).not.toContain("..");
    expect(path).toBe(resolve("/out", "etc", "passwd.html"));
  });

  it("hashes query strings into the filename", () => {
    const a = relativeLocalPath(new URL("https://example.com/p?a=1"));
    const b = relativeLocalPath(new URL("https://example.com/p?a=2"));
    expect(a).not.toBe(b);
    expect(a.endsWith(".html")).toBe(true);
  });
});

describe("assertPublicIp", () => {
  it("blocks loopback, private, link-local and CGNAT addresses", () => {
    for (const ip of ["127.0.0.1", "10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fd00::1", "fe80::1"]) {
      expect(() => assertPublicIp(ip), ip).toThrow();
    }
  });

  it("allows public addresses", () => {
    expect(() => assertPublicIp("8.8.8.8")).not.toThrow();
    expect(() => assertPublicIp("1.1.1.1")).not.toThrow();
    expect(() => assertPublicIp("2606:4700:4700::1111")).not.toThrow();
  });

  it("unwraps IPv4-mapped IPv6 addresses", () => {
    expect(() => assertPublicIp("::ffff:127.0.0.1")).toThrow();
    expect(() => assertPublicIp("::ffff:8.8.8.8")).not.toThrow();
  });
});

describe("mirrorSite end to end", () => {
  let server: Server;
  let origin: string;
  let outDir: string;

  beforeEach(async () => {
    outDir = await mkdtemp(join(tmpdir(), "reverso-mirror-"));
    server = createServer((req, res) => {
      switch (req.url) {
        case "/":
          res.writeHead(200, { "content-type": "text/html" });
          res.end('<html><head><link rel="stylesheet" href="/style.css"></head><body><a href="/sub/page.html">sub</a><img src="img/logo.png"></body></html>');
          return;
        case "/style.css":
          res.writeHead(200, { "content-type": "text/css" });
          res.end("body { background: url('img/bg.png'); }");
          return;
        case "/sub/page.html":
          res.writeHead(200, { "content-type": "text/html" });
          res.end('<html><body><a href="/">home</a></body></html>');
          return;
        case "/img/logo.png":
          res.writeHead(200, { "content-type": "image/png" });
          res.end(Buffer.from([0x89, 0x50, 0x4e, 0x47]));
          return;
        case "/img/bg.png":
          res.writeHead(200, { "content-type": "image/png" });
          res.end(Buffer.from([0x89, 0x50, 0x4e, 0x47]));
          return;
        default:
          res.writeHead(404);
          res.end("not found");
      }
    });
    await new Promise<void>((resolvePromise) => server.listen(0, "127.0.0.1", resolvePromise));
    origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterEach(async () => {
    await new Promise<void>((resolvePromise) => server.close(() => resolvePromise()));
    await rm(outDir, { recursive: true, force: true });
  });

  it("mirrors a site and rewrites references to relative paths", async () => {
    const report = await mirrorSite(`${origin}/`, { outDir, allowPrivate: true, maxPages: 20 });
    const names = report.pages.map((page) => page.localPath.replace(/\\/g, "/")).sort();
    expect(names).toContain("index.html");
    expect(names).toContain("style.css");
    expect(names).toContain("sub/page.html");
    expect(names).toContain("img/logo.png");

    const indexHtml = await readFile(join(outDir, "index.html"), "utf8");
    expect(indexHtml).toContain('href="./style.css"');
    expect(indexHtml).toContain('href="./sub/page.html"');
    expect(indexHtml).toContain('src="./img/logo.png"');

    const css = await readFile(join(outDir, "style.css"), "utf8");
    expect(css).toContain("url('./img/bg.png')");

    const reportFile = await stat(join(outDir, "reverso-mirror-report.json"));
    expect(reportFile.size).toBeGreaterThan(0);
    expect(report.errors).toHaveLength(0);
  });

  it("blocks loopback targets when allowPrivate is false", async () => {
    await expect(mirrorSite(`${origin}/`, { outDir })).rejects.toThrow(/private/i);
  });
});
