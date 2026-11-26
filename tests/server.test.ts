import { describe, it, expect, beforeAll, afterAll } from "vitest";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { createHttpServer } from "../src/server/index.js";
import { makeElf64 } from "./helpers.js";

let server: Server;
let base: string;

beforeAll(async () => {
  server = createHttpServer();
  await new Promise<void>((resolvePromise) => server.listen(0, "127.0.0.1", resolvePromise));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  await new Promise<void>((resolvePromise) => server.close(() => resolvePromise()));
});

describe("online HTTP service", () => {
  it("reports health", async () => {
    const response = await fetch(`${base}/health`);
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.status).toBe("ok");
    expect(body.version).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it("analyzes uploaded bytes via /api/analyze", async () => {
    const response = await fetch(`${base}/api/analyze?tool=format&label=sample.elf`, {
      method: "POST",
      body: makeElf64(),
    });
    expect(response.status).toBe(200);
    expect(response.headers.get("access-control-allow-origin")).toBe("*");
    const body = await response.json();
    expect(body.result.format).toBe("elf64");
  });

  it("rejects unknown tools", async () => {
    const response = await fetch(`${base}/api/analyze?tool=nope`, { method: "POST", body: "x" });
    expect(response.status).toBe(400);
  });

  it("answers MCP initialize over JSON", async () => {
    const response = await fetch(`${base}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize" }),
    });
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.result.serverInfo.name).toBe("reverso");
    expect(response.headers.get("mcp-protocol-version")).toBe("2025-06-18");
  });

  it("answers MCP initialize over server-sent events", async () => {
    const response = await fetch(`${base}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "text/event-stream" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }),
    });
    expect(response.headers.get("content-type")).toContain("text/event-stream");
    const text = await response.text();
    expect(text).toContain("event: message");
    expect(text).toContain("reverso_analyze");
  });

  it("accepts inline base64 content in a remote MCP tool call", async () => {
    const content = Buffer.from(makeElf64()).toString("base64");
    const response = await fetch(`${base}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 3,
        method: "tools/call",
        params: { name: "reverso_format", arguments: { content } },
      }),
    });
    const body = await response.json();
    const payload = JSON.parse(body.result.content[0].text);
    expect(payload.format).toBe("elf64");
  });

  it("serves the static website", async () => {
    const response = await fetch(`${base}/`);
    expect(response.status).toBe(200);
    expect(await response.text()).toContain("Reverso: Native reverse engineering toolkit");
  });

  it("serves the built-in rule pack", async () => {
    const response = await fetch(`${base}/api/rules`);
    const body = await response.json();
    expect(body.count).toBeGreaterThanOrEqual(10);
    expect(body.rules[0].condition).toBeTruthy();
  });

  it("creates and retrieves a job", async () => {
    const created = await fetch(`${base}/api/jobs?tool=format&label=sample.elf`, {
      method: "POST",
      body: makeElf64(),
    });
    expect(created.status).toBe(202);
    const job = await created.json();
    expect(job.status).toBe("done");
    const fetched = await fetch(`${base}${job.pollUrl}`);
    expect(fetched.status).toBe(200);
    const body = await fetched.json();
    expect(body.result.format).toBe("elf64");
  });

  it("issues an MCP session id on initialize", async () => {
    const response = await fetch(`${base}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 9, method: "initialize" }),
    });
    const session = response.headers.get("mcp-session-id");
    expect(session).toMatch(/^[a-f0-9-]{36}$/);
    const followUp = await fetch(`${base}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json", "mcp-session-id": session! },
      body: JSON.stringify({ jsonrpc: "2.0", id: 10, method: "tools/list" }),
    });
    expect(followUp.status).toBe(200);
  });

  it("applies a deterministic rate limit helper", async () => {
    const { checkRateLimit } = await import("../src/server/index.js");
    const map = new Map<string, { count: number; resetAt: number }>();
    expect(checkRateLimit(map, "ip", 0, 2, 1000).allowed).toBe(true);
    expect(checkRateLimit(map, "ip", 10, 2, 1000).allowed).toBe(true);
    const blocked = checkRateLimit(map, "ip", 20, 2, 1000);
    expect(blocked.allowed).toBe(false);
    expect(blocked.retryAfter).toBeGreaterThan(0);
    expect(checkRateLimit(map, "ip", 1100, 2, 1000).allowed).toBe(true);
  });
});
