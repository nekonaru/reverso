import { describe, it, expect } from "vitest";
import { decodeJwt } from "../src/inspect/jwt.ts";

const b64u = (value: object): string => Buffer.from(JSON.stringify(value), "utf8").toString("base64url");

function makeToken(payload: Record<string, unknown>, header: Record<string, unknown> = { alg: "HS256", typ: "JWT" }, signature = "testsignature"): string {
  return `${b64u(header)}.${b64u(payload)}.${signature}`;
}

describe("decodeJwt", () => {
  it("decodes header and payload with an HS256 token", () => {
    const now = Math.floor(Date.now() / 1000);
    const token = makeToken({ iss: "reverso", sub: "user-1", iat: now - 60, exp: now + 3600 });
    const info = decodeJwt(token);
    expect(info.algorithm).toBe("HS256");
    expect(info.signaturePresent).toBe(true);
    expect(info.signatureVerified).toBe(false);
    expect(info.expired).toBe(false);
    expect(info.secondsUntilExpiry).toBeGreaterThan(3000);
    expect(info.issuedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(info.warnings.join(" ")).toContain("expires in");
  });

  it("flags an expired token", () => {
    const now = Math.floor(Date.now() / 1000);
    const token = makeToken({ iss: "reverso", exp: now - 120 });
    const info = decodeJwt(token);
    expect(info.expired).toBe(true);
    expect(info.secondsUntilExpiry).toBeLessThan(0);
    expect(info.warnings.join(" ")).toContain("expired");
  });

  it("flags alg=none and sensitive claims", () => {
    const now = Math.floor(Date.now() / 1000);
    const token = makeToken({ exp: now + 60, api_key: "super-secret" }, { alg: "none", typ: "JWT" }, "");
    const info = decodeJwt(token);
    expect(info.algorithm).toBe("none");
    expect(info.signaturePresent).toBe(false);
    expect(info.warnings.join(" ")).toContain("'none'");
    expect(info.warnings.join(" ")).toContain("api_key");
  });

  it("notes a token without exp", () => {
    const token = makeToken({ iss: "reverso" });
    const info = decodeJwt(token);
    expect(info.expired).toBeNull();
    expect(info.warnings.join(" ")).toContain("no exp");
  });

  it("accepts a token without a signature segment", () => {
    const token = `${b64u({ alg: "none" })}.${b64u({ sub: "x" })}`;
    const info = decodeJwt(token);
    expect(info.signaturePresent).toBe(false);
    expect(info.warnings.join(" ")).toContain("no signature");
  });

  it("rejects malformed input", () => {
    expect(() => decodeJwt("not-a-jwt")).toThrow(/dot-separated/);
    expect(() => decodeJwt("a.b.c.d")).toThrow(/dot-separated/);
    expect(() => decodeJwt("!!!.!!!.!!!")).toThrow(/base64url|Not a JWT/);
    expect(() => decodeJwt(`${b64u({ a: 1 })}.not-json.sig`)).toThrow(/not valid JSON/);
  });
});
