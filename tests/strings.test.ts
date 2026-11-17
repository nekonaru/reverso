import { describe, it, expect } from "vitest";
import { extractStrings, summarizeCategories, categorize } from "../src/core/strings.js";

describe("extractStrings", () => {
  it("extracts ASCII strings with offsets", () => {
    const buf = Buffer.from("\x00\x01hello world\x00\x02", "binary");
    const strings = extractStrings(new Uint8Array(buf));
    expect(strings.map((s) => s.value)).toContain("hello world");
    const hello = strings.find((s) => s.value === "hello world")!;
    expect(hello.offset).toBe(2);
    expect(hello.encoding).toBe("ascii");
  });

  it("extracts UTF-16LE strings", () => {
    const wide = Buffer.from("wide-string-content", "utf16le");
    const buf = Buffer.concat([Buffer.from([0x00, 0x01]), wide, Buffer.from([0x00, 0x00])]);
    const strings = extractStrings(new Uint8Array(buf));
    expect(strings.some((s) => s.encoding === "utf16le" && s.value === "wide-string-content")).toBe(true);
  });

  it("respects minLength", () => {
    const buf = Buffer.from("abc\x00abcd\x00abcde", "binary");
    const strings = extractStrings(new Uint8Array(buf), { minLength: 5 });
    expect(strings.map((s) => s.value)).toEqual(["abcde"]);
  });

  it("caps the number of strings", () => {
    const buf = Buffer.from(Array.from({ length: 500 }, (_, i) => `string-number-${i}-padding`).join("\x00"), "ascii");
    const strings = extractStrings(new Uint8Array(buf), { maxStrings: 10 });
    expect(strings.length).toBeLessThanOrEqual(10);
  });
});

describe("categorize", () => {
  it("detects URLs", () => {
    expect(categorize("https://example.com/path?q=1")).toContain("url");
  });
  it("detects IPv4 with optional port", () => {
    expect(categorize("192.168.0.1:8080")).toContain("ipv4");
  });
  it("detects emails", () => {
    expect(categorize("user@example.com")).toContain("email");
  });
  it("detects JWTs", () => {
    const jwt = ["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", "testtest"].join(".");
    expect(categorize(jwt)).toContain("jwt");
  });
  it("detects AWS access keys", () => {
    expect(categorize("AKIAIOSFODNN7EXAMPLE")).toContain("aws-key");
  });
  it("detects GitHub tokens", () => {
    expect(categorize("ghp_" + "a".repeat(36))).toContain("github-token");
  });
  it("detects private key headers", () => {
    expect(categorize("-----BEGIN RSA PRIVATE KEY-----")).toContain("private-key");
  });
  it("detects assigned secrets", () => {
    expect(categorize('api_key = "supersecretvalue123"')).toContain("assigned-secret");
  });
  it("returns empty for ordinary words", () => {
    expect(categorize("hello world")).toEqual([]);
  });
});

describe("summarizeCategories", () => {
  it("aggregates counts and samples", () => {
    const buf = Buffer.from("https://a.example.com/x\x00https://b.example.com/y\x00plain text here", "ascii");
    const strings = extractStrings(new Uint8Array(buf));
    const summary = summarizeCategories(strings);
    const urls = summary.find((s) => s.category === "url");
    expect(urls).toBeDefined();
    expect(urls!.count).toBe(2);
    expect(urls!.samples).toContain("https://a.example.com/x");
  });
});
