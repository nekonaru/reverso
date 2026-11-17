import { describe, it, expect } from "vitest";
import { analyzeJavaScript } from "../src/js/jsanal.js";

describe("analyzeJavaScript", () => {
  it("extracts URLs, endpoints and frameworks", () => {
    const source = `
      const API = "https://api.example.com/v1";
      fetch("/api/users/42");
      fetch("/api/auth/login");
      // __webpack_require__ is used by the bundler
      const s = require("react-dom");
    `;
    const result = analyzeJavaScript(source);
    expect(result.urls).toContain("https://api.example.com/v1");
    expect(result.endpoints).toContain("/api/users/42");
    expect(result.frameworks).toEqual(expect.arrayContaining(["webpack", "react"]));
  });

  it("flags obfuscation indicators and scores them", () => {
    const source = `
      var _0x1a2b = ["aHR0cHM6Ly9leGFtcGxlLmNvbQ=="];
      eval(atob(_0x1a2b[0]));
      var plain = "normal code";
    `;
    const result = analyzeJavaScript(source);
    expect(result.obfuscation.score).toBeGreaterThan(20);
    expect(result.obfuscation.indicators.join(" ")).toContain("eval()");
    expect(result.suspiciousCalls).toContain("eval");
  });

  it("detects secrets with line numbers", () => {
    const source = `line one\nconst key = "AKIAIOSFODNN7EXAMPLE";\nline three\n`;
    const result = analyzeJavaScript(source);
    const aws = result.secrets.find((s) => s.type === "aws-access-key");
    expect(aws).toBeDefined();
    expect(aws!.line).toBe(2);
  });

  it("detects JWTs and private keys", () => {
    const source = "const t = eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQss5c;\nconst k = '-----BEGIN PRIVATE KEY-----';";
    const result = analyzeJavaScript(source);
    expect(result.secrets.map((s) => s.type)).toEqual(expect.arrayContaining(["jwt", "private-key"]));
  });

  it("detects source map references", () => {
    const result = analyzeJavaScript("console.log('x');\n//# sourceMappingURL=app.js.map\n");
    expect(result.sourceMapUrl).toBe("app.js.map");
  });

  it("recognizes minified bundles", () => {
    const longLine = "const a=1;const b=2;const c=3;".repeat(40);
    const result = analyzeJavaScript(longLine);
    expect(result.minified).toBe(true);
  });

  it("handles empty input", () => {
    const result = analyzeJavaScript("");
    expect(result.bytes).toBe(0);
    expect(result.lines).toBe(0);
    expect(result.frameworks).toEqual([]);
  });
});
