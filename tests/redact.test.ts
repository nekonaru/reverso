import { describe, it, expect } from "vitest";
import { analyzeBuffer } from "../src/core/analyze-buffer.js";
import { redactReport } from "../src/inspect/redact.js";

describe("report redaction", () => {
  it("masks a JWT and an AWS key while keeping report structure", () => {
    const token = ["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", "testtest"].join(".");
    const aws = "AKIAIOSFODNN7EXAMPLE";
    const source = `const a = "${token}"; const b = "${aws}";\n`;
    const report = analyzeBuffer(new TextEncoder().encode(source), "app.js");
    const redacted = redactReport(report);
    const blob = JSON.stringify(redacted);
    expect(blob).not.toContain(token);
    expect(blob).not.toContain(aws);
    expect(blob).toContain("...");
    expect(redacted.schemaVersion).toBe(report.schemaVersion);
    expect(redacted.risk.score).toBe(report.risk.score);
  });
});
