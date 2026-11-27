import { describe, it, expect } from "vitest";
import { parsePdf } from "../src/inspect/pdf.js";

describe("parsePdf", () => {
  it("reports static structure and embedded content markers", () => {
    const pdf = `%PDF-1.7\n1 0 obj\n<< /Type /Catalog /OpenAction 2 0 R /JavaScript <<>> >>\nendobj\n2 0 obj\n<< /URI (https://example.com/payload) /EmbeddedFile /Encrypt >>\nendobj\ntrailer\n<< /Title (Report) /Author (Lab) >>\n`;
    const info = parsePdf(new TextEncoder().encode(pdf));
    expect(info.version).toBe("1.7");
    expect(info.objects).toBeGreaterThanOrEqual(2);
    expect(info.javascript).toBe(true);
    expect(info.openAction).toBe(true);
    expect(info.encrypted).toBe(true);
    expect(info.embeddedFiles).toBe(1);
    expect(info.uris).toContain("https://example.com/payload");
    expect(info.metadata).toContain("Title: Report");
  });

  it("handles a non-PDF buffer without throwing", () => {
    const info = parsePdf(new TextEncoder().encode("plain text only"));
    expect(info.version).toBeNull();
    expect(info.javascript).toBe(false);
  });
});
