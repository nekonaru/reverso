import { describe, it, expect } from "vitest";
import { parseOoxml } from "../src/node/ooxml.js";
import { makeZip } from "./helpers.js";

describe("parseOoxml", () => {
  it("detects kind, external relationships and document text", () => {
    const zip = makeZip([
      { name: "[Content_Types].xml", content: "<Types/>" },
      {
        name: "word/_rels/document.xml.rels",
        content: '<Relationships><Relationship Target="https://evil.example.com/x" TargetMode="External"/></Relationships>',
      },
      { name: "word/document.xml", content: "<document><body><p>Hello contract</p></body></document>" },
    ]);
    const info = parseOoxml(zip);
    expect(info.kind).toBe("docx");
    expect(info.externalTargets).toContain("https://evil.example.com/x");
    expect(info.strings.some((s) => s.includes("Hello contract"))).toBe(true);
    expect(info.hasVba).toBe(false);
  });

  it("flags VBA projects", () => {
    const zip = makeZip([
      { name: "word/document.xml", content: "<document/>" },
      { name: "word/vbaProject.bin", content: "binary" },
    ]);
    expect(parseOoxml(zip).hasVba).toBe(true);
  });
});
