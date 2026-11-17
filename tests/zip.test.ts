import { describe, it, expect } from "vitest";
import { listArchive } from "../src/archive/zip.js";
import { makeZip } from "./helpers.js";

describe("listArchive", () => {
  it("lists entries of a plain zip", () => {
    const zip = makeZip([
      { name: "README.md", content: "# Hello\n" },
      { name: "src/main.js", content: "console.log('hi');\n" },
    ]);
    const listing = listArchive(zip);
    expect(listing).not.toBeNull();
    expect(listing!.kind).toBe("zip");
    expect(listing!.entries.map((e) => e.name)).toEqual(["README.md", "src/main.js"]);
    expect(listing!.totalUncompressedSize).toBeGreaterThan(0);
    expect(listing!.truncated).toBe(false);
  });

  it("detects APK layout", () => {
    const apk = makeZip([
      { name: "AndroidManifest.xml", content: "binary-xml-placeholder" },
      { name: "classes.dex", content: "dex-placeholder" },
      { name: "lib/arm64-v8a/libfoo.so", content: "elf-placeholder" },
    ]);
    const listing = listArchive(apk)!;
    expect(listing.kind).toBe("apk");
    expect(listing.suspiciousEntries).toContain("lib/arm64-v8a/libfoo.so");
  });

  it("detects JAR layout", () => {
    const jar = makeZip([
      { name: "META-INF/MANIFEST.MF", content: "Manifest-Version: 1.0\n" },
      { name: "com/example/Main.class", content: "class-bytes" },
    ]);
    expect(listArchive(jar)!.kind).toBe("jar");
  });

  it("flags suspicious executable entries", () => {
    const zip = makeZip([{ name: "docs/setup.exe", content: "mz" }]);
    expect(listArchive(zip)!.suspiciousEntries).toContain("docs/setup.exe");
  });

  it("returns null for non-zip data", () => {
    expect(listArchive(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]))).toBeNull();
  });
});
