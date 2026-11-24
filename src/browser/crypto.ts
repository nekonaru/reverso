/** Browser-only replacement for the small part of node:crypto that Reverso uses. */
import { md5, sha1 } from "@noble/hashes/legacy.js";
import { sha256 } from "@noble/hashes/sha2.js";

type Algorithm = "md5" | "sha1" | "sha256";

/** Minimal createHash-compatible shim: update(...).digest("hex"). */
export function createHash(algorithm: Algorithm) {
  const chunks: Uint8Array[] = [];
  return {
    update(data: Uint8Array, offset?: number, length?: number) {
      if (offset === undefined) chunks.push(data.slice());
      else chunks.push(data.slice(offset, offset + (length ?? data.length - offset)));
      return this;
    },
    digest(encoding: string): string {
      if (encoding !== "hex") throw new Error("Only hex digest is supported");
      let total = 0;
      for (const chunk of chunks) total += chunk.length;
      const merged = new Uint8Array(total);
      let pos = 0;
      for (const chunk of chunks) {
        merged.set(chunk, pos);
        pos += chunk.length;
      }
      const hashed = algorithm === "md5" ? md5(merged) : algorithm === "sha1" ? sha1(merged) : sha256(merged);
      return [...hashed].map((b) => b.toString(16).padStart(2, "0")).join("");
    },
  };
}
