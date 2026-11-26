import { describe, it, expect } from "vitest";
import { DEFAULT_RULES } from "../src/rules/defaults.js";
import { matchRules, parseRule, parseRulePack } from "../src/rules/engine.js";

describe("rule engine", () => {
  it("ships with a valid built-in pack", () => {
    expect(DEFAULT_RULES.length).toBeGreaterThanOrEqual(10);
    expect(DEFAULT_RULES.every((rule) => rule.patterns.length > 0)).toBe(true);
  });

  it("matches UPX markers", () => {
    const data = new TextEncoder().encode("hello UPX! world");
    const matches = matchRules(DEFAULT_RULES, data);
    expect(matches.find((m) => m.id === "packer-upx")?.matched).toBe(true);
    expect(matches.find((m) => m.id === "runtime-go")?.matched).toBe(false);
  });

  it("supports labels, and/or/not and filesize comparisons safely", () => {
    const rule = parseRule({
      id: "custom",
      name: "Custom",
      description: "",
      severity: "high",
      patterns: [
        { kind: "hex", value: "4d 5a", label: "pe" },
        { kind: "text", value: "secret", label: "word" },
      ],
      condition: "pe and not word and filesize < 1KB",
    });
    const data = new TextEncoder().encode("MZ just a header");
    expect(matchRules([rule], data)[0]!.matched).toBe(true);
    const withWord = new TextEncoder().encode("MZ secret here");
    expect(matchRules([rule], withWord)[0]!.matched).toBe(false);
  });

  it("supports 2 of them and entropy thresholds", () => {
    const rule = parseRule({
      id: "two",
      name: "Two of three",
      description: "",
      severity: "low",
      patterns: [
        { kind: "text", value: "alpha" },
        { kind: "text", value: "beta" },
        { kind: "text", value: "gamma" },
      ],
      condition: "2 of them",
    });
    expect(matchRules([rule], new TextEncoder().encode("alpha beta"))[0]!.matched).toBe(true);
    expect(matchRules([rule], new TextEncoder().encode("alpha only"))[0]!.matched).toBe(false);
  });

  it("never evaluates arbitrary JavaScript in a condition", () => {
    const rule = parseRule({
      id: "safe",
      name: "Safe",
      description: "",
      severity: "info",
      patterns: [{ kind: "text", value: "x" }],
      condition: "process.exit(1)",
    });
    const match = matchRules([rule], new TextEncoder().encode("x"))[0]!;
    expect(match.matched).toBe(false);
    expect(match.error).toContain("Unexpected token");
  });

  it("validates rule packs and rejects invalid patterns", () => {
    expect(parseRulePack({ rules: DEFAULT_RULES })).toHaveLength(DEFAULT_RULES.length);
    expect(() => parseRulePack([{ id: "bad", name: "Bad", condition: "them", patterns: [{ kind: "hex", value: "zz" }] }])).toThrow();
  });
});
