import { describe, it, expect } from "vitest";
import { parsePcap } from "../src/inspect/pcap.js";
import { makePcap } from "./pcap-helper.js";

describe("parsePcap", () => {
  it("parses a classic little-endian microsecond PCAP", () => {
    const info = parsePcap(makePcap());
    expect(info.version).toBe("2.4");
    expect(info.endianness).toBe("LE");
    expect(info.timestampPrecision).toBe("microseconds");
    expect(info.linkType).toBe(1);
    expect(info.linkTypeName).toBe("ethernet");
    expect(info.packets).toBe(3);
    expect(info.truncated).toBe(false);
    expect(info.ipv4Packets).toBe(3);
    expect(info.durationSeconds).toBe(2.002);
  });

  it("counts protocols and destination ports", () => {
    const info = parsePcap(makePcap());
    expect(info.protocols["ipv4"]).toBe(3);
    expect(info.protocols["tcp"]).toBe(1);
    expect(info.protocols["udp"]).toBe(1);
    expect(info.protocols["icmp"]).toBe(1);
    expect(info.protocols["tls"]).toBe(1);
    expect(info.protocols["dns"]).toBe(1);
    const ports = info.topDstPorts.map((entry) => `${entry.protocol}/${entry.port}`);
    expect(ports).toContain("tcp/443");
    expect(ports).toContain("udp/53");
  });

  it("reports top talkers", () => {
    const info = parsePcap(makePcap());
    expect(info.topSources[0]).toEqual({ value: "192.168.1.1", packets: 3 });
    expect(info.topDestinations.map((entry) => entry.value)).toContain("8.8.8.8");
  });

  it("flags truncation when the last packet is cut short", () => {
    const full = makePcap();
    const cut = full.subarray(0, full.length - 10);
    const info = parsePcap(cut);
    expect(info.truncated).toBe(true);
    expect(info.packets).toBe(2);
  });

  it("refuses pcapng with guidance", () => {
    const pcapng = new Uint8Array(28);
    pcapng.set([0x0a, 0x0d, 0x0d, 0x0a, 0x4d, 0x3c, 0x2b, 0x1a], 0);
    expect(() => parsePcap(pcapng)).toThrow(/pcapng/);
  });

  it("rejects non-PCAP input", () => {
    expect(() => parsePcap(new Uint8Array([1, 2, 3]))).toThrow(/too small/);
    const buf = new Uint8Array(24);
    expect(() => parsePcap(buf)).toThrow(/unrecognized magic/);
  });
});
