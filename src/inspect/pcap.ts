/** Native PCAP (classic) inspector. pcapng is detected and refused with a clear message. */

export interface PcapTopEntry {
  value: string;
  packets: number;
}

export interface PcapInfo {
  version: string;
  magic: string;
  endianness: "LE" | "BE";
  timestampPrecision: "microseconds" | "nanoseconds";
  snaplen: number;
  linkType: number;
  linkTypeName: string;
  packets: number;
  truncated: boolean;
  bytes: number;
  durationSeconds: number | null;
  avgPacketBytes: number;
  protocols: Record<string, number>;
  ipv4Packets: number;
  ipv6Packets: number;
  topSources: PcapTopEntry[];
  topDestinations: PcapTopEntry[];
  topDstPorts: Array<{ port: number; protocol: string; packets: number }>;
  dnsNames: string[];
  httpRequests: string[];
}

const LINKTYPE_NAMES: Record<number, string> = {
  0: "null",
  1: "ethernet",
  6: "token-ring",
  9: "ppp",
  101: "raw-ip",
  105: "ieee80211",
  113: "linux-cooked",
  228: "ipv4",
  229: "ipv6",
};

const IP_PROTOCOL_NAMES: Record<number, string> = {
  1: "icmp",
  2: "igmp",
  6: "tcp",
  17: "udp",
  47: "gre",
  58: "icmpv6",
  132: "sctp",
};

const MAX_PACKETS = 500000;
const TOP_N = 10;

export function parsePcap(buf: Uint8Array): PcapInfo {
  if (buf.length < 24) throw new Error("Not a PCAP file: too small");

  const b0 = buf[0]!, b1 = buf[1]!, b2 = buf[2]!, b3 = buf[3]!;
  // File magic bytes (differ between byte orders): a1b2c3d4 BE µs, d4c3b2a1 LE µs, a1b23c4d BE ns, 4d3cb2a1 LE ns.
  const isBeMicro = b0 === 0xa1 && b1 === 0xb2 && b2 === 0xc3 && b3 === 0xd4;
  const isLeMicro = b0 === 0xd4 && b1 === 0xc3 && b2 === 0xb2 && b3 === 0xa1;
  const isBeNano = b0 === 0xa1 && b1 === 0xb2 && b2 === 0x3c && b3 === 0x4d;
  const isLeNano = b0 === 0x4d && b1 === 0x3c && b2 === 0xb2 && b3 === 0xa1;
  if (b0 === 0x0a && b1 === 0x0d && b2 === 0x0d && b3 === 0x0a) {
    throw new Error("Not a PCAP file: this is pcapng. Convert it with editcap -F pcap first.");
  }
  if (!isLeMicro && !isBeMicro && !isLeNano && !isBeNano) {
    throw new Error("Not a PCAP file: unrecognized magic");
  }

  const le = isLeMicro || isLeNano;
  const nanoseconds = isLeNano || isBeNano;
  const magic = [b0, b1, b2, b3].map((b) => b.toString(16).padStart(2, "0")).join("");
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const u16 = (o: number) => dv.getUint16(o, le);
  const u32 = (o: number) => dv.getUint32(o, le) >>> 0;

  const versionMajor = u16(4);
  const versionMinor = u16(6);
  const snaplen = u32(16);
  const linkType = u32(20);

  const info: PcapInfo = {
    version: `${versionMajor}.${versionMinor}`,
    magic,
    endianness: le ? "LE" : "BE",
    timestampPrecision: nanoseconds ? "nanoseconds" : "microseconds",
    snaplen,
    linkType,
    linkTypeName: LINKTYPE_NAMES[linkType] ?? `linktype-${linkType}`,
    packets: 0,
    truncated: false,
    bytes: 0,
    durationSeconds: null,
    avgPacketBytes: 0,
    protocols: {},
    ipv4Packets: 0,
    ipv6Packets: 0,
    topSources: [],
    topDestinations: [],
    topDstPorts: [],
    dnsNames: [],
    httpRequests: [],
  };

  const sourceCount = new Map<string, number>();
  const destCount = new Map<string, number>();
  const portCount = new Map<string, number>();
  const dnsNames: string[] = [];
  const httpRequests: string[] = [];
  let firstTs: number | null = null;
  let lastTs: number | null = null;
  let payloadBytes = 0;

  let pos = 24;
  while (pos + 16 <= buf.length && info.packets < MAX_PACKETS) {
    const tsSec = u32(pos);
    const tsFrac = u32(pos + 4);
    const inclLen = u32(pos + 8);
    const origLen = u32(pos + 12);
    pos += 16;
    if (inclLen > snaplen || inclLen > 16 * 1024 * 1024 || pos + inclLen > buf.length) {
      info.truncated = true;
      break;
    }
    const packet = buf.subarray(pos, pos + inclLen);
    pos += inclLen;

    const ts = tsSec + (nanoseconds ? tsFrac / 1e9 : tsFrac / 1e6);
    if (firstTs === null || ts < firstTs) firstTs = ts;
    if (lastTs === null || ts > lastTs) lastTs = ts;

    info.packets += 1;
    info.bytes += origLen;
    payloadBytes += inclLen;

    inspectPacket(packet, linkType, info, sourceCount, destCount, portCount, dnsNames, httpRequests);
  }

  if (pos < buf.length && !info.truncated) info.truncated = true;

  if (info.packets > 0) {
    info.avgPacketBytes = Math.round(payloadBytes / info.packets);
    if (firstTs !== null && lastTs !== null && lastTs >= firstTs) {
      info.durationSeconds = Math.round((lastTs - firstTs) * 1000) / 1000;
    }
  }

  info.topSources = topEntries(sourceCount);
  info.topDestinations = topEntries(destCount);
  info.topDstPorts = topEntries(portCount).map(({ value, packets }) => {
    const [protocol, port] = value.split("/", 2);
    return { port: Number(port), protocol: protocol!, packets };
  });
  info.dnsNames = dnsNames.slice(0, 50);
  info.httpRequests = httpRequests.slice(0, 50);

  return info;
}

function inspectPacket(
  packet: Uint8Array,
  linkType: number,
  info: PcapInfo,
  sourceCount: Map<string, number>,
  destCount: Map<string, number>,
  portCount: Map<string, number>,
  dnsNames: string[],
  httpRequests: string[],
): void {
  let offset = 0;
  let ethertype: number | null = null;

  if (linkType === 1) {
    if (packet.length < 14) return bump(info.protocols, "malformed");
    ethertype = ((packet[12]! << 8) | packet[13]!) >>> 0;
    offset = 14;
    if (ethertype === 0x8100 || ethertype === 0x88a8) { // VLAN tags
      if (packet.length < 18) return bump(info.protocols, "malformed");
      ethertype = ((packet[16]! << 8) | packet[17]!) >>> 0;
      offset = 18;
    }
  } else if (linkType === 113) { // Linux cooked: protocol at 14
    if (packet.length < 16) return bump(info.protocols, "malformed");
    ethertype = ((packet[14]! << 8) | packet[15]!) >>> 0;
    offset = 16;
  } else if (linkType === 101 || linkType === 228) { // raw IPv4
    ethertype = 0x0800;
  } else if (linkType === 229 || linkType === 101 + 128) { // raw IPv6 variants
    ethertype = 0x86dd;
  } else if (linkType === 0) {
    const family = new DataView(packet.buffer, packet.byteOffset, packet.byteLength).getUint32(0, true);
    ethertype = family === 2 ? 0x0800 : family === 10 ? 0x86dd : null; // AF_INET / AF_INET6
    offset = 4;
  } else {
    return bump(info.protocols, "unsupported-link");
  }

  if (ethertype === 0x0806) {
    bump(info.protocols, "arp");
    return;
  }

  if (ethertype === 0x0800) {
    parseIpv4(packet, offset, info, sourceCount, destCount, portCount, dnsNames, httpRequests);
    return;
  }

  if (ethertype === 0x86dd) {
    parseIpv6(packet, offset, info, sourceCount, destCount, portCount, dnsNames, httpRequests);
    return;
  }

  bump(info.protocols, `ethertype-0x${(ethertype ?? 0).toString(16)}`);
}

function parseIpv4(
  buf: Uint8Array,
  offset: number,
  info: PcapInfo,
  sourceCount: Map<string, number>,
  destCount: Map<string, number>,
  portCount: Map<string, number>,
  dnsNames: string[],
  httpRequests: string[],
): void {
  if (buf.length < offset + 20) return bump(info.protocols, "malformed-ipv4");
  const versionIhl = buf[offset]!;
  if ((versionIhl >> 4) !== 4) return bump(info.protocols, "malformed-ipv4");
  const ihl = (versionIhl & 0x0f) * 4;
  if (ihl < 20 || buf.length < offset + ihl) return bump(info.protocols, "malformed-ipv4");

  const protocol = buf[offset + 9]!;
  const src = formatIpv4(buf, offset + 12);
  const dst = formatIpv4(buf, offset + 16);

  info.ipv4Packets += 1;
  bump(sourceCount, src);
  bump(destCount, dst);
  bump(info.protocols, "ipv4");
  parseTransport(buf, offset + ihl, protocol, info, portCount, dnsNames, httpRequests);
}

function parseIpv6(
  buf: Uint8Array,
  offset: number,
  info: PcapInfo,
  sourceCount: Map<string, number>,
  destCount: Map<string, number>,
  portCount: Map<string, number>,
  dnsNames: string[],
  httpRequests: string[],
): void {
  if (buf.length < offset + 40) return bump(info.protocols, "malformed-ipv6");
  if ((buf[offset]! >> 4) !== 6) return bump(info.protocols, "malformed-ipv6");

  let nextHeader = buf[offset + 6]!;
  const src = formatIpv6(buf, offset + 8);
  const dst = formatIpv6(buf, offset + 24);
  let headerOffset = offset + 40;

  // Bounded walk over extension headers.
  for (let hop = 0; hop < 4; hop++) {
    if (nextHeader === 0 || nextHeader === 43 || nextHeader === 60 || nextHeader === 44) {
      if (buf.length < headerOffset + 2) return bump(info.protocols, "malformed-ipv6");
      const extLen = nextHeader === 44 ? 8 : (buf[headerOffset + 1]! + 1) * 8;
      if (buf.length < headerOffset + extLen) return bump(info.protocols, "malformed-ipv6");
      nextHeader = buf[headerOffset]!;
      headerOffset += extLen;
      continue;
    }
    break;
  }

  info.ipv6Packets += 1;
  bump(sourceCount, src);
  bump(destCount, dst);
  bump(info.protocols, "ipv6");
  parseTransport(buf, headerOffset, nextHeader, info, portCount, dnsNames, httpRequests);
}

function parseTransport(
  buf: Uint8Array,
  offset: number,
  protocol: number,
  info: PcapInfo,
  portCount: Map<string, number>,
  dnsNames: string[],
  httpRequests: string[],
): void {
  const protoName = IP_PROTOCOL_NAMES[protocol] ?? `ipproto-${protocol}`;
  bump(info.protocols, protoName);

  if (protocol === 6 || protocol === 17) {
    if (buf.length < offset + 4) return bump(info.protocols, "malformed-transport");
    const srcPort = (buf[offset]! << 8) | buf[offset + 1]!;
    const dstPort = (buf[offset + 2]! << 8) | buf[offset + 3]!;
    bump(portCount, `${protoName}/${dstPort}`);
    if (dstPort === 80 || srcPort === 80) bump(info.protocols, "http");
    if (dstPort === 443 || srcPort === 443) bump(info.protocols, "tls");
    const isDns = dstPort === 53 || srcPort === 53;
    if (isDns) bump(info.protocols, "dns");
    if (dstPort === 22 || srcPort === 22) bump(info.protocols, "ssh");

    const headerLength = protocol === 6 ? ((buf[offset + 12]! >> 4) & 0xf) * 4 : 8;
    const payload = buf.subarray(offset + headerLength);
    if (isDns && dnsNames.length < 50) {
      const name = parseDnsName(payload, protocol === 6);
      if (name) dnsNames.push(name);
    }
    if ((dstPort === 80 || srcPort === 80) && httpRequests.length < 50) {
      const text = new TextDecoder("latin1").decode(payload.subarray(0, Math.min(payload.length, 512)));
      const firstLine = text.split("\r\n", 1)[0]?.trim() ?? "";
      if (/^(GET|POST|PUT|HEAD|DELETE|OPTIONS|PATCH)\s+\S+/.test(firstLine)) httpRequests.push(firstLine);
    }
  }
}

function parseDnsName(payload: Uint8Array, tcp: boolean): string | null {
  const start = tcp ? 2 : 0;
  if (payload.length < start + 12) return null;
  const qdcount = (payload[start + 4]! << 8) | payload[start + 5]!;
  if (qdcount === 0) return null;
  let pos = start + 12;
  const labels: string[] = [];
  for (let hop = 0; hop < 40; hop++) {
    if (pos >= payload.length) return null;
    const length = payload[pos]!;
    pos += 1;
    if (length === 0) break;
    if (pos + length > payload.length || length > 63) return null;
    labels.push(new TextDecoder("latin1").decode(payload.subarray(pos, pos + length)));
    pos += length;
  }
  return labels.length > 0 ? labels.join(".") : null;
}

function formatIpv4(buf: Uint8Array, offset: number): string {
  return `${buf[offset]!}.${buf[offset + 1]!}.${buf[offset + 2]!}.${buf[offset + 3]!}`;
}

function formatIpv6(buf: Uint8Array, offset: number): string {
  const dv = new DataView(buf.buffer, buf.byteOffset + offset, 16);
  const groups: string[] = [];
  for (let i = 0; i < 8; i++) groups.push(dv.getUint16(i * 2).toString(16));
  return groups.join(":");
}

function bump(counter: Map<string, number> | Record<string, number>, key: string): void {
  if (counter instanceof Map) {
    counter.set(key, (counter.get(key) ?? 0) + 1);
    return;
  }
  counter[key] = (counter[key] ?? 0) + 1;
}

function topEntries(counter: Map<string, number>): PcapTopEntry[] {
  return [...counter.entries()]
    .map(([value, packets]) => ({ value, packets }))
    .sort((a, b) => b.packets - a.packets)
    .slice(0, TOP_N);
}
