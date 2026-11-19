/** Minimal classic PCAP (Ethernet) builder for tests. */

function ipv4Packet(src: string, dst: string, protocol: number, payloadLength: number, transport: Buffer): Buffer {
  const ihl = 20;
  const totalLength = ihl + transport.length;
  const packet = Buffer.alloc(14 + totalLength);

  // Ethernet header
  Buffer.from([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]).copy(packet, 0); // dst MAC
  Buffer.from([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]).copy(packet, 6); // src MAC
  packet.writeUInt16BE(0x0800, 12);

  const ip = packet.subarray(14);
  ip.writeUInt8(0x45, 0); // version 4, IHL 5
  ip.writeUInt16BE(totalLength, 2);
  ip.writeUInt8(64, 8); // TTL
  ip.writeUInt8(protocol, 9);
  const parseIp = (s: string) => s.split(".").map((part) => Number(part));
  Buffer.from(parseIp(src)).copy(ip, 12);
  Buffer.from(parseIp(dst)).copy(ip, 16);
  transport.copy(ip, ihl);
  void payloadLength;

  return packet;
}

function tcpSegment(sport: number, dport: number): Buffer {
  const tcp = Buffer.alloc(20);
  tcp.writeUInt16BE(sport, 0);
  tcp.writeUInt16BE(dport, 2);
  tcp.writeUInt32BE(1000, 4); // seq
  tcp.writeUInt32BE(2000, 8); // ack
  tcp.writeUInt8(0x50, 12); // data offset 5
  tcp.writeUInt8(0x18, 13); // flags: PSH ACK
  tcp.writeUInt16BE(64240, 14); // window
  return tcp;
}

function udpDatagram(sport: number, dport: number): Buffer {
  const udp = Buffer.alloc(8);
  udp.writeUInt16BE(sport, 0);
  udp.writeUInt16BE(dport, 2);
  udp.writeUInt16BE(8, 4); // length
  return udp;
}

function icmpEcho(): Buffer {
  const icmp = Buffer.alloc(8);
  icmp.writeUInt8(8, 0); // echo request
  icmp.writeUInt8(0, 1);
  icmp.writeUInt16BE(0, 2);
  return icmp;
}

export function makePcap(): Uint8Array {
  const packets = [
    ipv4Packet("192.168.1.1", "93.184.216.34", 6, 0, tcpSegment(49200, 443)),
    ipv4Packet("192.168.1.1", "8.8.8.8", 17, 0, udpDatagram(53000, 53)),
    ipv4Packet("192.168.1.1", "192.168.1.254", 1, 0, icmpEcho()),
  ];
  const timestamps = [1700000000, 1700000001, 1700000002];

  const totalLength = 24 + packets.reduce((sum, packet) => sum + 16 + packet.length, 0);
  const buf = Buffer.alloc(totalLength);
  buf.writeUInt32LE(0xa1b2c3d4, 0); // magic: µs, LE
  buf.writeUInt16LE(2, 4); // version major
  buf.writeUInt16LE(4, 6); // version minor
  buf.writeInt32LE(0, 8); // thiszone
  buf.writeUInt32LE(0, 12); // sigfigs
  buf.writeUInt32LE(65535, 16); // snaplen
  buf.writeUInt32LE(1, 20); // network: Ethernet

  let offset = 24;
  for (let i = 0; i < packets.length; i++) {
    const packet = packets[i]!;
    buf.writeUInt32LE(timestamps[i]!, offset);
    buf.writeUInt32LE(i * 1000, offset + 4);
    buf.writeUInt32LE(packet.length, offset + 8);
    buf.writeUInt32LE(packet.length, offset + 12);
    packet.copy(buf, offset + 16);
    offset += 16 + packet.length;
  }

  return new Uint8Array(buf);
}
