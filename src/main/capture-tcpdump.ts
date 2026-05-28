import { execFileSync, spawn, type ChildProcessByStdio } from "node:child_process";
import type { Readable } from "node:stream";
import type { PacketCaptureHandle } from "./capture-adapter";

const PCAP_GLOBAL_HEADER_LENGTH = 24;
const PCAP_PACKET_HEADER_LENGTH = 16;

const LINK_TYPES = new Map<number, string>([
  [0, "NULL"],
  [1, "ETHERNET"],
  [101, "RAW"],
  [113, "LINKTYPE_LINUX_SLL"],
  [276, "LINKTYPE_LINUX_SLL"],
]);

export function openTcpdumpCapture(
  device: string,
  filter: string,
  buffer: Buffer,
  onPacket: (nbytes: number, truncated: boolean) => void,
): { cap: PacketCaptureHandle; linkType: string } {
  assertTcpdumpCanCapture();
  const linkType = getTcpdumpLinkType(device);
  const tcpdump = spawn("tcpdump", ["-i", device, "-U", "-s", "0", "-w", "-", filter], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  const reader = new PcapReader(buffer, onPacket);

  tcpdump.stdout.on("data", (chunk: Buffer) => reader.push(chunk));
  tcpdump.on("error", () => reader.close());
  tcpdump.on("exit", () => reader.close());

  return { cap: new TcpdumpHandle(tcpdump, reader), linkType };
}

class TcpdumpHandle implements PacketCaptureHandle {
  constructor(
    private readonly tcpdump: ChildProcessByStdio<null, Readable, Readable>,
    private readonly reader: PcapReader,
  ) {}

  close(): void {
    this.reader.close();
    if (!this.tcpdump.killed) this.tcpdump.kill("SIGTERM");
  }
}

class PcapReader {
  private pending = Buffer.alloc(0);
  private endian: "le" | "be" | null = null;
  private headerRead = false;
  private closed = false;

  constructor(
    private readonly targetBuffer: Buffer,
    private readonly onPacket: (nbytes: number, truncated: boolean) => void,
  ) {}

  push(chunk: Buffer): void {
    if (this.closed) return;
    this.pending = Buffer.concat([this.pending, chunk]);

    if (!this.headerRead) {
      if (this.pending.length < PCAP_GLOBAL_HEADER_LENGTH) return;
      this.readGlobalHeader();
    }

    while (this.pending.length >= PCAP_PACKET_HEADER_LENGTH) {
      const capturedLength = this.readUInt32(this.pending, 8);
      const packetOffset = PCAP_PACKET_HEADER_LENGTH;
      const nextOffset = packetOffset + capturedLength;
      if (this.pending.length < nextOffset) return;

      const packet = this.pending.subarray(packetOffset, nextOffset);
      const copiedLength = packet.copy(this.targetBuffer, 0, 0, Math.min(packet.length, this.targetBuffer.length));
      this.pending = this.pending.subarray(nextOffset);
      this.onPacket(copiedLength, copiedLength < packet.length);
    }
  }

  close(): void {
    this.closed = true;
  }

  private readGlobalHeader(): void {
    const magic = this.pending.readUInt32BE(0);
    if (magic === 0xa1b2c3d4 || magic === 0xa1b23c4d) this.endian = "be";
    if (magic === 0xd4c3b2a1 || magic === 0x4d3cb2a1) this.endian = "le";
    if (!this.endian) throw new Error("tcpdump produced an unsupported pcap stream.");

    this.pending = this.pending.subarray(PCAP_GLOBAL_HEADER_LENGTH);
    this.headerRead = true;
  }

  private readUInt32(buffer: Buffer, offset: number): number {
    return this.endian === "be" ? buffer.readUInt32BE(offset) : buffer.readUInt32LE(offset);
  }
}

function assertTcpdumpCanCapture(): void {
  try {
    const capability = execFileSync("getcap", ["/usr/bin/tcpdump"], { encoding: "utf8" });
    if (/cap_net_(?:admin|raw).*=/.test(capability)) return;
  } catch {
    // Fall through to the actionable error below.
  }

  throw new Error("tcpdump needs packet capture permission. Run: sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump");
}

function getTcpdumpLinkType(device: string): string {
  try {
    const output = execFileSync("tcpdump", ["-i", device, "-L"], { encoding: "utf8" });
    if (/EN10MB|Ethernet/i.test(output)) return "ETHERNET";
    if (/LINUX_SLL2|LINUX_SLL/i.test(output)) return "LINKTYPE_LINUX_SLL";
    if (/\bRAW\b/i.test(output)) return "RAW";
    if (/\bNULL\b/i.test(output)) return "NULL";
  } catch {
    // Most physical Linux interfaces use Ethernet framing.
  }
  return LINK_TYPES.get(1) ?? "ETHERNET";
}
