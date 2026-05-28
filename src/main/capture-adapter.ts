import { createRequire } from "node:module";
import os from "node:os";
import { openTcpdumpCapture } from "./capture-tcpdump";

const capRequire = createRequire(__filename);
const CAPTURE_BUFFER_BYTES = 10 * 1024 * 1024;

interface CapDeviceAddress {
  addr?: unknown;
}

interface CapDeviceInfo {
  name?: unknown;
  addresses?: CapDeviceAddress[];
}

export interface PacketCaptureHandle {
  close(): void;
}

interface NativePacketCapture extends PacketCaptureHandle {
  open(device: string, filter: string, bufferSize: number, buffer: Buffer): string;
  on(event: "packet", handler: (nbytes: number, truncated: boolean) => void): void;
}

interface CapConstructor {
  new (): NativePacketCapture;
  findDevice(localAddress: string): string | undefined;
  deviceList(): CapDeviceInfo[];
}

function nativeCap(): CapConstructor {
  return (capRequire("cap") as { Cap: CapConstructor }).Cap;
}

export function findNpcapDevice(localAddress: string): string | undefined {
  if (process.platform === "linux") return findLinuxInterface(localAddress);
  return nativeCap().findDevice(localAddress);
}

export function listNpcapDevices(): string {
  if (process.platform === "linux") return listLinuxInterfaces();
  return nativeCap().deviceList().map(formatDeviceInfo).join("; ");
}

export function openPacketCapture(
  device: string,
  filter: string,
  buffer: Buffer,
  onPacket: (nbytes: number, truncated: boolean) => void,
): { cap: PacketCaptureHandle; linkType: string } {
  if (process.platform === "linux") return openTcpdumpCapture(device, filter, buffer, onPacket);

  const cap = new (nativeCap())();
  const linkType = cap.open(device, filter, CAPTURE_BUFFER_BYTES, buffer);
  cap.on("packet", onPacket);
  return { cap, linkType };
}

function formatDeviceInfo(deviceInfo: CapDeviceInfo): string {
  const name = String(deviceInfo.name ?? "unknown");
  const addresses = Array.isArray(deviceInfo.addresses)
    ? deviceInfo.addresses.map((address) => String(address.addr ?? "")).filter(Boolean).join(", ")
    : "";
  return `${name}${addresses ? ` (${addresses})` : ""}`;
}

function findLinuxInterface(localAddress: string): string | undefined {
  for (const [name, addresses] of Object.entries(os.networkInterfaces())) {
    if (addresses?.some((address) => address.address === localAddress)) return name;
  }
  return undefined;
}

function listLinuxInterfaces(): string {
  return Object.entries(os.networkInterfaces())
    .map(([name, addresses]) => {
      const ips = addresses?.map((address) => address.address).filter(Boolean).join(", ") ?? "";
      return `${name}${ips ? ` (${ips})` : ""}`;
    })
    .join("; ");
}
