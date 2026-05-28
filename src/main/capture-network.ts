import { execFile } from "node:child_process";
import fs from "node:fs";
import type { CaptureConnection } from "../shared/app-state";

// Hero Siege gameplay traffic does not currently use HTTP/HTTPS ports.
// Exclude these transient launcher/CDN connections so they are not captured or logged.
const WEB_REMOTE_PORTS = new Set([80, 443]);

export interface HeroSiegeNetworkState {
  gameProcessIds: number[];
  antiCheatProcessIds: number[];
  connections: CaptureConnection[];
}

interface PowerShellConnectionEntry {
  OwningProcess: unknown;
  State: unknown;
  LocalAddress: unknown;
  LocalPort: unknown;
  RemoteAddress: unknown;
  RemotePort: unknown;
}

export interface CaptureTarget {
  remoteAddress: string;
  remotePort: number;
}

export async function getHeroSiegeNetworkState(): Promise<HeroSiegeNetworkState> {
  if (process.platform === "linux") return getLinuxHeroSiegeNetworkState();

  const script = `
    $processes = Get-Process |
      Where-Object {
        $normalizedName = ($_.ProcessName -replace '[^a-zA-Z0-9]', '').ToLowerInvariant();
        $normalizedName.StartsWith('herosiege') -and
        -not $normalizedName.Contains('companion')
      };

    $antiCheatProcesses = Get-Process |
      Where-Object {
        (($_.ProcessName -replace '[^a-zA-Z0-9]', '').ToLowerInvariant()).StartsWith('easyanticheat')
      };

    $processIds = @($processes | Select-Object -ExpandProperty Id);
    $connections = @();

    if ($processIds.Count -gt 0) {
      $connections = @(
        Get-NetTCPConnection -ErrorAction SilentlyContinue |
          Where-Object {
            $processIds -contains $_.OwningProcess -and
            $_.RemoteAddress -and
            $_.RemoteAddress -notin @('0.0.0.0', '::', '127.0.0.1', '::1') -and
            $_.RemoteAddress -notlike '*:*'
          } |
          Select-Object OwningProcess, State, LocalAddress, LocalPort, RemoteAddress, RemotePort
      );
    }

    [PSCustomObject]@{
      gameProcessIds = @($processIds);
      antiCheatProcessIds = @($antiCheatProcesses | Select-Object -ExpandProperty Id);
      connections = @($connections);
    } | ConvertTo-Json -Compress
  `;

  const output = await runPowerShell(script);
  if (!output) return { gameProcessIds: [], antiCheatProcessIds: [], connections: [] };

  try {
    const parsed = JSON.parse(output) as Record<string, unknown>;
    const rawConnections = parsed.connections;
    const entries: PowerShellConnectionEntry[] = Array.isArray(rawConnections)
      ? rawConnections
      : rawConnections
        ? [rawConnections as PowerShellConnectionEntry]
        : [];
    return {
      gameProcessIds: normalizeNumberArray(parsed.gameProcessIds),
      antiCheatProcessIds: normalizeNumberArray(parsed.antiCheatProcessIds),
      connections: entries.map((entry) => ({
        owningProcess: Number(entry.OwningProcess),
        state: String(entry.State),
        localAddress: String(entry.LocalAddress),
        localPort: Number(entry.LocalPort),
        remoteAddress: String(entry.RemoteAddress),
        remotePort: Number(entry.RemotePort),
      })),
    };
  } catch {
    return { gameProcessIds: [], antiCheatProcessIds: [], connections: [] };
  }
}

export async function getNpcapServiceStatus(): Promise<string> {
  if (process.platform === "linux") return "Not required on Linux";

  const output = await runPowerShell("Get-Service npcap -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status");
  return output || "Unknown";
}

export async function getNpcapRegistry(): Promise<{ adminOnly: boolean; winPcapCompatible: boolean }> {
  if (process.platform === "linux") return { adminOnly: false, winPcapCompatible: true };

  const output = await runPowerShell(
    "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\WOW6432Node\\Npcap' -ErrorAction SilentlyContinue | Select-Object AdminOnly,WinPcapCompatible | ConvertTo-Json -Compress",
  );
  if (!output) return { adminOnly: false, winPcapCompatible: false };

  try {
    const parsed = JSON.parse(output) as Record<string, unknown>;
    return {
      adminOnly: Number(parsed.AdminOnly) === 1,
      winPcapCompatible: Number(parsed.WinPcapCompatible) === 1,
    };
  } catch {
    return { adminOnly: false, winPcapCompatible: false };
  }
}

export function selectGameServerConnections(connections: CaptureConnection[]): CaptureConnection[] {
  return connections.filter((connection) => !isLikelyWebConnection(connection));
}

export function uniqueCaptureTargets(connections: CaptureConnection[]): CaptureTarget[] {
  const seen = new Set<string>();
  const targets: CaptureTarget[] = [];
  for (const connection of connections) {
    const key = `${connection.remoteAddress}:${connection.remotePort}`;
    if (seen.has(key)) continue;
    seen.add(key);
    targets.push({ remoteAddress: connection.remoteAddress, remotePort: Number(connection.remotePort) });
  }
  return targets;
}

export function stableCaptureFilter(localAddress: string): string {
  const webPortFilter = Array.from(WEB_REMOTE_PORTS)
    .map((port) => `port ${port}`)
    .join(" or ");
  return `tcp and host ${localAddress} and not (${webPortFilter}) and len > 30`;
}

export function summarizeConnections(connections: CaptureConnection[]): Array<Omit<CaptureConnection, "owningProcess">> {
  return connections.map((connection) => ({
    state: connection.state,
    localAddress: connection.localAddress,
    localPort: connection.localPort,
    remoteAddress: connection.remoteAddress,
    remotePort: connection.remotePort,
  }));
}

export function connectionSignature(connections: CaptureConnection[]): string {
  return connections
    .map((connection) => `${connection.localAddress}->${connection.remoteAddress}:${connection.remotePort}`)
    .sort()
    .filter((value, index, values) => index === 0 || values[index - 1] !== value)
    .join("|");
}

function isLikelyWebConnection(connection: CaptureConnection): boolean {
  return WEB_REMOTE_PORTS.has(Number(connection.remotePort));
}

function normalizeNumberArray(value: unknown): number[] {
  const values = Array.isArray(value) ? value : value === null || value === undefined ? [] : [value];
  return values.map(Number).filter(Number.isFinite);
}

function runPowerShell(script: string): Promise<string> {
  if (process.platform !== "win32") return Promise.resolve("");

  return new Promise((resolve) => {
    execFile(
      "powershell.exe",
      ["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
      { windowsHide: true, maxBuffer: 4 * 1024 * 1024 },
      (_error, stdout) => resolve(stdout.trim()),
    );
  });
}

function getLinuxHeroSiegeNetworkState(): HeroSiegeNetworkState {
  const gameProcessIds = findLinuxProcessIds((name) => name.startsWith("herosiege") && !name.includes("companion"));
  const antiCheatProcessIds = findLinuxProcessIds((name) => name.startsWith("easyanticheat"));
  const socketOwners = mapLinuxSocketOwners(gameProcessIds);
  return {
    gameProcessIds,
    antiCheatProcessIds,
    connections: parseLinuxTcpConnections(socketOwners),
  };
}

function findLinuxProcessIds(matches: (normalizedName: string) => boolean): number[] {
  const ids: number[] = [];
  for (const entry of safeReadDir("/proc")) {
    if (!/^\d+$/.test(entry)) continue;
    const pid = Number(entry);
    const name = linuxProcessName(pid);
    if (name && matches(normalizeProcessName(name))) ids.push(pid);
  }
  return ids;
}

function linuxProcessName(pid: number): string {
  const procDir = `/proc/${pid}`;
  const comm = safeReadFile(`${procDir}/comm`).trim();
  if (comm) return comm;

  const command = safeReadFile(`${procDir}/cmdline`).split("\0").find(Boolean);
  return command?.split("/").pop() ?? "";
}

function normalizeProcessName(name: string): string {
  return name.replace(/[^a-zA-Z0-9]/g, "").toLowerCase();
}

function mapLinuxSocketOwners(processIds: number[]): Map<string, number> {
  const owners = new Map<string, number>();
  for (const pid of processIds) {
    for (const fd of safeReadDir(`/proc/${pid}/fd`)) {
      const match = /^socket:\[(\d+)]$/.exec(safeReadLink(`/proc/${pid}/fd/${fd}`));
      if (match) owners.set(match[1], pid);
    }
  }
  return owners;
}

function parseLinuxTcpConnections(socketOwners: Map<string, number>): CaptureConnection[] {
  if (socketOwners.size === 0) return [];
  return [...parseLinuxTcpFile("/proc/net/tcp", socketOwners), ...parseLinuxTcpFile("/proc/net/tcp6", socketOwners)];
}

function parseLinuxTcpFile(filePath: string, socketOwners: Map<string, number>): CaptureConnection[] {
  const lines = safeReadFile(filePath).trim().split(/\r?\n/).slice(1);
  const connections: CaptureConnection[] = [];

  for (const line of lines) {
    const fields = line.trim().split(/\s+/);
    if (fields.length < 10) continue;

    const owner = socketOwners.get(fields[9]);
    if (!owner) continue;

    const local = parseLinuxSocketAddress(fields[1]);
    const remote = parseLinuxSocketAddress(fields[2]);
    if (!local || !remote || isLoopbackOrWildcard(remote.address)) continue;

    connections.push({
      owningProcess: owner,
      state: linuxTcpState(fields[3]),
      localAddress: local.address,
      localPort: local.port,
      remoteAddress: remote.address,
      remotePort: remote.port,
    });
  }

  return connections;
}

function parseLinuxSocketAddress(value: string): { address: string; port: number } | null {
  const [rawAddress, rawPort] = value.split(":");
  const port = Number.parseInt(rawPort, 16);
  if (!rawAddress || !Number.isFinite(port)) return null;

  if (rawAddress.length === 8) {
    const bytes = rawAddress.match(/../g)?.reverse().map((part) => Number.parseInt(part, 16));
    if (!bytes || bytes.some((byte) => !Number.isFinite(byte))) return null;
    return { address: bytes.join("."), port };
  }

  if (rawAddress.length === 32) return { address: parseLinuxIpv6Address(rawAddress), port };
  return null;
}

function parseLinuxIpv6Address(rawAddress: string): string {
  const words = rawAddress.match(/.{8}/g) ?? [];
  const segments = words.flatMap((word) => {
    const bytes = word.match(/../g)?.reverse() ?? [];
    return [bytes[0] + bytes[1], bytes[2] + bytes[3]];
  });

  const isIpv4Mapped =
    segments.length === 8 &&
    segments.slice(0, 5).every((segment) => Number.parseInt(segment, 16) === 0) &&
    Number.parseInt(segments[5], 16) === 0xffff;

  if (isIpv4Mapped) {
    const hex = `${segments[6]}${segments[7]}`.padStart(8, "0");
    const bytes = hex.match(/../g)?.map((part) => Number.parseInt(part, 16)) ?? [];
    if (bytes.length === 4 && bytes.every(Number.isFinite)) return bytes.join(".");
  }

  return segments.map((segment) => segment.replace(/^0{1,3}/, "") || "0").join(":");
}

function linuxTcpState(state: string): string {
  if (state === "01") return "Established";
  if (state === "02") return "SynSent";
  if (state === "03") return "SynReceived";
  if (state === "06") return "TimeWait";
  if (state === "0A") return "Listen";
  return state;
}

function isLoopbackOrWildcard(address: string): boolean {
  return address === "0.0.0.0" || address === "127.0.0.1" || address === "::" || address === "::1";
}

function safeReadDir(dirPath: string): string[] {
  try {
    return fs.readdirSync(dirPath);
  } catch {
    return [];
  }
}

function safeReadFile(filePath: string): string {
  try {
    return fs.readFileSync(filePath, "utf8");
  } catch {
    return "";
  }
}

function safeReadLink(filePath: string): string {
  try {
    return fs.readlinkSync(filePath);
  } catch {
    return "";
  }
}
