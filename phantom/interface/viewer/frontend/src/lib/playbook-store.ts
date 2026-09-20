import type { Vulnerability } from "@/types/issues";
import {
  createPlaybook as createPlaybookRequest,
  deletePlaybook as deletePlaybookRequest,
  fetchPlaybooks,
  setPlaybookRemediation as setPlaybookRemediationRequest,
  type PlaybookEntry as ServerPlaybookEntry,
} from "@/data/serverSource";

const STORAGE_KEY = "phantom_playbooks_v1";
const AUDITOR_KEY = "phantom_playbook_auditor";
export const PLAYBOOKS_CHANGED_EVENT = "phantom-playbooks-changed";

/** Client representation of a server-backed Playbook record. */
export interface PlaybookEntry {
  id: string;
  name: string;
  targetName: string;
  targetUrl: string | null;
  targetId?: string | null;
  auditorName: string;
  addedAt: string;
  updatedAt?: string;
  runName: string | null;
  sourceFindingId?: string;
  status?: string;
  replayCount?: number;
  lastReplayAt?: string | null;
  lastReplayStatus?: string | null;
  lastReplayReason?: string | null;
  replayHistory?: Array<Record<string, unknown>>;
  confirmedByReplayId?: string | null;
  remediationStatus?: "open" | "fixed" | "reopened";
  owner?: string | null;
  dueDate?: string | null;
  fixedAt?: string | null;
  reopenedAt?: string | null;
  finding: Vulnerability;
}

export interface AddPlaybookResult {
  entry: PlaybookEntry;
  created: boolean;
}

let remoteEntries: PlaybookEntry[] | null = null;
let loadPromise: Promise<PlaybookEntry[]> | null = null;
let migrationAttempted = false;

function readEntries(): PlaybookEntry[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((item): item is PlaybookEntry => {
      if (!item || typeof item !== "object") return false;
      const entry = item as Partial<PlaybookEntry>;
      const finding = entry.finding as Partial<Vulnerability> | null | undefined;
      return (
        typeof entry.id === "string" &&
        typeof entry.name === "string" &&
        typeof entry.targetName === "string" &&
        typeof entry.auditorName === "string" &&
        typeof entry.addedAt === "string" &&
        !!finding &&
        typeof finding.id === "string" &&
        typeof finding.title === "string"
      );
    });
  } catch {
    return [];
  }
}

function persistEntries(entries: PlaybookEntry[]): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(entries));
  } catch {
    // The server registry remains authoritative when browser storage is unavailable.
  }
}

function publishChange(): void {
  if (typeof window !== "undefined") {
    window.dispatchEvent(new Event(PLAYBOOKS_CHANGED_EVENT));
  }
}

export function listPlaybooks(): PlaybookEntry[] {
  return dedupeEntries(remoteEntries ?? readEntries()).sort((a, b) =>
    b.addedAt.localeCompare(a.addedAt),
  );
}

function normalizeIdentityPart(value: unknown): string {
  return (typeof value === "string" ? value : "").trim().toLowerCase().replace(/\/$/, "");
}

function isSameFinding(
  entry: PlaybookEntry,
  input: {
    runName?: string | null;
    targetUrl?: string | null;
    finding: Vulnerability;
  },
): boolean {
  if (input.runName && entry.runName === input.runName && entry.finding.id === input.finding.id) {
    return true;
  }
  const target = normalizeIdentityPart(input.targetUrl);
  if (!target || normalizeIdentityPart(entry.targetUrl) !== target) return false;
  return (
    normalizeIdentityPart(entry.finding.title) === normalizeIdentityPart(input.finding.title) &&
    normalizeIdentityPart(entry.finding.endpoint) === normalizeIdentityPart(input.finding.endpoint) &&
    normalizeIdentityPart(entry.finding.method) === normalizeIdentityPart(input.finding.method)
  );
}

function dedupeEntries(entries: PlaybookEntry[]): PlaybookEntry[] {
  const unique: PlaybookEntry[] = [];
  for (const entry of entries) {
    if (!unique.some((existing) => isSameFinding(existing, entry))) unique.push(entry);
  }
  return unique;
}

// Cross-run recognition. The AI emits fresh findings each run with no stable link to
// saved playbooks: titles are reworded, endpoints re-spelled, and the target host
// differs (a playbook saved against localhost:3000 is re-scanned as
// host.docker.internal:3000). Exact title+target matching therefore never fires. Match
// on the stable *shape* instead — endpoint path + HTTP method + CWE — host-agnostic but
// port-scoped, so a re-scan of the same app recognises its own confirmed attacks without
// over-matching a different app (over-matching would hide a genuinely new finding).
function normalizeEndpointTokens(value: unknown): Set<string> {
  return new Set(
    String(value ?? "")
      .split(",")
      .map((token) =>
        token
          .trim()
          .toLowerCase()
          .replace(/\?.*$/, "") // drop query string
          .replace(/\s*\([^)]*\)\s*/g, "") // drop "(q query parameter)" notes
          .replace(/\{[^}/]+\}/g, "*") // {id} -> *
          .replace(/:[^/]+/g, "*") // :id  -> *
          .replace(/\/\d+(?=\/|$)/g, "/*") // /123 -> /*
          .replace(/\/+$/, ""), // drop trailing slash
      )
      .filter(Boolean),
  );
}

function splitUpper(value: unknown): Set<string> {
  return new Set(
    String(value ?? "")
      .split(",")
      .map((part) => part.trim().toUpperCase())
      .filter(Boolean),
  );
}

function cweId(value: unknown): string {
  const match = String(value ?? "").match(/(\d+)/);
  return match ? `cwe-${match[1]}` : "";
}

function portOf(value: unknown): string {
  const match = String(value ?? "").match(/:(\d+)(?:\D|$)/);
  return match ? match[1] : "";
}

function setsIntersect(a: Set<string>, b: Set<string>): boolean {
  for (const value of a) if (b.has(value)) return true;
  return false;
}

/** Robust cross-run match: same endpoint + method + CWE (host-agnostic, port-scoped). */
function matchesFindingShape(entry: PlaybookEntry, finding: Vulnerability): boolean {
  const entryPort = portOf(entry.targetUrl ?? entry.finding.target);
  const findingPort = portOf(finding.target);
  if (entryPort && findingPort && entryPort !== findingPort) return false;
  const endpointsA = normalizeEndpointTokens(entry.finding.endpoint);
  const endpointsB = normalizeEndpointTokens(finding.endpoint);
  if (!endpointsA.size || !endpointsB.size || !setsIntersect(endpointsA, endpointsB)) return false;
  const methodsA = splitUpper(entry.finding.method);
  const methodsB = splitUpper(finding.method);
  if (methodsA.size && methodsB.size && !setsIntersect(methodsA, methodsB)) return false;
  const cweA = cweId(entry.finding.cwe);
  const cweB = cweId(finding.cwe);
  if (cweA && cweB && cweA !== cweB) return false;
  return true;
}

function fromServerEntry(entry: ServerPlaybookEntry): PlaybookEntry {
  return {
    id: entry.id,
    name: entry.name,
    targetName: entry.targetName,
    targetUrl: entry.targetUrl,
    targetId: entry.targetId,
    auditorName: entry.auditorName,
    addedAt: entry.addedAt,
    updatedAt: entry.updatedAt,
    runName: entry.runName,
    sourceFindingId: entry.sourceFindingId,
    status: entry.status,
    replayCount: entry.replayCount,
    lastReplayAt: entry.lastReplayAt,
    lastReplayStatus: entry.lastReplayStatus,
    lastReplayReason: entry.lastReplayReason,
    replayHistory: entry.replayHistory,
    confirmedByReplayId: entry.confirmedByReplayId,
    remediationStatus: entry.remediationStatus,
    owner: entry.owner,
    dueDate: entry.dueDate,
    fixedAt: entry.fixedAt,
    reopenedAt: entry.reopenedAt,
    finding: entry.finding,
  };
}

/** Load the server registry, preserving valid legacy browser entries by re-saving their source findings. */
export async function loadPlaybooks(): Promise<PlaybookEntry[]> {
  if (loadPromise) return loadPromise;
  loadPromise = (async () => {
    const localEntries = readEntries();
    let entries: PlaybookEntry[];
    try {
      entries = (await fetchPlaybooks()).map(fromServerEntry);
      if (!migrationAttempted) {
        migrationAttempted = true;
        const remoteKeys = new Set(entries.map((entry) => `${entry.runName}:${entry.finding.id}`));
        for (const legacy of localEntries) {
          const key = `${legacy.runName}:${legacy.finding.id}`;
          if (!legacy.runName || remoteKeys.has(key)) continue;
          const imported = await createPlaybookRequest(
            legacy.runName,
            legacy.finding.id,
            legacy.name,
            legacy.auditorName,
          );
          if (imported.ok) {
            entries.push(fromServerEntry(imported.entry));
            remoteKeys.add(key);
          } else if (imported.entry) {
            entries.push(fromServerEntry(imported.entry));
            remoteKeys.add(key);
          } else {
            // The server no longer accepts unsigned creates. Keep a browser
            // legacy entry visible so the auditor can replay and upgrade it
            // instead of silently losing the old local library.
            entries.push(legacy);
            remoteKeys.add(key);
          }
        }
      }
      remoteEntries = dedupeEntries(entries);
    } catch {
      // Keep the last known server cache or legacy browser entries visible on a transient startup error.
      remoteEntries = remoteEntries ?? dedupeEntries(localEntries);
    }
    persistEntries(remoteEntries);
    publishChange();
    return listPlaybooks();
  })().finally(() => {
    loadPromise = null;
  });
  return loadPromise;
}

export function findPlaybook(
  runName: string | null | undefined,
  finding: Vulnerability,
): PlaybookEntry | null {
  const entries = listPlaybooks();
  return (
    entries.find((entry) =>
      isSameFinding(entry, { runName, targetUrl: finding.target, finding }),
    ) ??
    // Fallback: recognise the same finding across runs (reworded title / different
    // target host) by its stable endpoint+method+CWE shape.
    entries.find((entry) => matchesFindingShape(entry, finding)) ??
    null
  );
}

export function findPlaybookById(id: string | null | undefined): PlaybookEntry | null {
  const normalized = typeof id === "string" ? id.trim() : "";
  if (!normalized) return null;
  return listPlaybooks().find((entry) => entry.id === normalized) ?? null;
}

export function getLastAuditorName(): string {
  try {
    return localStorage.getItem(AUDITOR_KEY) || "Local auditor";
  } catch {
    return "Local auditor";
  }
}

export async function addPlaybook(input: {
  name: string;
  targetName: string;
  targetUrl?: string | null;
  auditorName: string;
  runName?: string | null;
  confirmedReplayId?: string | null;
  finding: Vulnerability;
}): Promise<AddPlaybookResult> {
  const existing = listPlaybooks().find((entry) => isSameFinding(entry, input));
  // A legacy Playbook can be upgraded after the auditor watches a confirmed
  // replay. A replay-backed record is already signed and remains immutable.
  if (existing && (existing.confirmedByReplayId || !input.confirmedReplayId)) {
    return { entry: existing, created: false };
  }
  if (!input.runName) {
    throw new Error("This finding has no source run and cannot be saved to the server Playbook.");
  }
  const result = await createPlaybookRequest(
    input.runName,
    input.finding.id,
    input.name,
    input.auditorName,
    null,
    input.confirmedReplayId ?? null,
  );
  if (!result.ok) {
    if (result.entry) return { entry: fromServerEntry(result.entry), created: false };
    throw new Error(result.message);
  }
  const entry = fromServerEntry(result.entry);
  const previousEntries = remoteEntries ?? readEntries();
  remoteEntries = dedupeEntries([
    entry,
    ...previousEntries.filter((item) => item.id !== entry.id),
  ]);
  try {
    localStorage.setItem(AUDITOR_KEY, entry.auditorName);
  } catch {
    /* best-effort preference */
  }
  persistEntries(remoteEntries);
  publishChange();
  return { entry, created: true };
}

export async function removePlaybook(id: string): Promise<void> {
  if (id.startsWith("pb_")) {
    const result = await deletePlaybookRequest(id);
    if (!result.ok) throw new Error(result.message ?? "Could not remove this Playbook.");
  }
  remoteEntries = listPlaybooks().filter((entry) => entry.id !== id);
  persistEntries(remoteEntries);
  publishChange();
}

/** Set the analyst-owned remediation metadata (owner + due date) on a signed finding. */
export async function updatePlaybookRemediation(
  id: string,
  owner: string | null,
  dueDate: string | null,
): Promise<PlaybookEntry> {
  const result = await setPlaybookRemediationRequest(id, owner, dueDate);
  if (!result.ok || !result.entry) {
    throw new Error(result.message ?? "Could not update remediation.");
  }
  const entry = fromServerEntry(result.entry);
  remoteEntries = (remoteEntries ?? readEntries()).map((item) => (item.id === entry.id ? entry : item));
  persistEntries(remoteEntries);
  publishChange();
  return entry;
}
