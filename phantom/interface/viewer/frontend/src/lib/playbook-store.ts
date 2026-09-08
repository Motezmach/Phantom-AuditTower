import type { Vulnerability } from "@/types/issues";
import {
  createPlaybook as createPlaybookRequest,
  deletePlaybook as deletePlaybookRequest,
  fetchPlaybooks,
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
  return (
    listPlaybooks().find((entry) =>
      isSameFinding(entry, { runName, targetUrl: finding.target, finding }),
    ) ?? null
  );
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
  finding: Vulnerability;
}): Promise<AddPlaybookResult> {
  const existing = listPlaybooks().find((entry) => isSameFinding(entry, input));
  if (existing) return { entry: existing, created: false };
  if (!input.runName) {
    throw new Error("This finding has no source run and cannot be saved to the server Playbook.");
  }
  const result = await createPlaybookRequest(
    input.runName,
    input.finding.id,
    input.name,
    input.auditorName,
  );
  if (!result.ok) {
    if (result.entry) return { entry: fromServerEntry(result.entry), created: false };
    throw new Error(result.message);
  }
  const entry = fromServerEntry(result.entry);
  remoteEntries = dedupeEntries([...(remoteEntries ?? readEntries()), entry]);
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
