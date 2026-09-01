import type { Vulnerability } from "@/types/issues";

const STORAGE_KEY = "phantom_playbooks_v1";
const AUDITOR_KEY = "phantom_playbook_auditor";
export const PLAYBOOKS_CHANGED_EVENT = "phantom-playbooks-changed";

export interface PlaybookEntry {
  id: string;
  name: string;
  targetName: string;
  targetUrl: string | null;
  auditorName: string;
  addedAt: string;
  runName: string | null;
  finding: Vulnerability;
}

export interface AddPlaybookResult {
  entry: PlaybookEntry;
  created: boolean;
}

function createId(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return `playbook-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

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

function writeEntries(entries: PlaybookEntry[]): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(entries));
    window.dispatchEvent(new Event(PLAYBOOKS_CHANGED_EVENT));
  } catch {
    // Local persistence is best-effort. The UI reports failure at the form
    // level rather than breaking the findings viewer.
  }
}

export function listPlaybooks(): PlaybookEntry[] {
  return dedupeEntries(readEntries()).sort((a, b) => b.addedAt.localeCompare(a.addedAt));
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
  // The run/id pair is the strongest identity for the current report.
  if (input.runName && entry.runName === input.runName && entry.finding.id === input.finding.id) {
    return true;
  }
  // Also prevent duplicate copies when the same target is rescanned and the
  // scanner assigns a new per-run finding id.
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
    const duplicate = unique.some((existing) =>
      isSameFinding(existing, {
        runName: entry.runName,
        targetUrl: entry.targetUrl,
        finding: entry.finding,
      })
    );
    if (!duplicate) unique.push(entry);
  }
  return unique;
}

export function findPlaybook(
  runName: string | null | undefined,
  finding: Vulnerability,
): PlaybookEntry | null {
  const targetUrl = finding.target;
  return (
    readEntries().find((entry) => isSameFinding(entry, { runName, targetUrl, finding })) ?? null
  );
}

export function getLastAuditorName(): string {
  try {
    return localStorage.getItem(AUDITOR_KEY) || "Local auditor";
  } catch {
    return "Local auditor";
  }
}

export function addPlaybook(input: {
  name: string;
  targetName: string;
  targetUrl?: string | null;
  auditorName: string;
  runName?: string | null;
  finding: Vulnerability;
}): AddPlaybookResult {
  const entries = dedupeEntries(readEntries());
  const existing = entries.find((entry) => isSameFinding(entry, input));
  if (existing) return { entry: existing, created: false };

  const entry: PlaybookEntry = {
    id: createId(),
    name: input.name.trim(),
    targetName: input.targetName.trim(),
    targetUrl: input.targetUrl ?? null,
    auditorName: input.auditorName.trim(),
    addedAt: new Date().toISOString(),
    runName: input.runName ?? null,
    // Keep the exact finding snapshot that the analyst approved for the
    // library. Future backend work can replace this with a durable record.
    finding: structuredClone(input.finding),
  };
  entries.push(entry);
  try {
    localStorage.setItem(AUDITOR_KEY, entry.auditorName);
  } catch {
    /* best-effort preference */
  }
  writeEntries(entries);
  return { entry, created: true };
}

export function removePlaybook(id: string): void {
  writeEntries(readEntries().filter((entry) => entry.id !== id));
}
