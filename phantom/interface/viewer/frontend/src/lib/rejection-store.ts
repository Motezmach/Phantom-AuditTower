import type { Vulnerability } from "@/types/issues";
import {
  createRejection as createRejectionRequest,
  deleteRejection as deleteRejectionRequest,
  fetchRejections,
  type RejectionEntry as ServerRejectionEntry,
} from "@/data/serverSource";

export const REJECTIONS_CHANGED_EVENT = "phantom-rejections-changed";

/** Client representation of a server-backed Rejection record. */
export interface RejectionEntry {
  id: string;
  targetName: string;
  targetUrl: string | null;
  targetId?: string | null;
  auditorName: string;
  reason: string;
  rejectedAt: string;
  runName: string | null;
  sourceFindingId?: string;
  findingTitle: string;
  finding: Vulnerability;
}

export interface AddRejectionResult {
  entry: RejectionEntry;
  created: boolean;
}

// The server registry is authoritative; rejections are never cached in
// localStorage (unlike Playbooks) because they carry no offline value.
let remoteEntries: RejectionEntry[] | null = null;
let loadPromise: Promise<RejectionEntry[]> | null = null;

function fromServerEntry(entry: ServerRejectionEntry): RejectionEntry {
  return {
    id: entry.id,
    targetName: entry.targetName,
    targetUrl: entry.targetUrl,
    targetId: entry.targetId,
    auditorName: entry.auditorName,
    reason: entry.reason,
    rejectedAt: entry.rejectedAt,
    runName: entry.runName,
    sourceFindingId: entry.sourceFindingId,
    findingTitle: entry.findingTitle,
    finding: entry.finding,
  };
}

function publishChange(): void {
  if (typeof window !== "undefined") {
    window.dispatchEvent(new Event(REJECTIONS_CHANGED_EVENT));
  }
}

export function listRejections(): RejectionEntry[] {
  return (remoteEntries ?? []).slice().sort((a, b) => b.rejectedAt.localeCompare(a.rejectedAt));
}

function normalizeIdentityPart(value: unknown): string {
  return (typeof value === "string" ? value : "").trim().toLowerCase().replace(/\/$/, "");
}

// Mirror of playbook-store's isSameFinding so a rejection is recognised across
// rescans (new finding ids) by target + title + endpoint + method.
function isSameFinding(
  entry: RejectionEntry,
  input: { runName?: string | null; targetUrl?: string | null; finding: Vulnerability },
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

export async function loadRejections(): Promise<RejectionEntry[]> {
  if (loadPromise) return loadPromise;
  loadPromise = (async () => {
    try {
      remoteEntries = (await fetchRejections()).map(fromServerEntry);
    } catch {
      // Keep the last known cache visible on a transient error.
      remoteEntries = remoteEntries ?? [];
    }
    publishChange();
    return listRejections();
  })().finally(() => {
    loadPromise = null;
  });
  return loadPromise;
}

export function findRejection(
  runName: string | null | undefined,
  finding: Vulnerability,
): RejectionEntry | null {
  return (
    listRejections().find((entry) =>
      isSameFinding(entry, { runName, targetUrl: finding.target, finding }),
    ) ?? null
  );
}

export async function addRejection(input: {
  reason: string;
  auditorName: string;
  runName?: string | null;
  finding: Vulnerability;
}): Promise<AddRejectionResult> {
  const existing = listRejections().find((entry) =>
    isSameFinding(entry, { runName: input.runName, targetUrl: input.finding.target, finding: input.finding }),
  );
  if (existing) return { entry: existing, created: false };
  if (!input.runName) {
    throw new Error("This finding has no source run and cannot be rejected in the server registry.");
  }
  const result = await createRejectionRequest(
    input.runName,
    input.finding.id,
    input.reason,
    input.auditorName,
  );
  if (!result.ok) {
    if (result.entry) return { entry: fromServerEntry(result.entry), created: false };
    throw new Error(result.message);
  }
  const entry = fromServerEntry(result.entry);
  remoteEntries = [...(remoteEntries ?? []), entry];
  publishChange();
  return { entry, created: true };
}

export async function removeRejection(id: string): Promise<void> {
  const result = await deleteRejectionRequest(id);
  if (!result.ok) throw new Error(result.message ?? "Could not undo this rejection.");
  remoteEntries = (remoteEntries ?? []).filter((entry) => entry.id !== id);
  publishChange();
}
