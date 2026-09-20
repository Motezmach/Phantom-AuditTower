import type { Vulnerability } from "@/types/issues";
import {
  parseVulnerabilityRecord,
  parseRunJson,
  parseVulnerabilitiesJson,
  type ParsedRunSummary,
} from "@/lib/local-run-parser";

/**
 * Data seam for the local viewer: fetches against the local Python server's
 * JSON endpoints (same origin, relative URLs), producing the in-memory
 * `LoadedRun` shape the UI renders plus a `finished` flag driving live polling.
 *
 * The server serves a live in-progress run and a finished one identically; the
 * only signal is `run.finished`.
 */

/** A transcript agent as emitted by GET /api/transcript (already parsed). */
export interface TranscriptAgent {
  id: string;
  name: string;
  parent_id: string | null;
  status: string;
  created_at: string;
  updated_at: string;
}

/** Chat/tool event data as emitted by GET /api/transcript. */
export interface TranscriptEvent {
  id: string;
  type: "chat" | "tool";
  agent_id: string;
  timestamp: string;
  version: number;
  data: Record<string, unknown>;
}

export interface Transcript {
  agents: TranscriptAgent[];
  events: TranscriptEvent[];
}

export interface LoadedRun {
  summary: ParsedRunSummary;
  /** Whole raw run record (for llm_usage, targets_info details, etc.). */
  raw: Record<string, unknown>;
  finished: boolean;
  vulnerabilities: Vulnerability[];
  reportMarkdown: string | null;
  transcript: Transcript;
  review: RunReviewSummary;
}

export interface RunReviewSummary {
  candidateCount: number;
  signedCount: number;
  rejectedCount: number;
  pendingCount: number;
  decidedCount: number;
  reportReady: boolean;
}

function parseReviewSummary(raw: unknown): RunReviewSummary {
  const value = raw && typeof raw === "object" ? raw as Record<string, unknown> : {};
  const number = (key: string) => typeof value[key] === "number" && Number.isFinite(value[key])
    ? value[key] as number
    : 0;
  return {
    candidateCount: number("candidate_count"),
    signedCount: number("signed_count"),
    rejectedCount: number("rejected_count"),
    pendingCount: number("pending_count"),
    decidedCount: number("decided_count"),
    reportReady: value.report_ready === true,
  };
}

export interface DashboardInfo {
  mode: "dashboard" | "viewer";
  /** Whether this dashboard owns a scan manager (can add targets / launch scans). */
  canManageScans: boolean;
  /** The live run this dashboard was launched for (the TUI); null for `phantom serve`. */
  defaultRun: string | null;
  llm: {
    configured: boolean;
    model: string | null;
    endpoint: "local" | "provider";
  };
  target_count: number;
}

export interface RegisteredTarget {
  id: string;
  name: string;
  base_url: string;
  scope_hosts: string[];
  active: boolean;
  created_at: string;
  updated_at: string;
}

export type ScanMode = "quick" | "deep";
export type ScanJobStatus = "preparing" | "running" | "completed" | "failed" | "stopped";

export interface ScanJob {
  id: string;
  target_id: string;
  target_name: string;
  target_url: string;
  scan_mode: ScanMode;
  status: ScanJobStatus;
  run_name: string | null;
  created_at: string;
  started_at: string | null;
  ended_at: string | null;
  error: string | null;
  stop_requested: boolean;
}

export interface ScansPayload {
  active: ScanJob | null;
  jobs: ScanJob[];
}

export interface PlaybookEntry {
  id: string;
  name: string;
  targetName: string;
  targetUrl: string | null;
  targetId: string | null;
  auditorName: string;
  addedAt: string;
  updatedAt: string;
  runName: string | null;
  sourceFindingId: string;
  status: string;
  replayCount: number;
  lastReplayAt: string | null;
  lastReplayStatus: ReplayJobStatus | null;
  lastReplayReason: string | null;
  replayHistory: Array<Record<string, unknown>>;
  confirmedByReplayId: string | null;
  remediationStatus: "open" | "fixed" | "reopened";
  owner: string | null;
  dueDate: string | null;
  fixedAt: string | null;
  reopenedAt: string | null;
  finding: Vulnerability;
}

function parsePlaybook(raw: unknown): PlaybookEntry | null {
  if (!raw || typeof raw !== "object") return null;
  const item = raw as Record<string, unknown>;
  if (!item.finding || typeof item.finding !== "object") return null;
  const finding = item.finding as Record<string, unknown>;
  return {
    id: String(item.id ?? ""),
    name: String(item.name ?? ""),
    targetName: String(item.target_name ?? ""),
    targetUrl: typeof item.target_url === "string" ? item.target_url : null,
    targetId: typeof item.target_id === "string" ? item.target_id : null,
    auditorName: String(item.auditor_name ?? ""),
    addedAt: String(item.added_at ?? ""),
    updatedAt: String(item.updated_at ?? item.added_at ?? ""),
    runName: typeof item.source_run_name === "string" ? item.source_run_name : null,
    sourceFindingId: String(item.source_finding_id ?? ""),
    status: String(item.status ?? "active"),
    replayCount: typeof item.replay_count === "number" ? item.replay_count : 0,
    lastReplayAt: typeof item.last_replay_at === "string" ? item.last_replay_at : null,
    lastReplayStatus: typeof item.last_replay_status === "string" ? item.last_replay_status as ReplayJobStatus : null,
    lastReplayReason: typeof item.last_replay_reason === "string" ? item.last_replay_reason : null,
    replayHistory: Array.isArray(item.replay_history) ? item.replay_history.filter((entry): entry is Record<string, unknown> => !!entry && typeof entry === "object") : [],
    confirmedByReplayId: typeof item.confirmed_by_replay_id === "string" ? item.confirmed_by_replay_id : null,
    remediationStatus:
      item.remediation_status === "fixed" || item.remediation_status === "reopened"
        ? item.remediation_status
        : "open",
    owner: typeof item.owner === "string" && item.owner ? item.owner : null,
    dueDate: typeof item.due_date === "string" && item.due_date ? item.due_date : null,
    fixedAt: typeof item.fixed_at === "string" ? item.fixed_at : null,
    reopenedAt: typeof item.reopened_at === "string" ? item.reopened_at : null,
    // Playbook records may come from an older scan snapshot and therefore
    // omit fields that the issue detail page expects (for example `status`) or
    // use the writer's scalar CWE form. Reuse the run parser's normalization
    // seam so the Playbook detail is identical to the Issues detail.
    finding: parseVulnerabilityRecord(finding, 0, null),
  };
}

export async function fetchPlaybooks(targetId?: string | null): Promise<PlaybookEntry[]> {
  const suffix = targetId ? `?target_id=${encodeURIComponent(targetId)}` : "";
  const obj = (await getJson(`/api/playbooks${suffix}`)) as { playbooks?: unknown };
  return Array.isArray(obj?.playbooks)
    ? obj.playbooks.map(parsePlaybook).filter((item): item is PlaybookEntry => item !== null)
    : [];
}

export type CreatePlaybookResult =
  | { ok: true; entry: PlaybookEntry; created: true }
  | { ok: false; message: string; code?: string; entry?: PlaybookEntry };

export async function createPlaybook(
  runName: string,
  findingId: string,
  name: string,
  auditorName: string,
  targetId?: string | null,
  confirmedReplayId?: string | null,
): Promise<CreatePlaybookResult> {
  const { ok, data } = await postJson("/api/playbooks", {
    run: runName,
    finding_id: findingId,
    name,
    auditor_name: auditorName,
    ...(targetId ? { target_id: targetId } : {}),
    ...(confirmedReplayId ? { confirmed_replay_id: confirmedReplayId } : {}),
  });
  const entry = parsePlaybook(data.playbook);
  if (ok && entry) return { ok: true, entry, created: true };
  return {
    ok: false,
    code: typeof data.error === "string" ? data.error : undefined,
    entry: entry ?? undefined,
    message: typeof data.message === "string" ? data.message : "Could not save this Playbook.",
  };
}

export async function deletePlaybook(id: string): Promise<{ ok: boolean; message?: string }> {
  const { ok, data } = await fetch(`/api/playbooks/${encodeURIComponent(id)}`, {
    method: "DELETE",
    cache: "no-store",
  }).then(async (res) => {
    let parsed: Record<string, unknown> = {};
    try {
      const body = await res.json();
      if (body && typeof body === "object") parsed = body as Record<string, unknown>;
    } catch {
      /* empty response */
    }
    return { ok: res.ok, data: parsed };
  });
  return ok ? { ok: true } : { ok: false, message: typeof data.message === "string" ? data.message : "Could not remove this Playbook." };
}

/** POST /api/playbooks/{id}/remediation — set the analyst-owned owner + due date. */
export async function setPlaybookRemediation(
  id: string,
  owner: string | null,
  dueDate: string | null,
): Promise<{ ok: boolean; entry?: PlaybookEntry; message?: string }> {
  const { ok, data } = await postJson(`/api/playbooks/${encodeURIComponent(id)}/remediation`, {
    owner: owner ?? "",
    due_date: dueDate ?? "",
  });
  const entry = parsePlaybook(data.playbook);
  if (ok && entry) return { ok: true, entry };
  return {
    ok: false,
    message: typeof data.message === "string" ? data.message : "Could not update remediation.",
  };
}

export interface RejectionEntry {
  id: string;
  targetName: string;
  targetUrl: string | null;
  targetId: string | null;
  auditorName: string;
  reason: string;
  rejectedAt: string;
  updatedAt: string;
  runName: string | null;
  sourceFindingId: string;
  findingTitle: string;
  finding: Vulnerability;
}

function parseRejection(raw: unknown): RejectionEntry | null {
  if (!raw || typeof raw !== "object") return null;
  const item = raw as Record<string, unknown>;
  if (!item.finding || typeof item.finding !== "object") return null;
  const finding = item.finding as Record<string, unknown>;
  return {
    id: String(item.id ?? ""),
    targetName: String(item.target_name ?? ""),
    targetUrl: typeof item.target_url === "string" ? item.target_url : null,
    targetId: typeof item.target_id === "string" ? item.target_id : null,
    auditorName: String(item.auditor_name ?? ""),
    reason: String(item.reason ?? ""),
    rejectedAt: String(item.rejected_at ?? ""),
    updatedAt: String(item.updated_at ?? item.rejected_at ?? ""),
    runName: typeof item.source_run_name === "string" ? item.source_run_name : null,
    sourceFindingId: String(item.source_finding_id ?? ""),
    findingTitle: String(item.finding_title ?? finding.title ?? ""),
    finding: parseVulnerabilityRecord(finding, 0, null),
  };
}

export async function fetchRejections(targetId?: string | null): Promise<RejectionEntry[]> {
  const suffix = targetId ? `?target_id=${encodeURIComponent(targetId)}` : "";
  const obj = (await getJson(`/api/rejections${suffix}`)) as { rejections?: unknown };
  return Array.isArray(obj?.rejections)
    ? obj.rejections.map(parseRejection).filter((item): item is RejectionEntry => item !== null)
    : [];
}

export type CreateRejectionResult =
  | { ok: true; entry: RejectionEntry; created: true }
  | { ok: false; message: string; code?: string; entry?: RejectionEntry };

export async function createRejection(
  runName: string,
  findingId: string,
  reason: string,
  auditorName: string,
  targetId?: string | null,
): Promise<CreateRejectionResult> {
  const { ok, data } = await postJson("/api/rejections", {
    run: runName,
    finding_id: findingId,
    reason,
    auditor_name: auditorName,
    ...(targetId ? { target_id: targetId } : {}),
  });
  const entry = parseRejection(data.rejection);
  if (ok && entry) return { ok: true, entry, created: true };
  return {
    ok: false,
    code: typeof data.error === "string" ? data.error : undefined,
    entry: entry ?? undefined,
    message: typeof data.message === "string" ? data.message : "Could not reject this finding.",
  };
}

export async function deleteRejection(id: string): Promise<{ ok: boolean; message?: string }> {
  const { ok, data } = await fetch(`/api/rejections/${encodeURIComponent(id)}`, {
    method: "DELETE",
    cache: "no-store",
  }).then(async (res) => {
    let parsed: Record<string, unknown> = {};
    try {
      const body = await res.json();
      if (body && typeof body === "object") parsed = body as Record<string, unknown>;
    } catch {
      /* empty response */
    }
    return { ok: res.ok, data: parsed };
  });
  return ok ? { ok: true } : { ok: false, message: typeof data.message === "string" ? data.message : "Could not undo this rejection." };
}

export type ReplayJobStatus =
  | "preparing"
  | "running"
  | "confirmed"
  | "not_reproduced"
  | "inconclusive"
  | "blocked"
  | "failed";

export interface ReplayJob {
  id: string;
  run_name: string;
  finding_id: string;
  status: ReplayJobStatus;
  created_at: string;
  started_at: string | null;
  ended_at: string | null;
  phase: string;
  output: string[];
  script: string;
  result: Record<string, unknown> | null;
  error: string | null;
}

async function getJson(path: string): Promise<unknown> {
  const res = await fetch(path, { cache: "no-store" });
  if (!res.ok) throw new Error(`${path} responded ${res.status}`);
  return res.json();
}

/** Build a ``?run=<name>`` suffix for run-scoped data endpoints. */
function runQuery(runName?: string | null): string {
  return runName ? `?run=${encodeURIComponent(runName)}` : "";
}

export async function fetchRunSummary(runName?: string | null): Promise<{
  summary: ParsedRunSummary;
  raw: Record<string, unknown>;
  finished: boolean;
  review: RunReviewSummary;
}> {
  const raw = (await getJson("/api/run" + runQuery(runName))) as Record<string, unknown>;
  // parseRunJson tolerates extra keys and takes raw TEXT.
  const summary = parseRunJson(JSON.stringify(raw));
  const finished = raw.finished === true;
  return { summary, raw, finished, review: parseReviewSummary(raw.review_summary) };
}

export async function fetchVulnerabilities(
  runId: string | null,
  runName?: string | null
): Promise<Vulnerability[]> {
  const arr = await getJson("/api/vulnerabilities" + runQuery(runName));
  return parseVulnerabilitiesJson(JSON.stringify(arr), runId);
}

export async function fetchReportMarkdown(runName?: string | null): Promise<string | null> {
  const obj = (await getJson("/api/report" + runQuery(runName))) as { markdown?: string };
  return obj?.markdown ?? null;
}

export async function fetchTranscript(runName?: string | null): Promise<Transcript> {
  const obj = (await getJson("/api/transcript" + runQuery(runName))) as Partial<Transcript>;
  return {
    agents: Array.isArray(obj?.agents) ? obj.agents : [],
    events: Array.isArray(obj?.events) ? obj.events : [],
  };
}

/** One-shot fetch of every endpoint (used on mount and on final settle). */
export async function fetchAll(runName?: string | null): Promise<LoadedRun> {
  const { summary, raw, finished, review } = await fetchRunSummary(runName);
  const reportPromise = finished && review.reportReady
    ? fetchReportMarkdown(runName).catch(() => null)
    : Promise.resolve(null);
  const [vulnerabilities, reportMarkdown, transcript] = await Promise.all([
    fetchVulnerabilities(summary.runId, runName).catch(() => [] as Vulnerability[]),
    reportPromise,
    fetchTranscript(runName).catch(() => ({ agents: [], events: [] }) as Transcript),
  ]);
  return { summary, raw, finished, vulnerabilities, reportMarkdown, transcript, review };
}

// ---------------------------------------------------------------------------
// Local run history, report export, and live-agent steering.
// ---------------------------------------------------------------------------

export interface RunSeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface RunListEntry {
  name: string;
  target: string | null;
  scan_mode: string | null;
  status: string | null;
  start_time: string | null;
  end_time: string | null;
  finished: boolean;
  severity_counts: RunSeverityCounts;
}

export interface RunsPayload {
  locked: boolean;
  count: number;
  runs: RunListEntry[];
}

async function postJson(
  path: string,
  body: Record<string, unknown>
): Promise<{ ok: boolean; status: number; data: Record<string, unknown> }> {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    cache: "no-store",
  });
  let data: Record<string, unknown> = {};
  try {
    const parsed = await res.json();
    if (parsed && typeof parsed === "object") data = parsed as Record<string, unknown>;
  } catch {
    /* empty or non-JSON body */
  }
  return { ok: res.ok, status: res.status, data };
}

export async function fetchDashboardInfo(): Promise<DashboardInfo> {
  const obj = (await getJson("/api/dashboard")) as Record<string, unknown>;
  const rawLlm = obj?.llm as Partial<DashboardInfo["llm"]> | undefined;
  const mode = obj?.mode === "dashboard" ? "dashboard" : "viewer";
  return {
    mode,
    // Back-compat: an older server omits can_manage_scans — infer it from mode
    // (a legacy dashboard always managed scans).
    canManageScans:
      typeof obj?.can_manage_scans === "boolean" ? obj.can_manage_scans : mode === "dashboard",
    defaultRun: typeof obj?.default_run === "string" ? obj.default_run : null,
    llm: {
      configured: rawLlm?.configured === true,
      model: typeof rawLlm?.model === "string" ? rawLlm.model : null,
      endpoint: rawLlm?.endpoint === "local" ? "local" : "provider",
    },
    target_count: typeof obj?.target_count === "number" ? obj.target_count : 0,
  };
}

export async function fetchTargets(): Promise<RegisteredTarget[]> {
  const obj = (await getJson("/api/targets")) as { targets?: unknown };
  return Array.isArray(obj?.targets) ? (obj.targets as RegisteredTarget[]) : [];
}

export type CreateTargetResult =
  | { ok: true; target: RegisteredTarget }
  | { ok: false; message: string };

export async function createTarget(name: string, baseUrl: string): Promise<CreateTargetResult> {
  const { ok, data } = await postJson("/api/targets", { name, base_url: baseUrl });
  if (ok && data.target && typeof data.target === "object") {
    return { ok: true, target: data.target as RegisteredTarget };
  }
  return {
    ok: false,
    message: typeof data.message === "string" ? data.message : "Could not register this target.",
  };
}

export async function fetchScans(): Promise<ScansPayload> {
  const obj = (await getJson("/api/scans")) as Partial<ScansPayload>;
  const active = obj?.active && typeof obj.active === "object" ? (obj.active as ScanJob) : null;
  return {
    active,
    jobs: Array.isArray(obj?.jobs) ? (obj.jobs as ScanJob[]) : [],
  };
}

export type StartScanResult =
  | { ok: true; job: ScanJob }
  | { ok: false; message: string };

export async function startScan(
  targetId: string,
  scanMode: ScanMode,
): Promise<StartScanResult> {
  const { ok, data } = await postJson("/api/scans", {
    target_id: targetId,
    scan_mode: scanMode,
  });
  if (ok && data.job && typeof data.job === "object") {
    return { ok: true, job: data.job as ScanJob };
  }
  return {
    ok: false,
    message: typeof data.message === "string" ? data.message : "Could not start this scan.",
  };
}

/** POST /api/scans/stop. Requests a graceful stop for a dashboard scan. */
export async function stopScan(jobId: string): Promise<StartScanResult> {
  const { ok, data } = await postJson("/api/scans/stop", { job_id: jobId });
  if (ok && data.job && typeof data.job === "object") {
    return { ok: true, job: data.job as ScanJob };
  }
  return {
    ok: false,
    message: typeof data.message === "string" ? data.message : "Could not stop this scan.",
  };
}

export type StartReplayResult =
  | { ok: true; job: ReplayJob }
  | { ok: false; message: string; code?: string };

export async function startReplay(
  runName: string,
  findingId: string,
  confirmed = false,
): Promise<StartReplayResult> {
  const { ok, data } = await postJson("/api/replays", {
    run: runName,
    finding_id: findingId,
    confirmed,
  });
  if (ok && data.job && typeof data.job === "object") {
    return { ok: true, job: data.job as ReplayJob };
  }
  return {
    ok: false,
    code: typeof data.error === "string" ? data.error : undefined,
    message:
      typeof data.message === "string"
        ? data.message
        : "Could not start the finding replay.",
  };
}

export async function fetchReplay(
  replayId: string,
  runName: string,
): Promise<ReplayJob> {
  return (await getJson(
    `/api/replays/${encodeURIComponent(replayId)}?run=${encodeURIComponent(runName)}`,
  )) as ReplayJob;
}

export async function startPlaybookReplay(
  playbookId: string,
  confirmed = false,
): Promise<StartReplayResult> {
  const { ok, data } = await postJson(
    `/api/playbooks/${encodeURIComponent(playbookId)}/replay`,
    { confirmed },
  );
  if (ok && data.job && typeof data.job === "object") {
    return { ok: true, job: data.job as ReplayJob };
  }
  return {
    ok: false,
    code: typeof data.error === "string" ? data.error : undefined,
    message:
      typeof data.message === "string"
        ? data.message
        : "Could not start the Playbook replay.",
  };
}

export async function fetchPlaybookReplay(replayId: string): Promise<ReplayJob> {
  return (await getJson(
    `/api/playbook-replays/${encodeURIComponent(replayId)}`,
  )) as ReplayJob;
}

export interface AuthStatus {
  verified: boolean;
  email: string | null;
}

export async function fetchAuthStatus(): Promise<AuthStatus> {
  const obj = (await getJson("/api/auth/status")) as Partial<AuthStatus>;
  return {
    verified: obj?.verified === true,
    email: typeof obj?.email === "string" ? obj.email : null,
  };
}

export type AuthActionResult = { ok: true } | { ok: false; error: string };

export async function otpStart(email: string): Promise<AuthActionResult> {
  const { ok, data } = await postJson("/api/auth/otp/start", { email });
  if (ok) return { ok: true };
  return { ok: false, error: String(data.error ?? "unavailable") };
}

export async function otpVerify(
  email: string,
  code: string
): Promise<{ verified: boolean; email: string }> {
  const { ok, data } = await postJson("/api/auth/otp/verify", { email, code });
  return {
    verified: ok && data.verified === true,
    email: typeof data.email === "string" ? data.email : email,
  };
}

export type SendReportResult =
  | { ok: true; password: string; filename: string }
  | { ok: false; error: string };

export async function sendReport(runName: string | null): Promise<SendReportResult> {
  const { ok, data } = await postJson("/api/report/send", { run: runName });
  if (ok && typeof data.password === "string" && typeof data.filename === "string") {
    return { ok: true, password: data.password, filename: data.filename };
  }
  return { ok: false, error: String(data.error ?? "unavailable") };
}

export async function fetchRuns(): Promise<RunsPayload> {
  const obj = (await getJson("/api/runs")) as Partial<RunsPayload>;
  return {
    locked: obj?.locked ?? true,
    count: typeof obj?.count === "number" ? obj.count : 0,
    runs: Array.isArray(obj?.runs) ? (obj.runs as RunListEntry[]) : [],
  };
}

export interface DeleteRunResult {
  ok: boolean;
  status?: number;
  /** Machine-readable error code, e.g. "run_running" | "run_has_playbooks" | "unknown_run". */
  error?: string;
  message?: string;
  playbookCount?: number;
  playbooks?: Array<{ id: string; name: string }>;
}

/**
 * DELETE /api/runs/{name}. Deletes a finished run's artifacts. When the run is the
 * source of saved Playbooks, the first call returns `run_has_playbooks` (an
 * informational warning — the Playbooks are never deleted); pass {confirm:true} to
 * proceed. A still-running scan returns `run_running`.
 */
export async function deleteRun(
  name: string,
  opts: { confirm?: boolean } = {},
): Promise<DeleteRunResult> {
  const url = `/api/runs/${encodeURIComponent(name)}${opts.confirm ? "?confirm=true" : ""}`;
  const res = await fetch(url, { method: "DELETE", cache: "no-store" });
  let data: Record<string, unknown> = {};
  try {
    const body = await res.json();
    if (body && typeof body === "object") data = body as Record<string, unknown>;
  } catch {
    /* empty response body */
  }
  if (res.ok) return { ok: true };
  return {
    ok: false,
    status: res.status,
    error: typeof data.error === "string" ? data.error : undefined,
    message: typeof data.message === "string" ? data.message : "Could not delete this run.",
    playbookCount: typeof data.playbook_count === "number" ? data.playbook_count : undefined,
    playbooks: Array.isArray(data.playbooks)
      ? (data.playbooks as Array<{ id: string; name: string }>)
      : undefined,
  };
}

export interface Capabilities {
  can_steer: boolean;
  can_stop: boolean;
}

export type SteerResult = { ok: true } | { ok: false; error: string };

/** GET /api/capabilities. */
export async function fetchCapabilities(): Promise<Capabilities> {
  const obj = (await getJson("/api/capabilities")) as Partial<Capabilities>;
  return { can_steer: obj?.can_steer === true, can_stop: obj?.can_stop === true };
}

/** POST /api/agents/steer. Sends a steering instruction to a running agent. */
export async function steerAgent(agentId: string, message: string): Promise<SteerResult> {
  const { ok, data } = await postJson("/api/agents/steer", {
    agent_id: agentId,
    message,
  });
  if (ok && data.ok === true) return { ok: true };
  return { ok: false, error: String(data.error ?? "unavailable") };
}

export function reportPdfUrl(runName?: string | null): string {
  return "/api/report/pdf" + runQuery(runName);
}
