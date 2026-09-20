import { Fragment, useEffect, useMemo, useState, type ElementType, type ReactNode } from "react";
import {
  ArrowLeft,
  Ban,
  BookMarked,
  CalendarDays,
  ChevronRight,
  Globe2,
  RotateCcw,
  Trash2,
  UserRound,
} from "lucide-react";
import type { Vulnerability } from "@/types/issues";
import VulnerabilityDetail from "@/components/vulnerability/VulnerabilityDetail";
import ConfirmRemovePlaybookModal from "@/components/ConfirmRemovePlaybookModal";
import {
  loadPlaybooks,
  listPlaybooks,
  PLAYBOOKS_CHANGED_EVENT,
  removePlaybook,
  updatePlaybookRemediation,
  type PlaybookEntry,
} from "@/lib/playbook-store";
import {
  loadRejections,
  listRejections,
  REJECTIONS_CHANGED_EVENT,
  removeRejection,
  type RejectionEntry,
} from "@/lib/rejection-store";
import { runTitle } from "@/lib/target-utils";
import { getSeverityDot } from "@/lib/vulnerability-utils";

type Mode = "playbooks" | "rejections";

function targetLabelFor(targetName: string, finding: Vulnerability, runName: string | null): string {
  return targetName || runTitle(finding.target, runName ?? "Saved target");
}

function formatDate(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "date unavailable";
  return date.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

function relativeTime(value: string): string {
  const timestamp = new Date(value).getTime();
  if (!Number.isFinite(timestamp)) return "date unavailable";
  const seconds = Math.max(0, Math.floor((Date.now() - timestamp) / 1000));
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  if (seconds < 604800) return `${Math.floor(seconds / 86400)}d ago`;
  if (seconds < 2592000) return `${Math.floor(seconds / 604800)}w ago`;
  return `${Math.floor(seconds / 2592000)}mo ago`;
}

function replayStatusMeta(status: string | null | undefined): { label: string; color: string } {
  switch ((status ?? "").toLowerCase().replace(/-/g, "_")) {
    case "confirmed":
    case "reproduced":
    case "success":
      return { label: "reproduced", color: "text-emerald-300" };
    case "not_reproduced":
    case "inconclusive":
      return { label: "not reproduced", color: "text-amber-300" };
    case "failed":
    case "error":
    case "blocked":
      return { label: "failed", color: "text-red-300" };
    default:
      return { label: "recorded", color: "text-[var(--neutral-8a8a8a)]" };
  }
}

function latestReplayAt(entry: Pick<PlaybookEntry, "lastReplayAt" | "confirmedByReplayId" | "updatedAt" | "addedAt">): string | null {
  return entry.lastReplayAt ?? (entry.confirmedByReplayId ? entry.updatedAt ?? entry.addedAt : null);
}

function latestReplayStatus(entry: Pick<PlaybookEntry, "lastReplayStatus" | "confirmedByReplayId">): string | null {
  return entry.lastReplayStatus ?? (entry.confirmedByReplayId ? "confirmed" : null);
}

/** A small pill. Chips are fine — the boxy feel came from nested bordered panels, not these. */
function Chip({ tone, children }: { tone: "emerald" | "amber" | "neutral" | "red"; children: ReactNode }) {
  const tones = {
    emerald: "border-emerald-400/20 bg-emerald-400/[0.08] text-emerald-300",
    amber: "border-amber-400/20 bg-amber-400/[0.08] text-amber-300",
    red: "border-red-400/20 bg-red-400/[0.08] text-red-300",
    neutral: "border-[var(--neutral-333)] bg-foreground/[0.04] text-[var(--neutral-9a9a9a)]",
  } as const;
  return (
    <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${tones[tone]}`}>
      {children}
    </span>
  );
}

/** Remediation lifecycle -> badge tone + label. Open (still an issue), Fixed, Reopened (regression). */
function remediationMeta(status: PlaybookEntry["remediationStatus"]): {
  tone: "neutral" | "emerald" | "red";
  label: string;
} {
  switch (status) {
    case "fixed":
      return { tone: "emerald", label: "Fixed" };
    case "reopened":
      return { tone: "red", label: "Reopened" };
    default:
      return { tone: "neutral", label: "Open" };
  }
}

type MetaItem = { icon?: ElementType; text: string; className?: string };

/** One muted line of `icon text · icon text · …` — replaces the old nested metadata boxes. */
function MetaRow({ items, className = "" }: { items: MetaItem[]; className?: string }) {
  const shown = items.filter((item) => item.text);
  if (shown.length === 0) return null;
  return (
    <div className={`flex flex-wrap items-center gap-x-2.5 gap-y-1 text-[11px] text-[var(--neutral-6f6f6f)] ${className}`}>
      {shown.map((item, index) => {
        const Icon = item.icon;
        return (
          <Fragment key={index}>
            {index > 0 && <span className="text-[var(--neutral-333)]" aria-hidden="true">·</span>}
            <span className={`inline-flex min-w-0 items-center gap-1 ${item.className ?? ""}`}>
              {Icon ? <Icon className="h-3 w-3 flex-shrink-0 text-[var(--neutral-555)]" aria-hidden="true" /> : null}
              <span className="truncate">{item.text}</span>
            </span>
          </Fragment>
        );
      })}
    </div>
  );
}

function SeverityDot({ severity }: { severity: string }) {
  // Match the AI-findings severity dots exactly (getSeverityDot: red/orange/yellow/blue-500).
  return (
    <span
      className={`mt-1.5 block h-2.5 w-2.5 flex-shrink-0 rounded-full ${getSeverityDot(severity)}`}
      aria-hidden="true"
    />
  );
}

function ViewSwitch({
  mode,
  onChange,
  playbookCount,
  rejectionCount,
}: {
  mode: Mode;
  onChange: (mode: Mode) => void;
  playbookCount: number;
  rejectionCount: number;
}) {
  const tab = (active: boolean) =>
    `inline-flex items-center gap-2 rounded-lg px-3.5 py-2 text-sm font-semibold transition-colors ${
      active ? "bg-foreground text-inverse" : "text-[var(--neutral-888)] hover:text-foreground"
    }`;
  const badge = (active: boolean) =>
    `rounded-full px-1.5 py-0.5 text-[10px] font-semibold ${active ? "bg-black/10 text-inverse/70" : "bg-foreground/[0.06] text-[var(--neutral-888)]"}`;
  return (
    <div className="inline-flex flex-shrink-0 items-center gap-1 rounded-xl border border-[var(--neutral-242424)] bg-[rgb(var(--contrast-rgb)/0.02)] p-1">
      <button type="button" onClick={() => onChange("playbooks")} className={tab(mode === "playbooks")}>
        <BookMarked className="h-4 w-4" aria-hidden="true" /> Playbooks
        <span className={badge(mode === "playbooks")}>{playbookCount}</span>
      </button>
      <button type="button" onClick={() => onChange("rejections")} className={tab(mode === "rejections")}>
        <Ban className="h-4 w-4" aria-hidden="true" /> Rejected
        <span className={badge(mode === "rejections")}>{rejectionCount}</span>
      </button>
    </div>
  );
}

function EmptyState({ icon: Icon, tone, title, hint }: { icon: ElementType; tone: "blue" | "amber"; title: string; hint: string }) {
  const ring = tone === "blue" ? "border-blue-400/25 bg-blue-500/10 text-blue-300" : "border-amber-400/25 bg-amber-500/10 text-amber-300";
  return (
    <div className="flex min-h-[320px] flex-col items-center justify-center rounded-xl border border-dashed border-[var(--neutral-262626)] px-6 text-center">
      <div className={`flex h-11 w-11 items-center justify-center rounded-xl border ${ring}`}>
        <Icon className="h-5 w-5" aria-hidden="true" />
      </div>
      <h2 className="mt-4 text-base font-semibold text-foreground">{title}</h2>
      <p className="mt-1.5 max-w-md text-sm leading-6 text-[var(--neutral-777)]">{hint}</p>
    </div>
  );
}

/** One row in the divided list — a single hairline-separated line, no per-item box. */
function ListRow({
  severity,
  title,
  subtitle,
  chip,
  meta,
  hoverBorder,
  onClick,
}: {
  severity: string;
  title: string;
  subtitle: string;
  chip: ReactNode;
  meta: MetaItem[];
  hoverBorder: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`group flex w-full items-start gap-4 px-5 py-5 text-left transition-colors hover:bg-foreground/[0.035] ${hoverBorder}`}
    >
      <SeverityDot severity={severity} />
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="truncate text-sm font-semibold text-foreground">{title}</span>
          {chip}
        </div>
        <p className="mt-1 truncate text-[13px] text-[var(--neutral-8a8a8a)]">{subtitle}</p>
        <MetaRow items={meta} className="mt-3" />
      </div>
      <ChevronRight className="mt-1 h-4 w-4 flex-shrink-0 text-[var(--neutral-4d4d4d)] transition-transform group-hover:translate-x-0.5 group-hover:text-[var(--neutral-8a8a8a)]" aria-hidden="true" />
    </button>
  );
}

export default function PlaybookView() {
  const [mode, setMode] = useState<Mode>("playbooks");
  const [entries, setEntries] = useState<PlaybookEntry[]>(listPlaybooks);
  const [rejections, setRejections] = useState<RejectionEntry[]>(listRejections);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selectedRejectionId, setSelectedRejectionId] = useState<string | null>(null);
  const [removeRequested, setRemoveRequested] = useState<PlaybookEntry | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [remOwner, setRemOwner] = useState("");
  const [remDueDate, setRemDueDate] = useState("");
  const [savingRem, setSavingRem] = useState(false);

  useEffect(() => {
    void loadPlaybooks().then(setEntries).catch(() => setError("Could not load the server Playbook."));
    void loadRejections().then(setRejections).catch(() => setError("Could not load the rejected findings."));
    const refresh = () => setEntries(listPlaybooks());
    const refreshRejections = () => setRejections(listRejections());
    window.addEventListener(PLAYBOOKS_CHANGED_EVENT, refresh);
    window.addEventListener(REJECTIONS_CHANGED_EVENT, refreshRejections);
    return () => {
      window.removeEventListener(PLAYBOOKS_CHANGED_EVENT, refresh);
      window.removeEventListener(REJECTIONS_CHANGED_EVENT, refreshRejections);
    };
  }, []);

  const selected = useMemo(() => entries.find((entry) => entry.id === selectedId) ?? null, [entries, selectedId]);
  const selectedRejection = useMemo(
    () => rejections.find((entry) => entry.id === selectedRejectionId) ?? null,
    [rejections, selectedRejectionId],
  );

  // Keep the remediation editor synced with the open playbook.
  useEffect(() => {
    setRemOwner(selected?.owner ?? "");
    setRemDueDate(selected?.dueDate ?? "");
  }, [selected?.id, selected?.owner, selected?.dueDate]);

  // While a playbook is open, poll so a retest's remediation change
  // (open -> fixed -> reopened) shows up without leaving the page.
  useEffect(() => {
    if (!selectedId) return;
    const timer = window.setInterval(() => {
      void loadPlaybooks().then(setEntries).catch(() => undefined);
    }, 4000);
    return () => window.clearInterval(timer);
  }, [selectedId]);

  const backLink = (label: string, onClick: () => void) => (
    <button type="button" onClick={onClick} className="inline-flex items-center gap-1.5 text-sm text-[var(--neutral-888)] transition-colors hover:text-foreground">
      <ArrowLeft className="h-4 w-4" aria-hidden="true" /> {label}
    </button>
  );

  if (selected) {
    const replay = replayStatusMeta(latestReplayStatus(selected));
    const replayAt = latestReplayAt(selected) ?? selected.addedAt;
    const remediation = remediationMeta(selected.remediationStatus ?? "open");
    const playbookId = selected.id;
    const saveRemediation = () => {
      if (savingRem) return;
      setSavingRem(true);
      void updatePlaybookRemediation(playbookId, remOwner.trim() || null, remDueDate.trim() || null)
        .catch((cause: unknown) =>
          setError(cause instanceof Error ? cause.message : "Could not update remediation."),
        )
        .finally(() => setSavingRem(false));
    };
    return (
      <div className="space-y-6">
        {backLink("Back to Playbooks", () => setSelectedId(null))}
        <div className="border-b border-[var(--neutral-1e1e1e)] pb-5">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="min-w-0">
              <div className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.16em] text-blue-300">
                <BookMarked className="h-3.5 w-3.5" aria-hidden="true" /> Saved playbook
                <Chip tone={remediation.tone}>{remediation.label}</Chip>
              </div>
              <h1 className="mt-2 text-2xl font-semibold text-foreground">{selected.name}</h1>
              <MetaRow
                className="mt-3"
                items={[
                  { icon: Globe2, text: targetLabelFor(selected.targetName, selected.finding, selected.runName), className: "text-foreground" },
                  { icon: UserRound, text: selected.auditorName, className: "text-foreground" },
                  { icon: CalendarDays, text: `added ${formatDate(selected.addedAt)}`, className: "text-foreground" },
                  { text: `replay ${replay.label} ${relativeTime(replayAt)}`, className: replay.color },
                ]}
              />
            </div>
            <button
              type="button"
              onClick={() => setRemoveRequested(selected)}
              className="inline-flex flex-shrink-0 items-center gap-2 rounded-lg border border-red-400/20 px-3 py-2 text-sm text-red-300 transition-colors hover:border-red-400/40 hover:bg-red-400/[0.06]"
            >
              <Trash2 className="h-4 w-4" aria-hidden="true" /> Remove
            </button>
          </div>

          {/* Remediation: owner + deadline are analyst-set; the status advances
              automatically (open -> fixed -> reopened) as the finding is retested. */}
          <div className="mt-4 rounded-lg border border-[var(--neutral-252525)] bg-black/20 px-4 py-3">
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
              <span className="text-[10px] font-semibold uppercase tracking-[0.16em] text-[var(--neutral-777)]">Remediation</span>
              <Chip tone={remediation.tone}>{remediation.label}</Chip>
              {selected.remediationStatus === "fixed" && selected.fixedAt && (
                <span className="text-[11px] text-emerald-300/80">fixed {relativeTime(selected.fixedAt)}</span>
              )}
              {selected.remediationStatus === "reopened" && selected.reopenedAt && (
                <span className="text-[11px] text-red-300/80">reopened {relativeTime(selected.reopenedAt)}</span>
              )}
              <span className="text-[11px] text-[var(--neutral-666)]">· retest below to update automatically</span>
            </div>
            <div className="mt-3 flex flex-wrap items-end gap-3">
              <label className="block">
                <span className="text-[10px] font-semibold uppercase tracking-[0.14em] text-[var(--neutral-777)]">Owner</span>
                <input
                  value={remOwner}
                  onChange={(event) => setRemOwner(event.target.value)}
                  placeholder="Unassigned"
                  className="mt-1 h-9 w-44 rounded-lg border border-[var(--neutral-333)] bg-canvas px-3 text-sm text-foreground outline-none transition-colors placeholder:text-[var(--neutral-555)] focus:border-blue-400/70"
                />
              </label>
              <label className="block">
                <span className="text-[10px] font-semibold uppercase tracking-[0.14em] text-[var(--neutral-777)]">Due date</span>
                <input
                  type="date"
                  value={remDueDate}
                  onChange={(event) => setRemDueDate(event.target.value)}
                  className="mt-1 h-9 rounded-lg border border-[var(--neutral-333)] bg-canvas px-3 text-sm text-foreground outline-none transition-colors focus:border-blue-400/70"
                />
              </label>
              <button
                type="button"
                onClick={saveRemediation}
                disabled={savingRem}
                className="h-9 rounded-lg border border-[var(--neutral-3a3a3a)] px-3.5 text-sm font-medium text-[var(--neutral-ddd)] transition-colors hover:border-[var(--neutral-555)] hover:text-foreground disabled:cursor-wait disabled:opacity-60"
              >
                {savingRem ? "Saving…" : "Save"}
              </button>
            </div>
          </div>
        </div>
        <VulnerabilityDetail
          vulnerability={selected.finding}
          runName={selected.runName}
          playbookId={selected.id}
          replayEnabled={!!selected.finding.replay_spec}
          playbookEnabled={false}
        />
        <ConfirmRemovePlaybookModal
          entry={removeRequested}
          onCancel={() => setRemoveRequested(null)}
          onConfirm={() => {
            if (!removeRequested) return;
            const id = removeRequested.id;
            void removePlaybook(id)
              .then(() => {
                setRemoveRequested(null);
                setSelectedId(null);
              })
              .catch((cause: unknown) => {
                setError(cause instanceof Error ? cause.message : "Could not remove this Playbook.");
              });
          }}
        />
      </div>
    );
  }

  if (selectedRejection) {
    const restore = () => {
      const id = selectedRejection.id;
      void removeRejection(id)
        .then(() => setSelectedRejectionId(null))
        .catch((cause: unknown) => {
          setError(cause instanceof Error ? cause.message : "Could not restore this finding.");
        });
    };
    return (
      <div className="space-y-6">
        {backLink("Back to Rejected", () => setSelectedRejectionId(null))}
        <div className="border-b border-[var(--neutral-1e1e1e)] pb-5">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="min-w-0">
              <div className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.16em] text-amber-300">
                <Ban className="h-3.5 w-3.5" aria-hidden="true" /> Rejected false positive
              </div>
              <h1 className="mt-2 text-2xl font-semibold text-foreground">{selectedRejection.findingTitle || selectedRejection.finding.title}</h1>
              <MetaRow
                className="mt-3"
                items={[
                  { icon: Globe2, text: targetLabelFor(selectedRejection.targetName, selectedRejection.finding, selectedRejection.runName), className: "text-foreground" },
                  { icon: UserRound, text: selectedRejection.auditorName, className: "text-foreground" },
                  { icon: CalendarDays, text: `rejected ${relativeTime(selectedRejection.rejectedAt)}` },
                ]}
              />
            </div>
            <button
              type="button"
              onClick={restore}
              className="inline-flex flex-shrink-0 items-center gap-2 rounded-lg border border-[var(--neutral-3a3a3a)] px-3 py-2 text-sm text-[var(--neutral-ddd)] transition-colors hover:border-[var(--neutral-555)] hover:text-foreground"
            >
              <RotateCcw className="h-4 w-4" aria-hidden="true" /> Restore
            </button>
          </div>
          <div className="mt-4 border-l-2 border-amber-400/40 bg-amber-400/[0.04] px-4 py-3">
            <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-amber-300/80">Reason for rejection</p>
            <p className="mt-1.5 whitespace-pre-wrap text-sm leading-6 text-[var(--neutral-dcdcdc)]">{selectedRejection.reason}</p>
          </div>
        </div>
        <VulnerabilityDetail
          vulnerability={selectedRejection.finding}
          runName={selectedRejection.runName}
          replayEnabled={!!selectedRejection.finding.replay_spec}
          playbookEnabled={false}
        />
      </div>
    );
  }

  const isPlaybooks = mode === "playbooks";
  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          {isPlaybooks ? (
            <>
              <div className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.18em] text-blue-300">
                <BookMarked className="h-4 w-4" aria-hidden="true" /> Playbook library
              </div>
              <h1 className="mt-2 text-2xl font-semibold tracking-tight text-foreground">Saved attacks</h1>
              <p className="mt-1.5 max-w-2xl text-sm leading-6 text-[var(--neutral-888)]">Replay-confirmed attacks, ready for fast retesting.</p>
            </>
          ) : (
            <>
              <div className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.18em] text-amber-300">
                <Ban className="h-4 w-4" aria-hidden="true" /> False positives
              </div>
              <h1 className="mt-2 text-2xl font-semibold tracking-tight text-foreground">Rejected findings</h1>
              <p className="mt-1.5 max-w-2xl text-sm leading-6 text-[var(--neutral-888)]">Findings an auditor judged not real. Restore one to return it to triage.</p>
            </>
          )}
        </div>
        <ViewSwitch mode={mode} onChange={setMode} playbookCount={entries.length} rejectionCount={rejections.length} />
      </div>

      {error && <p className="rounded-lg border border-red-400/20 bg-red-400/[0.05] px-4 py-3 text-sm text-red-300">{error}</p>}

      {isPlaybooks ? (
        entries.length === 0 ? (
          <EmptyState
            icon={BookMarked}
            tone="blue"
            title="Your playbook is empty"
            hint="Open a finding, replay it to confirm, and choose “Sign” to save the attack for later retesting."
          />
        ) : (
          <div className="overflow-hidden rounded-xl border border-[var(--neutral-222)] bg-[rgb(var(--contrast-rgb)/0.02)] divide-y divide-[var(--neutral-1c1c1c)]">
            {entries.map((entry) => {
              const replay = replayStatusMeta(latestReplayStatus(entry));
              const replayAt = latestReplayAt(entry) ?? entry.addedAt;
              const remediation = remediationMeta(entry.remediationStatus ?? "open");
              return (
                <ListRow
                  key={entry.id}
                  severity={entry.finding.severity}
                  title={entry.name}
                  subtitle={entry.finding.title}
                  chip={<Chip tone={remediation.tone}>{remediation.label}</Chip>}
                  hoverBorder=""
                  meta={[
                    { icon: Globe2, text: targetLabelFor(entry.targetName, entry.finding, entry.runName), className: "text-foreground" },
                    { icon: UserRound, text: entry.auditorName, className: "text-foreground" },
                    { icon: CalendarDays, text: `added ${formatDate(entry.addedAt)}`, className: "text-foreground" },
                    { text: `replay ${replay.label} ${relativeTime(replayAt)}`, className: replay.color },
                  ]}
                  onClick={() => setSelectedId(entry.id)}
                />
              );
            })}
          </div>
        )
      ) : rejections.length === 0 ? (
        <EmptyState
          icon={Ban}
          tone="amber"
          title="No rejected findings"
          hint="When a candidate is a false positive, open it and choose “Reject” to record why. Rejected findings collect here."
        />
      ) : (
        <div className="overflow-hidden rounded-xl border border-[var(--neutral-222)] bg-[rgb(var(--contrast-rgb)/0.02)] divide-y divide-[var(--neutral-1c1c1c)]">
          {rejections.map((entry) => (
            <ListRow
              key={entry.id}
              severity={entry.finding.severity}
              title={entry.findingTitle || entry.finding.title}
              subtitle={`“${entry.reason}”`}
              chip={<Chip tone="amber">Rejected</Chip>}
              hoverBorder=""
              meta={[
                { icon: Globe2, text: targetLabelFor(entry.targetName, entry.finding, entry.runName), className: "text-foreground" },
                { icon: UserRound, text: entry.auditorName, className: "text-foreground" },
                { icon: CalendarDays, text: `rejected ${relativeTime(entry.rejectedAt)}` },
              ]}
              onClick={() => setSelectedRejectionId(entry.id)}
            />
          ))}
        </div>
      )}
    </div>
  );
}
