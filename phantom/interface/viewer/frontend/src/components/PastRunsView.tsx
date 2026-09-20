import { useState } from "react";
import { History, ChevronRight, Terminal, Trash2 } from "lucide-react";
import type { RunListEntry, RunsPayload, RunSeverityCounts } from "@/data/serverSource";
import { deleteRun } from "@/data/serverSource";
import { runTitle } from "@/lib/target-utils";
import ConfirmDeleteRunModal, {
  type DeleteRunPlaybookWarning,
} from "@/components/ConfirmDeleteRunModal";

/**
 * "Past runs" panel. The local viewer can browse every run available on this
 * machine and switch the active run, which threads ?run=<name> through the
 * data fetches.
 */

const SEV = [
  { key: "critical", dot: "bg-red-500", text: "text-red-500" },
  { key: "high", dot: "bg-orange-500", text: "text-orange-500" },
  { key: "medium", dot: "bg-yellow-500", text: "text-yellow-500" },
  { key: "low", dot: "bg-blue-500", text: "text-blue-500" },
] as const;

function SeverityChips({ counts }: { counts: RunSeverityCounts }) {
  const shown = SEV.filter((s) => counts[s.key] > 0);
  if (shown.length === 0) {
    return <span className="text-xs text-[var(--neutral-555)]">No findings</span>;
  }
  return (
    <div className="flex items-center gap-3">
      {shown.map((s) => (
        <div key={s.key} className="flex items-center gap-1.5">
          <span className={`h-2 w-2 rounded-full ${s.dot}`} aria-hidden="true" />
          <span className={`text-xs tabular-nums ${s.text}`}>{counts[s.key]}</span>
        </div>
      ))}
    </div>
  );
}

function formatDate(iso: string | null): string | null {
  if (!iso) return null;
  const normalized = iso.trim().replace(" UTC", "Z").replace(" ", "T");
  const d = new Date(normalized);
  if (Number.isNaN(d.getTime())) return null;
  return d.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

/**
 * Relative time ("just now" / "5m ago" / "3h ago" / "2d ago"), falling back to
 * the absolute date for anything older than a week (mirrors the pro app).
 */
function formatTimeAgo(iso: string | null): string | null {
  if (!iso) return null;
  const normalized = iso.trim().replace(" UTC", "Z").replace(" ", "T");
  const d = new Date(normalized);
  if (Number.isNaN(d.getTime())) return null;
  const diffMs = Date.now() - d.getTime();
  const mins = Math.floor(diffMs / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days}d ago`;
  return formatDate(iso);
}

interface PastRunsViewProps {
  runs: RunsPayload | null;
  activeRun: string | null;
  onSelectRun: (name: string) => void;
  /** Called after a run's artifacts are deleted, so the parent can refresh + clear. */
  onDeleted?: (name: string) => void;
}

export default function PastRunsView({
  runs,
  activeRun,
  onSelectRun,
  onDeleted,
}: PastRunsViewProps) {
  const [pendingDelete, setPendingDelete] = useState<RunListEntry | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [playbookWarning, setPlaybookWarning] = useState<DeleteRunPlaybookWarning | null>(null);

  function closeDelete() {
    if (deleting) return;
    setPendingDelete(null);
    setDeleteError(null);
    setPlaybookWarning(null);
  }

  async function confirmDelete() {
    if (!pendingDelete) return;
    setDeleting(true);
    setDeleteError(null);
    // First press deletes; if the run has saved Playbooks the server asks for an
    // explicit confirm (a warning, not a blocker) which the second press supplies.
    const res = await deleteRun(pendingDelete.name, { confirm: playbookWarning != null });
    setDeleting(false);
    if (res.ok) {
      const name = pendingDelete.name;
      setPendingDelete(null);
      setPlaybookWarning(null);
      onDeleted?.(name);
      return;
    }
    if (res.error === "run_has_playbooks") {
      setPlaybookWarning({
        count: res.playbookCount ?? 0,
        names: (res.playbooks ?? []).map((pb) => pb.name),
      });
      return;
    }
    setDeleteError(res.message ?? "Could not delete this run.");
  }

  if (!runs) {
    return (
      <div className="rounded-xl border border-[var(--neutral-222)] bg-[rgb(var(--contrast-rgb)/0.02)] p-8 text-center">
        <div
          className="mx-auto mb-4 flex h-11 w-11 items-center justify-center rounded-xl"
          style={{ border: "1px solid var(--neutral-2a2a2a)", background: "rgb(var(--contrast-rgb)/0.04)" }}
        >
          <History className="h-5 w-5 text-[var(--neutral-888)]" aria-hidden="true" />
        </div>
        <h2 className="text-base font-semibold text-foreground">Browse every run on this machine</h2>
        <p className="mx-auto mt-1.5 max-w-md text-sm text-[var(--neutral-888)]">
          Loading local run history…
        </p>
        <p className="mt-4 flex items-center justify-center gap-1.5 text-xs text-[var(--neutral-555)]">
          <Terminal className="h-3.5 w-3.5" aria-hidden="true" />
          Or open one from the CLI with{" "}
          <code className="font-mono text-[var(--neutral-888)]">phantom view &lt;name&gt;</code>
        </p>
      </div>
    );
  }

  if (runs.runs.length === 0) {
    return (
      <div className="rounded-xl border border-[var(--neutral-222)] bg-[rgb(var(--contrast-rgb)/0.02)] p-8 text-center text-sm text-[var(--neutral-888)]">
        No past runs found on this machine yet.
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {runs.runs.map((run: RunListEntry) => {
        const active = run.name === activeRun;
        const date = formatTimeAgo(run.start_time) ?? formatTimeAgo(run.end_time);
        const title = runTitle(run.target, run.name);
        return (
          <div
            key={run.name}
            className={`animate-card-in group flex w-full items-center gap-3 rounded-lg border px-4 py-3 transition-colors ${
              active
                ? "border-[var(--neutral-444)] bg-[rgb(var(--contrast-rgb)/0.04)]"
                : "border-[var(--neutral-222)] bg-[rgb(var(--contrast-rgb)/0.02)] hover:border-[var(--neutral-444)]"
            }`}
          >
            <button
              onClick={() => onSelectRun(run.name)}
              className="flex min-w-0 flex-1 cursor-pointer items-center gap-4 text-left"
            >
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="truncate text-sm font-medium text-foreground">{title}</span>
                  {active && (
                    <span className="rounded-full px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-blue-400" style={{ border: "1px solid rgba(59,130,246,0.3)" }}>
                      Active
                    </span>
                  )}
                </div>
                <div className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-xs text-[var(--neutral-666)]">
                  {run.scan_mode && <span className="capitalize">{run.scan_mode}</span>}
                  {run.scan_mode && (date || run.status) && <span className="text-[var(--neutral-333)]">·</span>}
                  {date && <span>{date}</span>}
                  {date && run.status && <span className="text-[var(--neutral-333)]">·</span>}
                  {run.status && <span className="capitalize">{run.status}</span>}
                </div>
              </div>
              <SeverityChips counts={run.severity_counts} />
              <ChevronRight className="h-4 w-4 flex-shrink-0 text-[var(--neutral-555)] transition-colors group-hover:text-[var(--neutral-aaa)]" aria-hidden="true" />
            </button>
            {run.finished && (
              <button
                type="button"
                onClick={(event) => {
                  event.stopPropagation();
                  setDeleteError(null);
                  setPlaybookWarning(null);
                  setPendingDelete(run);
                }}
                aria-label={`Delete run ${title}`}
                title="Delete run"
                className="flex-shrink-0 rounded-lg p-1.5 text-[var(--neutral-666)] transition-colors hover:bg-red-500/10 hover:text-red-400"
              >
                <Trash2 className="h-4 w-4" aria-hidden="true" />
              </button>
            )}
          </div>
        );
      })}
      <ConfirmDeleteRunModal
        runTitle={pendingDelete ? runTitle(pendingDelete.target, pendingDelete.name) : null}
        busy={deleting}
        error={deleteError}
        playbookWarning={playbookWarning}
        onCancel={closeDelete}
        onConfirm={confirmDelete}
      />
    </div>
  );
}
