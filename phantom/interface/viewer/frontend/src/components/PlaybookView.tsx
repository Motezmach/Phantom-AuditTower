import { useEffect, useMemo, useState } from "react";
import { ArrowLeft, BookMarked, CalendarDays, ChevronRight, Globe2, Trash2, UserRound } from "lucide-react";
import type { Vulnerability } from "@/types/issues";
import VulnerabilityDetail from "@/components/vulnerability/VulnerabilityDetail";
import ConfirmRemovePlaybookModal from "@/components/ConfirmRemovePlaybookModal";
import {
  loadPlaybooks,
  listPlaybooks,
  PLAYBOOKS_CHANGED_EVENT,
  removePlaybook,
  type PlaybookEntry,
} from "@/lib/playbook-store";
import { runTitle } from "@/lib/target-utils";
import { SEVERITY_COLORS } from "@/types/issues";
import { getSeverityDot } from "@/lib/vulnerability-utils";

function formatDate(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Date unavailable";
  return date.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

function targetLabel(entry: PlaybookEntry): string {
  return entry.targetName || runTitle(entry.finding.target, entry.runName ?? "Saved target");
}

function FindingSnapshot({ entry }: { entry: PlaybookEntry }) {
  const finding: Vulnerability = entry.finding;
  return (
    <div className="mt-5 flex flex-wrap items-center gap-2 text-xs text-[#777]">
      <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 ${SEVERITY_COLORS[finding.severity]}`}>
        <span className={`h-1.5 w-1.5 rounded-full ${getSeverityDot(finding.severity)}`} aria-hidden="true" />
        <span className="capitalize">{finding.severity}</span>
      </span>
      {finding.replay_spec && <span className="rounded-full border border-emerald-400/20 bg-emerald-400/[0.05] px-2.5 py-1 text-emerald-300">Replay ready</span>}
      <span>{finding.endpoint ?? "Finding evidence preserved"}</span>
    </div>
  );
}

export default function PlaybookView() {
  const [entries, setEntries] = useState<PlaybookEntry[]>(listPlaybooks);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [removeRequested, setRemoveRequested] = useState<PlaybookEntry | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void loadPlaybooks().then(setEntries).catch(() => setError("Could not load the server Playbook."));
    const refresh = () => setEntries(listPlaybooks());
    window.addEventListener(PLAYBOOKS_CHANGED_EVENT, refresh);
    return () => window.removeEventListener(PLAYBOOKS_CHANGED_EVENT, refresh);
  }, []);

  const selected = useMemo(() => entries.find((entry) => entry.id === selectedId) ?? null, [entries, selectedId]);

  if (selected) {
    return (
      <div className="space-y-5">
        <button type="button" onClick={() => setSelectedId(null)} className="inline-flex items-center gap-1.5 text-sm text-[#888] transition-colors hover:text-white">
          <ArrowLeft className="h-4 w-4" aria-hidden="true" /> Back to Playbook
        </button>
        <div className="rounded-2xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-5 sm:p-6">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="min-w-0">
              <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.16em] text-blue-300">
                <BookMarked className="h-3.5 w-3.5" aria-hidden="true" /> Saved playbook
              </div>
              <h1 className="mt-2 text-2xl font-semibold text-white">{selected.name}</h1>
              <FindingSnapshot entry={selected} />
            </div>
            <button
              type="button"
              onClick={() => setRemoveRequested(selected)}
              className="inline-flex items-center gap-2 rounded-lg border border-red-400/20 px-3 py-2 text-sm text-red-300 transition-colors hover:border-red-400/40 hover:bg-red-400/[0.06]"
            >
              <Trash2 className="h-4 w-4" aria-hidden="true" /> Remove
            </button>
          </div>
          <div className="mt-5 grid gap-3 border-t border-[#252525] pt-4 text-xs text-[#777] sm:grid-cols-3">
            <span className="inline-flex items-center gap-2"><Globe2 className="h-3.5 w-3.5 text-[#555]" />{targetLabel(selected)}</span>
            <span className="inline-flex items-center gap-2"><UserRound className="h-3.5 w-3.5 text-[#555]" />{selected.auditorName}</span>
            <span className="inline-flex items-center gap-2"><CalendarDays className="h-3.5 w-3.5 text-[#555]" />Added {formatDate(selected.addedAt)}</span>
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

  return (
    <div className="space-y-6">
      <div>
        <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.18em] text-blue-300">
          <BookMarked className="h-4 w-4" aria-hidden="true" /> Playbook
        </div>
        <h1 className="mt-2 text-3xl font-semibold tracking-tight text-white">Saved attacks</h1>
        <p className="mt-2 max-w-2xl text-sm leading-6 text-[#888]">Keep confirmed attacks ready for fast retesting. Each entry preserves the finding exactly as it was saved.</p>
      </div>

      {error && <p className="rounded-lg border border-red-400/20 bg-red-400/[0.05] px-4 py-3 text-sm text-red-300">{error}</p>}

      {entries.length === 0 ? (
        <div className="flex min-h-[360px] flex-col items-center justify-center rounded-2xl border border-[#222] bg-[rgba(255,255,255,0.02)] px-6 text-center">
          <div className="flex h-12 w-12 items-center justify-center rounded-2xl border border-blue-400/25 bg-blue-500/10 text-blue-300">
            <BookMarked className="h-5 w-5" aria-hidden="true" />
          </div>
          <h2 className="mt-5 text-lg font-semibold text-white">Your playbook is empty</h2>
          <p className="mt-2 max-w-md text-sm leading-6 text-[#777]">Open a finding, review its evidence, and choose “Add to Playbook” to save the attack for later retesting.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {entries.map((entry) => (
            <button key={entry.id} type="button" onClick={() => setSelectedId(entry.id)} className="group w-full rounded-2xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-5 text-left transition-all hover:-translate-y-0.5 hover:border-[#3d3d3d] hover:bg-[rgba(255,255,255,0.04)] hover:shadow-[0_14px_40px_rgba(0,0,0,0.24)]">
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="truncate text-base font-semibold text-white">{entry.name}</span>
                    <span className="rounded-full border border-blue-400/20 bg-blue-400/[0.06] px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-blue-300">Saved</span>
                  </div>
                  <p className="mt-1 truncate text-sm text-[#999]">{entry.finding.title}</p>
                </div>
                <ChevronRight className="mt-1 h-5 w-5 flex-shrink-0 text-[#555] transition-transform group-hover:translate-x-1 group-hover:text-[#aaa]" aria-hidden="true" />
              </div>
              <FindingSnapshot entry={entry} />
              <div className="mt-4 flex flex-wrap gap-x-4 gap-y-2 border-t border-[#252525] pt-3 text-xs text-[#666]">
                <span className="inline-flex items-center gap-1.5"><Globe2 className="h-3.5 w-3.5" />{targetLabel(entry)}</span>
                <span className="inline-flex items-center gap-1.5"><UserRound className="h-3.5 w-3.5" />{entry.auditorName}</span>
                <span className="inline-flex items-center gap-1.5"><CalendarDays className="h-3.5 w-3.5" />{formatDate(entry.addedAt)}</span>
              </div>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
