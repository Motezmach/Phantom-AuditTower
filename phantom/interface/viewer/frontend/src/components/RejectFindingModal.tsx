import { useEffect, useState } from "react";
import { Ban, Loader2, X } from "lucide-react";
import type { Vulnerability } from "@/types/issues";
import { getLastAuditorName } from "@/lib/playbook-store";
import { addRejection, type RejectionEntry } from "@/lib/rejection-store";

interface RejectFindingModalProps {
  open: boolean;
  vulnerability: Vulnerability;
  targetName: string;
  targetUrl: string | null;
  runName: string | null;
  onClose: () => void;
  onRejected?: (entry: RejectionEntry) => void;
}

export default function RejectFindingModal({
  open,
  vulnerability,
  targetName,
  targetUrl,
  runName,
  onClose,
  onRejected,
}: RejectFindingModalProps) {
  const [reason, setReason] = useState("");
  const [auditorName, setAuditorName] = useState(getLastAuditorName);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!open) return;
    setReason("");
    setAuditorName(getLastAuditorName());
    setError(null);
    setSaving(false);
  }, [open, vulnerability.id]);

  useEffect(() => {
    if (!open) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKeyDown);
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      document.body.style.overflow = previousOverflow;
    };
  }, [open, onClose]);

  if (!open) return null;

  const save = async () => {
    if (saving) return;
    if (!reason.trim()) {
      setError("Write down why this finding is a false positive before rejecting it.");
      return;
    }
    if (!auditorName.trim()) {
      setError("Enter the auditor name for this decision.");
      return;
    }
    setSaving(true);
    try {
      const result = await addRejection({
        reason,
        auditorName,
        runName,
        finding: vulnerability,
      });
      if (!result.created) {
        setError("This finding is already rejected.");
        return;
      }
      onRejected?.(result.entry);
      onClose();
    } catch (cause: unknown) {
      setError(cause instanceof Error ? cause.message : "Could not reject this finding.");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div
      className="dialog-overlay fixed inset-0 z-[110] flex items-center justify-center bg-black/80 p-4 backdrop-blur-sm"
      data-state="open"
      role="dialog"
      aria-modal="true"
      aria-labelledby="reject-dialog-title"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div className="dialog-panel w-full max-w-lg rounded-2xl border border-[var(--neutral-333)] bg-[var(--neutral-0b0b0b)] shadow-2xl" data-state="open">
        <div className="flex items-start justify-between gap-4 border-b border-[var(--neutral-252525)] px-6 py-5">
          <div className="flex min-w-0 items-start gap-3">
            <div className="mt-0.5 flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-xl border border-amber-400/25 bg-amber-500/10 text-amber-300">
              <Ban className="h-4 w-4" aria-hidden="true" />
            </div>
            <div className="min-w-0">
              <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-[var(--neutral-777)]">Triage decision</p>
              <h2 id="reject-dialog-title" className="mt-1 text-lg font-semibold text-foreground">Reject as false positive</h2>
              <p className="mt-1 text-sm leading-6 text-[var(--neutral-888)]">Records why this candidate is not real, so a rescan won&rsquo;t re-surface it cold.</p>
            </div>
          </div>
          <button type="button" onClick={onClose} aria-label="Close" className="rounded-lg p-2 text-[var(--neutral-777)] transition-colors hover:bg-foreground/[0.06] hover:text-foreground">
            <X className="h-5 w-5" aria-hidden="true" />
          </button>
        </div>

        <div className="space-y-5 px-6 py-5">
          <div className="rounded-xl border border-[var(--neutral-252525)] bg-black/50 p-4">
            <p className="truncate text-sm font-medium text-foreground">{vulnerability.title}</p>
            <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-xs text-[var(--neutral-777)]">
              <span>{targetName}</span>
              {targetUrl && <span className="truncate font-mono">{targetUrl}</span>}
            </div>
          </div>

          <label className="block">
            <span className="text-sm font-medium text-[var(--neutral-ddd)]">Reason</span>
            <textarea
              autoFocus
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              rows={4}
              className="mt-2 w-full resize-y rounded-lg border border-[var(--neutral-333)] bg-canvas px-3 py-2 text-sm text-foreground outline-none transition-colors placeholder:text-[var(--neutral-555)] focus:border-amber-400/70"
              placeholder="e.g. Reflection is HTML-encoded; not exploitable. Out of agreed scope. Duplicate of vuln-0003."
            />
          </label>

          <label className="block">
            <span className="text-sm font-medium text-[var(--neutral-ddd)]">Auditor</span>
            <input
              value={auditorName}
              onChange={(event) => setAuditorName(event.target.value)}
              className="mt-2 h-11 w-full rounded-lg border border-[var(--neutral-333)] bg-canvas px-3 text-sm text-foreground outline-none transition-colors placeholder:text-[var(--neutral-555)] focus:border-amber-400/70"
              placeholder="Your name"
            />
          </label>

          {error && <p className="text-sm text-red-400">{error}</p>}
        </div>

        <div className="flex items-center justify-end gap-3 border-t border-[var(--neutral-252525)] px-6 py-4">
          <button type="button" onClick={onClose} className="rounded-lg border border-[var(--neutral-333)] px-4 py-2 text-sm text-[var(--neutral-aaa)] transition-colors hover:border-[var(--neutral-555)] hover:text-foreground">Cancel</button>
          <button type="button" disabled={saving} onClick={() => void save()} className="inline-flex items-center gap-2 rounded-lg bg-amber-400 px-4 py-2 text-sm font-semibold text-black transition-all hover:bg-amber-300 disabled:cursor-wait disabled:opacity-60">
            {saving ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Ban className="h-4 w-4" aria-hidden="true" />}
            {saving ? "Rejecting…" : "Reject finding"}
          </button>
        </div>
      </div>
    </div>
  );
}
