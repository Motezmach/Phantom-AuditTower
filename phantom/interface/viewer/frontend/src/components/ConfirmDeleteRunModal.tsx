import { useEffect } from "react";
import { AlertTriangle, X } from "lucide-react";

export interface DeleteRunPlaybookWarning {
  count: number;
  names: string[];
}

interface ConfirmDeleteRunModalProps {
  runTitle: string | null;
  busy: boolean;
  error: string | null;
  /** Set once the server reports the run is the source of saved Playbooks. */
  playbookWarning: DeleteRunPlaybookWarning | null;
  onCancel: () => void;
  onConfirm: () => void;
}

export default function ConfirmDeleteRunModal({
  runTitle,
  busy,
  error,
  playbookWarning,
  onCancel,
  onConfirm,
}: ConfirmDeleteRunModalProps) {
  useEffect(() => {
    if (!runTitle) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !busy) onCancel();
    };
    document.addEventListener("keydown", onKeyDown);
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      document.body.style.overflow = previousOverflow;
    };
  }, [runTitle, busy, onCancel]);

  if (!runTitle) return null;

  return (
    <div
      className="dialog-overlay fixed inset-0 z-[120] flex items-center justify-center bg-black/80 p-4 backdrop-blur-sm"
      data-state="open"
      role="dialog"
      aria-modal="true"
      aria-labelledby="delete-run-title"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget && !busy) onCancel();
      }}
    >
      <div className="dialog-panel w-full max-w-md rounded-2xl border border-[var(--neutral-333)] bg-[var(--neutral-0b0b0b)] shadow-2xl" data-state="open">
        <div className="flex items-start justify-between gap-4 border-b border-[var(--neutral-252525)] px-6 py-5">
          <div className="flex items-start gap-3">
            <div className="mt-0.5 flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-xl border border-red-400/25 bg-red-500/10 text-red-300">
              <AlertTriangle className="h-4 w-4" aria-hidden="true" />
            </div>
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-[var(--neutral-777)]">Run history</p>
              <h2 id="delete-run-title" className="mt-1 text-lg font-semibold text-foreground">Delete this run?</h2>
            </div>
          </div>
          <button type="button" onClick={onCancel} disabled={busy} aria-label="Close" className="rounded-lg p-2 text-[var(--neutral-777)] transition-colors hover:bg-foreground/[0.06] hover:text-foreground disabled:opacity-50">
            <X className="h-5 w-5" aria-hidden="true" />
          </button>
        </div>
        <div className="px-6 py-5">
          <p className="truncate text-sm font-semibold text-foreground">{runTitle}</p>
          <p className="mt-2 text-sm leading-6 text-[var(--neutral-888)]">
            This permanently removes the run&apos;s artifacts (report, findings, coverage, and logs) from this machine. This cannot be undone.
          </p>
          {playbookWarning && playbookWarning.count > 0 && (
            <div className="mt-4 rounded-lg border border-yellow-500/25 bg-yellow-500/[0.06] px-4 py-3">
              <p className="text-sm font-semibold text-yellow-300">
                This run is the source of {playbookWarning.count} saved Playbook
                {playbookWarning.count === 1 ? "" : "s"}.
              </p>
              <p className="mt-1 text-sm leading-6 text-[var(--neutral-999)]">
                Your Playbooks stay in the library and remain replayable — only their source-run link will point to a run that no longer exists.
              </p>
              {playbookWarning.names.length > 0 && (
                <ul className="mt-2 space-y-0.5 text-xs text-[var(--neutral-777)]">
                  {playbookWarning.names.slice(0, 5).map((name, i) => (
                    <li key={`${name}-${i}`} className="truncate">• {name}</li>
                  ))}
                  {playbookWarning.names.length > 5 && (
                    <li className="text-[var(--neutral-555)]">+{playbookWarning.names.length - 5} more</li>
                  )}
                </ul>
              )}
            </div>
          )}
          {error && <p className="mt-4 text-sm text-red-400">{error}</p>}
        </div>
        <div className="flex items-center justify-end gap-3 border-t border-[var(--neutral-252525)] px-6 py-4">
          <button type="button" onClick={onCancel} disabled={busy} className="rounded-lg border border-[var(--neutral-333)] px-4 py-2 text-sm text-[var(--neutral-aaa)] transition-colors hover:border-[var(--neutral-555)] hover:text-foreground disabled:opacity-50">Keep run</button>
          <button type="button" onClick={onConfirm} disabled={busy} className="rounded-lg bg-red-500 px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-red-400 disabled:opacity-50">
            {busy ? "Deleting…" : playbookWarning ? "Delete anyway" : "Delete run"}
          </button>
        </div>
      </div>
    </div>
  );
}
