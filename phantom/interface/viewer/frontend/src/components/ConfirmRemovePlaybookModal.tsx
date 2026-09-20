import { useEffect } from "react";
import { AlertTriangle, X } from "lucide-react";
import type { PlaybookEntry } from "@/lib/playbook-store";

interface ConfirmRemovePlaybookModalProps {
  entry: PlaybookEntry | null;
  onCancel: () => void;
  onConfirm: () => void;
}

export default function ConfirmRemovePlaybookModal({
  entry,
  onCancel,
  onConfirm,
}: ConfirmRemovePlaybookModalProps) {
  useEffect(() => {
    if (!entry) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onCancel();
    };
    document.addEventListener("keydown", onKeyDown);
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      document.body.style.overflow = previousOverflow;
    };
  }, [entry, onCancel]);

  if (!entry) return null;

  return (
    <div
      className="dialog-overlay fixed inset-0 z-[120] flex items-center justify-center bg-black/80 p-4 backdrop-blur-sm"
      data-state="open"
      role="dialog"
      aria-modal="true"
      aria-labelledby="remove-playbook-title"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onCancel();
      }}
    >
      <div className="dialog-panel w-full max-w-md rounded-2xl border border-[var(--neutral-333)] bg-[var(--neutral-0b0b0b)] shadow-2xl" data-state="open">
        <div className="flex items-start justify-between gap-4 border-b border-[var(--neutral-252525)] px-6 py-5">
          <div className="flex items-start gap-3">
            <div className="mt-0.5 flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-xl border border-red-400/25 bg-red-500/10 text-red-300">
              <AlertTriangle className="h-4 w-4" aria-hidden="true" />
            </div>
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-[var(--neutral-777)]">Playbook library</p>
              <h2 id="remove-playbook-title" className="mt-1 text-lg font-semibold text-foreground">Remove this playbook?</h2>
            </div>
          </div>
          <button type="button" onClick={onCancel} aria-label="Close" className="rounded-lg p-2 text-[var(--neutral-777)] transition-colors hover:bg-foreground/[0.06] hover:text-foreground">
            <X className="h-5 w-5" aria-hidden="true" />
          </button>
        </div>
        <div className="px-6 py-5">
          <p className="truncate text-sm font-semibold text-foreground">{entry.name}</p>
          <p className="mt-2 text-sm leading-6 text-[var(--neutral-888)]">This removes the saved copy from your local Playbook library. The original finding, scan, and report will not be changed.</p>
        </div>
        <div className="flex items-center justify-end gap-3 border-t border-[var(--neutral-252525)] px-6 py-4">
          <button type="button" onClick={onCancel} className="rounded-lg border border-[var(--neutral-333)] px-4 py-2 text-sm text-[var(--neutral-aaa)] transition-colors hover:border-[var(--neutral-555)] hover:text-foreground">Keep playbook</button>
          <button type="button" onClick={onConfirm} className="rounded-lg bg-red-500 px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-red-400">Remove playbook</button>
        </div>
      </div>
    </div>
  );
}
