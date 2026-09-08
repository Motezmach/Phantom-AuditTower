import { useEffect, useState } from "react";
import { BookMarked, Check, Loader2, X } from "lucide-react";
import type { Vulnerability } from "@/types/issues";
import {
  addPlaybook,
  getLastAuditorName,
  type PlaybookEntry,
} from "@/lib/playbook-store";

interface AddToPlaybookModalProps {
  open: boolean;
  vulnerability: Vulnerability;
  targetName: string;
  targetUrl: string | null;
  runName: string | null;
  onClose: () => void;
  onSaved?: (entry: PlaybookEntry) => void;
}

export default function AddToPlaybookModal({
  open,
  vulnerability,
  targetName,
  targetUrl,
  runName,
  onClose,
  onSaved,
}: AddToPlaybookModalProps) {
  const [name, setName] = useState(vulnerability.title);
  const [auditorName, setAuditorName] = useState(getLastAuditorName);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!open) return;
    setName(vulnerability.title);
    setAuditorName(getLastAuditorName());
    setError(null);
    setSaving(false);
  }, [open, vulnerability.id, vulnerability.title]);

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
    if (!name.trim()) {
      setError("Give this playbook a name before saving.");
      return;
    }
    if (!auditorName.trim()) {
      setError("Enter the auditor name for this saved attack.");
      return;
    }
    setSaving(true);
    try {
      const result = await addPlaybook({
        name,
        targetName,
        targetUrl,
        auditorName,
        runName,
        finding: vulnerability,
      });
      if (!result.created) {
        setError("This finding is already saved in the Playbook.");
        return;
      }
      onSaved?.(result.entry);
      onClose();
    } catch (cause: unknown) {
      setError(cause instanceof Error ? cause.message : "Could not save this Playbook.");
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
      aria-labelledby="playbook-dialog-title"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div className="dialog-panel w-full max-w-lg rounded-2xl border border-[#333] bg-[#0b0b0b] shadow-2xl" data-state="open">
        <div className="flex items-start justify-between gap-4 border-b border-[#252525] px-6 py-5">
          <div className="flex min-w-0 items-start gap-3">
            <div className="mt-0.5 flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-xl border border-blue-400/25 bg-blue-500/10 text-blue-300">
              <BookMarked className="h-4 w-4" aria-hidden="true" />
            </div>
            <div className="min-w-0">
              <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-[#777]">Playbook library</p>
              <h2 id="playbook-dialog-title" className="mt-1 text-lg font-semibold text-white">Save this attack</h2>
              <p className="mt-1 text-sm leading-6 text-[#888]">Keep the finding, proof, and replay recipe together for future retesting.</p>
            </div>
          </div>
          <button type="button" onClick={onClose} aria-label="Close" className="rounded-lg p-2 text-[#777] transition-colors hover:bg-white/[0.06] hover:text-white">
            <X className="h-5 w-5" aria-hidden="true" />
          </button>
        </div>

        <div className="space-y-5 px-6 py-5">
          <div className="rounded-xl border border-[#252525] bg-black/50 p-4">
            <p className="truncate text-sm font-medium text-white">{vulnerability.title}</p>
            <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-xs text-[#777]">
              <span>{targetName}</span>
              {targetUrl && <span className="truncate font-mono">{targetUrl}</span>}
            </div>
          </div>

          <label className="block">
            <span className="text-sm font-medium text-[#ddd]">Playbook name</span>
            <input
              autoFocus
              value={name}
              onChange={(event) => setName(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") void save();
              }}
              className="mt-2 h-11 w-full rounded-lg border border-[#333] bg-black px-3 text-sm text-white outline-none transition-colors placeholder:text-[#555] focus:border-blue-400/70"
              placeholder="e.g. Unauthenticated admin takeover"
            />
          </label>

          <label className="block">
            <span className="text-sm font-medium text-[#ddd]">Auditor</span>
            <input
              value={auditorName}
              onChange={(event) => setAuditorName(event.target.value)}
              className="mt-2 h-11 w-full rounded-lg border border-[#333] bg-black px-3 text-sm text-white outline-none transition-colors placeholder:text-[#555] focus:border-blue-400/70"
              placeholder="Your name"
            />
          </label>

          <div className="flex items-center gap-2 text-xs text-[#666]">
            <Check className="h-3.5 w-3.5 text-emerald-400" aria-hidden="true" />
            Added now · the original finding snapshot and replay recipe will be preserved
          </div>
          {error && <p className="text-sm text-red-400">{error}</p>}
        </div>

        <div className="flex items-center justify-end gap-3 border-t border-[#252525] px-6 py-4">
          <button type="button" onClick={onClose} className="rounded-lg border border-[#333] px-4 py-2 text-sm text-[#aaa] transition-colors hover:border-[#555] hover:text-white">Cancel</button>
          <button type="button" disabled={saving} onClick={() => void save()} className="inline-flex items-center gap-2 rounded-lg bg-white px-4 py-2 text-sm font-semibold text-black transition-all hover:bg-[#e8e8e8] hover:shadow-[0_0_24px_rgba(255,255,255,0.14)] disabled:cursor-wait disabled:opacity-60">
            {saving ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <BookMarked className="h-4 w-4" aria-hidden="true" />}
            {saving ? "Saving…" : "Save playbook"}
          </button>
        </div>
      </div>
    </div>
  );
}
