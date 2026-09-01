import { useCallback, useEffect, useState } from "react";
import type { FormEvent } from "react";
import { AlertCircle, CheckCircle2, Globe2, Plus, Target } from "lucide-react";
import { createTarget, fetchTargets, type RegisteredTarget } from "@/data/serverSource";

export default function TargetsView() {
  const [targets, setTargets] = useState<RegisteredTarget[]>([]);
  const [name, setName] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  const refresh = useCallback(async () => {
    try {
      setTargets(await fetchTargets());
      setError(null);
    } catch {
      setError("Could not load the target registry.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError(null);
    const cleanName = name.trim();
    const cleanUrl = baseUrl.trim();
    if (!cleanName) {
      setError("Enter a target name.");
      return;
    }
    try {
      const parsed = new URL(cleanUrl);
      if (!(["http:", "https:"].includes(parsed.protocol)) || parsed.username || parsed.password || parsed.search || parsed.hash) {
        throw new Error("invalid");
      }
    } catch {
      setError("Use a valid http:// or https:// base URL without credentials, query strings, or fragments.");
      return;
    }

    setSaving(true);
    const result = await createTarget(cleanName, cleanUrl);
    setSaving(false);
    if (!result.ok) {
      setError(result.message);
      return;
    }
    setName("");
    setBaseUrl("");
    setTargets((current) => [result.target, ...current]);
  };

  return (
    <div className="space-y-7">
      <div>
        <div className="flex items-center gap-2 text-blue-400">
          <Target className="h-5 w-5" aria-hidden="true" />
          <span className="text-xs font-semibold uppercase tracking-[0.18em]">Workspace</span>
        </div>
        <h1 className="mt-2 text-3xl font-semibold tracking-tight text-white">Targets</h1>
        <p className="mt-2 max-w-2xl text-sm leading-6 text-[#888]">
          Register only applications you are authorized to assess. Phantom will use the saved target and its scope
          when the scan workspace is enabled.
        </p>
      </div>

      {error && (
        <div className="flex items-start gap-3 rounded-xl border border-red-500/30 bg-red-500/5 px-4 py-3 text-sm text-red-300">
          <AlertCircle className="mt-0.5 h-4 w-4 flex-shrink-0" aria-hidden="true" />
          <span>{error}</span>
        </div>
      )}

      <section className="rounded-2xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-6">
        <div className="flex items-center gap-2">
          <Plus className="h-4 w-4 text-blue-400" aria-hidden="true" />
          <h2 className="text-lg font-semibold text-white">Register a target</h2>
        </div>
        <form onSubmit={submit} className="mt-5 grid gap-4 md:grid-cols-[0.8fr_1.2fr_auto] md:items-end">
          <label className="block">
            <span className="mb-2 block text-xs font-medium uppercase tracking-wide text-[#777]">Name</span>
            <input
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="Internal portal"
              maxLength={100}
              className="h-11 w-full rounded-lg border border-[#333] bg-black px-3 text-sm text-white outline-none transition-colors placeholder:text-[#555] focus:border-blue-400/70"
            />
          </label>
          <label className="block">
            <span className="mb-2 block text-xs font-medium uppercase tracking-wide text-[#777]">Base URL</span>
            <input
              value={baseUrl}
              onChange={(event) => setBaseUrl(event.target.value)}
              placeholder="https://app.example.test"
              inputMode="url"
              maxLength={2048}
              className="h-11 w-full rounded-lg border border-[#333] bg-black px-3 font-mono text-sm text-white outline-none transition-colors placeholder:text-[#555] focus:border-blue-400/70"
            />
          </label>
          <button
            type="submit"
            disabled={saving}
            className="inline-flex h-11 items-center justify-center gap-2 rounded-lg bg-blue-500 px-5 text-sm font-semibold text-white transition-colors hover:bg-blue-400 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {saving ? "Saving…" : "Register target"}
          </button>
        </form>
        <p className="mt-3 text-xs text-[#666]">Phantom starts with the URL host as the initial scope. Additional scope controls belong in the scan setup.</p>
      </section>

      <section className="rounded-2xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-6">
        <div className="flex items-center justify-between gap-4">
          <div>
            <h2 className="text-lg font-semibold text-white">Registered targets</h2>
            <p className="mt-1 text-sm text-[#777]">Stored locally in Phantom’s workspace registry.</p>
          </div>
          <span className="rounded-full border border-white/10 px-2.5 py-1 text-xs tabular-nums text-[#888]">{targets.length}</span>
        </div>

        {loading ? (
          <p className="mt-6 text-sm text-[#777]">Loading targets…</p>
        ) : targets.length === 0 ? (
          <div className="mt-6 rounded-xl border border-dashed border-[#333] px-5 py-8 text-center">
            <Globe2 className="mx-auto h-5 w-5 text-[#555]" aria-hidden="true" />
            <p className="mt-3 text-sm text-[#888]">No targets registered yet.</p>
          </div>
        ) : (
          <div className="mt-5 divide-y divide-[#222]">
            {targets.map((target) => (
              <div key={target.id} className="flex flex-wrap items-center gap-4 py-4">
                <div className="flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-lg border border-blue-400/20 bg-blue-500/10 text-blue-400">
                  <Globe2 className="h-4 w-4" aria-hidden="true" />
                </div>
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm font-medium text-white">{target.name}</p>
                  <p className="mt-1 truncate font-mono text-xs text-[#777]">{target.base_url}</p>
                </div>
                <div className="flex items-center gap-2 text-xs text-[#777]">
                  <CheckCircle2 className="h-4 w-4 text-blue-400" aria-hidden="true" />
                  <span>{target.scope_hosts.join(", ")}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
