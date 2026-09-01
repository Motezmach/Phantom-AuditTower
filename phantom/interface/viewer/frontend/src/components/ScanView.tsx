import {
  ArrowLeft,
  ArrowRight,
  Check,
  CircleAlert,
  CircleCheck,
  ExternalLink,
  Loader2,
  Play,
  ScanLine,
  ShieldCheck,
  Square,
  Target,
  Zap,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import {
  fetchScans,
  fetchTargets,
  startScan,
  stopScan,
  type DashboardInfo,
  type RegisteredTarget,
  type ScanJob,
  type ScanMode,
} from "@/data/serverSource";

interface ScanViewProps {
  info: DashboardInfo | null;
  onOpenTargets: () => void;
  onOpenRun: (name: string) => void;
}

type WizardStep = 1 | 2 | 3;

const ACTIVE_STATUSES = new Set<ScanJob["status"]>(["preparing", "running"]);

export default function ScanView({ info, onOpenTargets, onOpenRun }: ScanViewProps) {
  const [targets, setTargets] = useState<RegisteredTarget[]>([]);
  const [targetLoading, setTargetLoading] = useState(true);
  const [targetError, setTargetError] = useState<string | null>(null);
  const [targetId, setTargetId] = useState("");
  const [scanMode, setScanMode] = useState<ScanMode>("deep");
  const [step, setStep] = useState<WizardStep>(1);
  const [job, setJob] = useState<ScanJob | null>(null);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  const selectedTarget = useMemo(
    () => targets.find((target) => target.id === targetId) ?? null,
    [targetId, targets]
  );
  const jobActive = job ? ACTIVE_STATUSES.has(job.status) : false;
  const jobTerminal = job ? !jobActive : false;

  const refreshState = useCallback(async () => {
    const [targetResult, scanResult] = await Promise.all([fetchTargets(), fetchScans()]);
    setTargets(targetResult.filter((target) => target.active));
    setTargetId((current) => {
      if (current && targetResult.some((target) => target.id === current && target.active)) return current;
      return targetResult.find((target) => target.active)?.id ?? "";
    });
    if (scanResult.active) {
      setJob(scanResult.active);
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    setTargetLoading(true);
    setTargetError(null);
    refreshState()
      .catch((cause) => {
        if (!cancelled) setTargetError(cause instanceof Error ? cause.message : "Could not load scan setup.");
      })
      .finally(() => {
        if (!cancelled) setTargetLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [refreshState]);

  useEffect(() => {
    if (!job || !ACTIVE_STATUSES.has(job.status)) return;
    let cancelled = false;
    const timer = window.setInterval(() => {
      fetchScans()
        .then((payload) => {
          if (cancelled) return;
          const latest = payload.jobs.find((item) => item.id === job.id) ?? payload.active;
          if (latest) setJob(latest);
        })
        .catch(() => {
          /* The run viewer remains the source of truth if a poll is missed. */
        });
    }, 1200);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [job]);

  const selectMode = (mode: ScanMode) => {
    setScanMode(mode);
    setActionError(null);
  };

  const beginScan = async () => {
    if (!selectedTarget || busy) return;
    setBusy(true);
    setActionError(null);
    const result = await startScan(selectedTarget.id, scanMode).catch((cause) => ({
      ok: false as const,
      message: cause instanceof Error ? cause.message : "Could not start this scan.",
    }));
    setBusy(false);
    if (!result.ok) {
      setActionError(result.message);
      return;
    }
    setJob(result.job);
  };

  const resetWizard = () => {
    setJob(null);
    setStep(1);
    setActionError(null);
    void refreshState().catch(() => undefined);
  };

  const requestStop = async () => {
    if (!job || !jobActive || job.stop_requested || busy) return;
    setBusy(true);
    setActionError(null);
    const result = await stopScan(job.id).catch((cause) => ({
      ok: false as const,
      message: cause instanceof Error ? cause.message : "Could not stop this scan.",
    }));
    setBusy(false);
    if (!result.ok) {
      setActionError(result.message);
      return;
    }
    setJob(result.job);
  };

  if (job) {
    return (
      <ScanProgress
        job={job}
        onOpenRun={onOpenRun}
        onStartAnother={jobTerminal ? resetWizard : undefined}
        onStop={() => void requestStop()}
        actionError={actionError}
        stopping={busy}
      />
    );
  }

  return (
    <div className="space-y-7">
      <div>
        <p className="text-xs font-semibold uppercase tracking-[0.18em] text-blue-300">Phantom scanner</p>
        <h1 className="mt-2 text-3xl font-semibold tracking-tight text-white">Start an assessment</h1>
        <p className="mt-2 max-w-2xl text-sm leading-6 text-[#888]">
          Configure an authorized target, choose the assessment depth, and review the launch before Phantom starts its
          existing agent workflow.
        </p>
      </div>

      <StepRail step={step} />

      {targetError && (
        <div className="flex items-start gap-3 rounded-xl border border-red-500/30 bg-red-500/5 px-4 py-3 text-sm text-red-200">
          <CircleAlert className="mt-0.5 h-4 w-4 flex-shrink-0 text-red-300" aria-hidden="true" />
          <span>{targetError}</span>
        </div>
      )}

      {step === 1 && (
        <TargetStep
          targets={targets}
          selectedId={targetId}
          loading={targetLoading}
          onSelect={setTargetId}
          onOpenTargets={onOpenTargets}
        />
      )}
      {step === 2 && <DepthStep mode={scanMode} onSelect={selectMode} />}
      {step === 3 && (
        <ReviewStep
          info={info}
          target={selectedTarget}
          mode={scanMode}
          busy={busy}
          error={actionError}
          onStart={() => void beginScan()}
        />
      )}

      <div className="flex items-center justify-between gap-3 border-t border-[#222] pt-5">
        <button
          type="button"
          onClick={() => setStep((current) => (current === 1 ? current : ((current - 1) as WizardStep)))}
          disabled={step === 1 || busy}
          className="dashboard-button inline-flex items-center gap-2 rounded-lg border border-[#333] px-3.5 py-2.5 text-sm font-medium text-[#aaa] transition-all hover:border-[#555] hover:text-white disabled:cursor-not-allowed disabled:opacity-30"
        >
          <ArrowLeft className="h-4 w-4" aria-hidden="true" /> Back
        </button>
        {step < 3 && (
          <button
            type="button"
            onClick={() => setStep((current) => (current + 1) as WizardStep)}
            disabled={(step === 1 && !selectedTarget) || busy}
            className="dashboard-button inline-flex items-center gap-2 rounded-lg bg-blue-500 px-4 py-2.5 text-sm font-semibold text-white transition-all hover:bg-blue-400 hover:shadow-[0_0_24px_rgba(59,130,246,0.2)] disabled:cursor-not-allowed disabled:opacity-40"
          >
            Continue <ArrowRight className="h-4 w-4" aria-hidden="true" />
          </button>
        )}
      </div>
    </div>
  );
}

function StepRail({ step }: { step: WizardStep }) {
  const steps = ["Target", "Depth", "Review"];
  return (
    <div className="grid grid-cols-3 gap-2 rounded-xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-2">
      {steps.map((label, index) => {
        const number = index + 1;
        const complete = number < step;
        const current = number === step;
        return (
          <div
            key={label}
            className={`flex items-center gap-2 rounded-lg px-3 py-2 text-sm transition-colors ${
              current ? "bg-white/[0.08] text-white" : complete ? "text-blue-300" : "text-[#666]"
            }`}
          >
            <span
              className={`flex h-6 w-6 items-center justify-center rounded-full border text-xs font-semibold ${
                current
                  ? "border-blue-300 bg-blue-500/20 text-blue-200"
                  : complete
                    ? "border-blue-400/50 bg-blue-500/10 text-blue-300"
                    : "border-[#333] text-[#666]"
              }`}
            >
              {complete ? <Check className="h-3.5 w-3.5" aria-hidden="true" /> : number}
            </span>
            <span className="font-medium">{label}</span>
          </div>
        );
      })}
    </div>
  );
}

function TargetStep({
  targets,
  selectedId,
  loading,
  onSelect,
  onOpenTargets,
}: {
  targets: RegisteredTarget[];
  selectedId: string;
  loading: boolean;
  onSelect: (id: string) => void;
  onOpenTargets: () => void;
}) {
  return (
    <section className="rounded-2xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-5 sm:p-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-blue-300">
            <Target className="h-4 w-4" aria-hidden="true" />
            <span className="text-xs font-semibold uppercase tracking-[0.16em]">Step 1 · Scope</span>
          </div>
          <h2 className="mt-3 text-xl font-semibold text-white">Choose an authorized target</h2>
          <p className="mt-2 text-sm leading-6 text-[#888]">Only active targets in your Phantom registry can be scanned.</p>
        </div>
        <button
          type="button"
          onClick={onOpenTargets}
          className="dashboard-button inline-flex items-center gap-2 rounded-lg border border-[#333] px-3 py-2 text-sm font-medium text-[#aaa] transition-all hover:border-[#555] hover:text-white"
        >
          Manage targets <ExternalLink className="h-3.5 w-3.5" aria-hidden="true" />
        </button>
      </div>

      {loading ? (
        <div className="mt-6 flex items-center gap-2 text-sm text-[#777]">
          <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> Loading authorized targets…
        </div>
      ) : targets.length === 0 ? (
        <div className="mt-6 rounded-xl border border-dashed border-[#333] px-5 py-8 text-center">
          <ShieldCheck className="mx-auto h-6 w-6 text-[#666]" aria-hidden="true" />
          <p className="mt-3 text-sm font-medium text-white">No active targets yet</p>
          <p className="mt-1 text-sm text-[#777]">Register the application and its scope before starting an assessment.</p>
          <button
            type="button"
            onClick={onOpenTargets}
            className="dashboard-button mt-5 inline-flex items-center gap-2 rounded-lg bg-blue-500 px-4 py-2.5 text-sm font-semibold text-white transition-all hover:bg-blue-400"
          >
            Register a target <ArrowRight className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>
      ) : (
        <div className="mt-6 grid gap-3">
          {targets.map((target) => (
            <button
              type="button"
              key={target.id}
              onClick={() => onSelect(target.id)}
              className={`group flex w-full items-start gap-3 rounded-xl border px-4 py-4 text-left transition-all ${
                selectedId === target.id
                  ? "border-blue-400/70 bg-blue-500/[0.08] shadow-[0_0_28px_rgba(59,130,246,0.08)]"
                  : "border-[#2b2b2b] bg-black/20 hover:border-[#4a4a4a] hover:bg-white/[0.03]"
              }`}
            >
              <span
                className={`mt-0.5 flex h-5 w-5 flex-shrink-0 items-center justify-center rounded-full border ${
                  selectedId === target.id ? "border-blue-300 bg-blue-500 text-white" : "border-[#555] text-transparent"
                }`}
              >
                <Check className="h-3 w-3" aria-hidden="true" />
              </span>
              <span className="min-w-0 flex-1">
                <span className="block text-sm font-semibold text-white">{target.name}</span>
                <span className="mt-1 block truncate font-mono text-xs text-[#888]">{target.base_url}</span>
                <span className="mt-2 flex flex-wrap gap-1.5">
                  {target.scope_hosts.map((host) => (
                    <span key={host} className="rounded-md border border-white/10 px-2 py-0.5 text-[11px] text-[#777]">
                      {host}
                    </span>
                  ))}
                </span>
              </span>
              <span className="mt-1 flex items-center gap-1.5 text-xs text-emerald-300">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" /> Active
              </span>
            </button>
          ))}
        </div>
      )}
    </section>
  );
}

function DepthStep({ mode, onSelect }: { mode: ScanMode; onSelect: (mode: ScanMode) => void }) {
  return (
    <section className="rounded-2xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-5 sm:p-6">
      <div className="flex items-center gap-2 text-blue-300">
        <ScanLine className="h-4 w-4" aria-hidden="true" />
        <span className="text-xs font-semibold uppercase tracking-[0.16em]">Step 2 · Assessment depth</span>
      </div>
      <h2 className="mt-3 text-xl font-semibold text-white">Choose how Phantom should run</h2>
      <p className="mt-2 text-sm leading-6 text-[#888]">Both modes use the same engine, sandbox, agents, skills, and reporting path.</p>

      <div className="mt-6 grid gap-3 md:grid-cols-2">
        <ModeCard
          mode="quick"
          selected={mode === "quick"}
          icon={<Zap className="h-5 w-5" aria-hidden="true" />}
          title="Quick scan"
          detail="A focused first pass for fast feedback."
          bullets={["Shorter time-to-result", "Good for a release check"]}
          onSelect={() => onSelect("quick")}
        />
        <ModeCard
          mode="deep"
          selected={mode === "deep"}
          icon={<ShieldCheck className="h-5 w-5" aria-hidden="true" />}
          title="Deep scan"
          detail="Broader coverage for a complete assessment."
          bullets={["More discovery and validation time", "Recommended for an audit"]}
          onSelect={() => onSelect("deep")}
        />
      </div>
    </section>
  );
}

function ModeCard({
  mode,
  selected,
  icon,
  title,
  detail,
  bullets,
  onSelect,
}: {
  mode: ScanMode;
  selected: boolean;
  icon: ReactNode;
  title: string;
  detail: string;
  bullets: string[];
  onSelect: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onSelect}
      className={`group rounded-xl border p-5 text-left transition-all ${
        selected
          ? "border-blue-400/70 bg-blue-500/[0.08] shadow-[0_0_28px_rgba(59,130,246,0.08)]"
          : "border-[#2b2b2b] bg-black/20 hover:border-[#4a4a4a] hover:bg-white/[0.03]"
      }`}
    >
      <div className="flex items-start justify-between gap-3">
        <span className={`rounded-lg border p-2 ${selected ? "border-blue-300/40 bg-blue-500/10 text-blue-200" : "border-[#333] text-[#888]"}`}>
          {icon}
        </span>
        <span className={`h-5 w-5 rounded-full border p-0.5 ${selected ? "border-blue-300" : "border-[#555]"}`}>
          <span className={`block h-full w-full rounded-full ${selected ? "bg-blue-400" : "bg-transparent"}`} />
        </span>
      </div>
      <p className="mt-4 text-base font-semibold text-white">{title}</p>
      <p className="mt-1 text-sm text-[#888]">{detail}</p>
      <ul className="mt-4 space-y-2 text-xs text-[#777]">
        {bullets.map((bullet) => (
          <li key={bullet} className="flex items-center gap-2">
            <Check className="h-3.5 w-3.5 text-blue-300" aria-hidden="true" /> {bullet}
          </li>
        ))}
      </ul>
      <span className="sr-only">{mode} scan</span>
    </button>
  );
}

function ReviewStep({
  info,
  target,
  mode,
  busy,
  error,
  onStart,
}: {
  info: DashboardInfo | null;
  target: RegisteredTarget | null;
  mode: ScanMode;
  busy: boolean;
  error: string | null;
  onStart: () => void;
}) {
  return (
    <section className="rounded-2xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-5 sm:p-6">
      <div className="flex items-center gap-2 text-blue-300">
        <CircleCheck className="h-4 w-4" aria-hidden="true" />
        <span className="text-xs font-semibold uppercase tracking-[0.16em]">Step 3 · Review and launch</span>
      </div>
      <h2 className="mt-3 text-xl font-semibold text-white">Everything ready?</h2>
      <p className="mt-2 text-sm leading-6 text-[#888]">Review the scope, then Phantom will hand this request to its existing scan engine.</p>

      <div className="mt-6 grid gap-3 sm:grid-cols-2">
        <ReviewItem label="Target" value={target?.name ?? "Not selected"} detail={target?.base_url} />
        <ReviewItem label="Depth" value={mode === "deep" ? "Deep scan" : "Quick scan"} detail="Existing Phantom workflow" />
        <ReviewItem label="Language model" value={info?.llm.model ?? "Not configured"} detail={info?.llm.endpoint === "local" ? "Local endpoint" : "Provider endpoint"} />
        <ReviewItem label="Execution" value="Phantom sandbox" detail="Run artifacts stay in the local workspace" />
      </div>

      {error && (
        <div className="mt-4 flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/5 px-3 py-2.5 text-sm text-red-200">
          <CircleAlert className="mt-0.5 h-4 w-4 flex-shrink-0" aria-hidden="true" />
          <span>{error}</span>
        </div>
      )}

      <button
        type="button"
        onClick={onStart}
        disabled={!target || busy}
        className="dashboard-button mt-6 inline-flex items-center gap-2 rounded-lg bg-blue-500 px-4 py-2.5 text-sm font-semibold text-white transition-all hover:bg-blue-400 hover:shadow-[0_0_24px_rgba(59,130,246,0.2)] disabled:cursor-not-allowed disabled:opacity-40"
      >
        {busy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Play className="h-4 w-4" aria-hidden="true" />}
        {busy ? "Preparing scan…" : "Start Phantom scan"}
      </button>
    </section>
  );
}

function ReviewItem({ label, value, detail }: { label: string; value: string; detail?: string }) {
  return (
    <div className="rounded-xl border border-[#2b2b2b] bg-black/20 px-4 py-3">
      <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-[#666]">{label}</p>
      <p className="mt-2 truncate text-sm font-medium text-white" title={value}>{value}</p>
      {detail && <p className="mt-1 truncate font-mono text-xs text-[#777]" title={detail}>{detail}</p>}
    </div>
  );
}

function ScanProgress({
  job,
  onOpenRun,
  onStartAnother,
  onStop,
  actionError,
  stopping,
}: {
  job: ScanJob;
  onOpenRun: (name: string) => void;
  onStartAnother?: () => void;
  onStop?: () => void;
  actionError?: string | null;
  stopping?: boolean;
}) {
  const active = ACTIVE_STATUSES.has(job.status);
  const failed = job.status === "failed";
  const complete = job.status === "completed";
  const stopped = job.status === "stopped";
  const stopPending = active && (job.stop_requested || stopping);
  const title = complete
    ? "Assessment complete"
    : failed
      ? "Assessment failed"
      : stopped
        ? "Assessment stopped"
        : stopPending
          ? "Stopping assessment"
          : "Phantom is working";
  const message = complete
    ? "The run is ready. Open it to review findings, the agent graph, and the existing report views."
    : failed
      ? job.error ?? "Phantom could not complete this assessment."
      : stopped
        ? job.error ?? "The scan was stopped. Any partial artifacts remain available for review."
        : stopPending
          ? "Stop requested. Phantom is finishing the current safe shutdown and preserving the run artifacts."
          : "The dashboard has handed the request to the existing Phantom engine. The live run viewer will update as agents report back.";

  const stages = [
    { label: "Request accepted", done: true },
    { label: "Engine started", done: job.status !== "preparing" },
    { label: "Agent workspace", done: job.status === "running" || complete },
    { label: "Report ready", done: complete },
  ];

  return (
    <div className="space-y-7">
      <div>
        <p className="text-xs font-semibold uppercase tracking-[0.18em] text-blue-300">Phantom scanner</p>
        <h1 className="mt-2 text-3xl font-semibold tracking-tight text-white">{title}</h1>
        <p className="mt-2 max-w-2xl text-sm leading-6 text-[#888]">{message}</p>
      </div>

      <section className="rounded-2xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-5 sm:p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="flex min-w-0 items-start gap-3">
            <span className={`mt-0.5 flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-xl border ${
              failed ? "border-red-400/30 bg-red-500/10 text-red-300" : complete ? "border-emerald-400/30 bg-emerald-500/10 text-emerald-300" : stopped ? "border-amber-400/30 bg-amber-500/10 text-amber-300" : "border-blue-400/30 bg-blue-500/10 text-blue-300"
            }`}>
              {active ? <Loader2 className="h-5 w-5 animate-spin" aria-hidden="true" /> : failed ? <CircleAlert className="h-5 w-5" aria-hidden="true" /> : stopped ? <Square className="h-4 w-4" aria-hidden="true" /> : <CircleCheck className="h-5 w-5" aria-hidden="true" />}
            </span>
            <div className="min-w-0">
              <p className="truncate text-base font-semibold text-white">{job.target_name}</p>
              <p className="mt-1 truncate font-mono text-xs text-[#777]">{job.target_url}</p>
            </div>
          </div>
          <span className="rounded-full border border-white/10 px-2.5 py-1 text-xs font-medium capitalize text-[#aaa]">
            {job.scan_mode} · {job.status}
          </span>
        </div>

        <div className="mt-8 grid gap-3 sm:grid-cols-4">
          {stages.map((stage, index) => (
            <div key={stage.label} className="relative flex items-center gap-2 sm:block">
              <span className={`flex h-7 w-7 items-center justify-center rounded-full border text-xs ${
                stage.done ? "border-blue-300/50 bg-blue-500/15 text-blue-200" : "border-[#333] text-[#666]"
              }`}>
                {stage.done ? <Check className="h-3.5 w-3.5" aria-hidden="true" /> : index + 1}
              </span>
              <span className={`ml-2 text-xs sm:ml-0 sm:mt-2 sm:block ${stage.done ? "text-[#ccc]" : "text-[#666]"}`}>{stage.label}</span>
              {index < stages.length - 1 && <span className="absolute left-8 right-[-0.75rem] top-3 hidden h-px bg-[#2d2d2d] sm:block" />}
            </div>
          ))}
        </div>

        {job.run_name && (
          <div className="mt-7 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-[#2b2b2b] bg-black/20 px-4 py-3">
            <div>
              <p className="text-xs text-[#666]">Run workspace</p>
              <p className="mt-1 font-mono text-sm text-[#aaa]">{job.run_name}</p>
            </div>
            <button
              type="button"
              onClick={() => onOpenRun(job.run_name as string)}
              className="dashboard-button inline-flex items-center gap-2 rounded-lg border border-blue-400/40 bg-blue-500/10 px-3 py-2 text-sm font-medium text-blue-200 transition-all hover:border-blue-300/70 hover:bg-blue-500/20"
            >
              {active ? "Open live workspace" : "Open run"} <ArrowRight className="h-4 w-4" aria-hidden="true" />
            </button>
          </div>
        )}

        {active && onStop && (
          <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
            {actionError ? <p className="text-xs text-red-300">{actionError}</p> : <span />}
            <button
              type="button"
              onClick={onStop}
              disabled={stopPending}
              className="dashboard-button inline-flex items-center gap-2 rounded-lg border border-amber-300/30 px-3 py-2 text-sm font-semibold text-amber-200 transition-all hover:border-amber-200/60 hover:bg-amber-300/10 disabled:cursor-wait disabled:opacity-60"
            >
              {stopPending ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Square className="h-3.5 w-3.5 fill-current" aria-hidden="true" />}
              {stopPending ? "Stopping…" : "Stop scan"}
            </button>
          </div>
        )}
      </section>

      {onStartAnother && (
        <button
          type="button"
          onClick={onStartAnother}
          className="dashboard-button inline-flex items-center gap-2 rounded-lg border border-[#333] px-3.5 py-2.5 text-sm font-medium text-[#aaa] transition-all hover:border-[#555] hover:text-white"
        >
          Start another scan <ScanLine className="h-4 w-4" aria-hidden="true" />
        </button>
      )}
    </div>
  );
}
