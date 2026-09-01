import { ArrowRight, History, ScanLine, Target } from "lucide-react";
import type { ReactNode } from "react";
import type { DashboardInfo, RunsPayload } from "@/data/serverSource";

interface DashboardHomeProps {
  info: DashboardInfo | null;
  runs: RunsPayload | null;
  onOpenTargets: () => void;
  onOpenScan: () => void;
  onOpenRun: (name: string) => void;
}

export default function DashboardHome({
  info,
  runs,
  onOpenTargets,
  onOpenScan,
  onOpenRun,
}: DashboardHomeProps) {
  const latestRun = runs?.runs[0] ?? null;

  return (
    <div className="space-y-8">
      <div>
        <p className="text-xs font-semibold uppercase tracking-[0.18em] text-[#777]">Phantom workspace</p>
        <h1 className="mt-2 text-3xl font-semibold tracking-tight text-white">Audit workspace</h1>
        <p className="mt-2 text-sm text-[#888]">Targets, runs, and findings in one local workspace.</p>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <StatusCard
          icon={<ScanLine className="h-4 w-4" />}
          eyebrow="Scanner"
          title="Ready"
          detail="Configure and start a Phantom assessment"
          action={<button onClick={onOpenScan} className="dashboard-link">Start scan</button>}
        />
        <StatusCard
          icon={<Target className="h-4 w-4" />}
          eyebrow="Registered targets"
          title={String(info?.target_count ?? 0)}
          detail="Authorized assets available to the workspace"
          action={<button onClick={onOpenTargets} className="dashboard-link">Manage</button>}
        />
        <StatusCard
          icon={<History className="h-4 w-4" />}
          eyebrow="Recorded runs"
          title={String(runs?.count ?? 0)}
          detail={latestRun ? `Latest: ${latestRun.name}` : "No scans recorded yet"}
          action={latestRun ? <button onClick={() => onOpenRun(latestRun.name)} className="dashboard-link">Open latest</button> : undefined}
        />
      </div>

      <div>
        <section className="rounded-2xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-6">
          <div className="flex items-start justify-between gap-4">
            <div>
              <div className="flex items-center gap-2 text-[#888]">
                <Target className="h-4 w-4" aria-hidden="true" />
                <span className="text-xs font-semibold uppercase tracking-[0.16em]">Targets</span>
              </div>
              <h2 className="mt-3 text-xl font-semibold text-white">Your authorized assets</h2>
              <p className="mt-2 max-w-xl text-sm leading-6 text-[#888]">
                Keep each application’s base URL and scope in one place. Scan configuration uses these records to
                keep every assessment inside its approved scope.
              </p>
            </div>
            <div className="flex flex-shrink-0 flex-wrap items-center justify-end gap-2">
              <button
                onClick={onOpenTargets}
                className="dashboard-button group inline-flex items-center gap-1.5 rounded-lg border border-[#333] px-3 py-2 text-sm font-medium text-[#aaa] transition-all hover:border-[#555] hover:text-white"
              >
                Open targets <ArrowRight className="h-4 w-4 transition-transform duration-200 group-hover:translate-x-0.5" aria-hidden="true" />
              </button>
              <button
                onClick={onOpenScan}
                className="dashboard-button group inline-flex items-center gap-1.5 rounded-lg bg-blue-500 px-3 py-2 text-sm font-semibold text-white transition-all hover:bg-blue-400 hover:shadow-[0_0_24px_rgba(59,130,246,0.2)]"
              >
                Start a scan <ScanLine className="h-4 w-4 transition-transform duration-200 group-hover:rotate-6" aria-hidden="true" />
              </button>
            </div>
          </div>
        </section>

      </div>

      {latestRun && (
        <section className="rounded-2xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-6">
          <div className="flex items-center justify-between gap-4">
            <div>
              <h2 className="text-lg font-semibold text-white">Recent runs</h2>
              <p className="mt-1 text-sm text-[#777]">Existing reports and agent graphs remain available.</p>
            </div>
            <button onClick={() => onOpenRun(latestRun.name)} className="dashboard-link text-sm">
              View latest
            </button>
          </div>
          <div className="mt-5 divide-y divide-[#222]">
            {runs?.runs.slice(0, 5).map((run) => (
              <button
                key={run.name}
                onClick={() => onOpenRun(run.name)}
                className="group flex w-full items-center gap-4 py-3 text-left transition-all duration-200 hover:translate-x-0.5 hover:text-white"
              >
                <span className={`h-2 w-2 flex-shrink-0 rounded-full ${run.finished ? "bg-blue-400" : "bg-amber-400"}`} />
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-sm font-medium text-[#ddd]">{run.name}</span>
                  <span className="block truncate font-mono text-xs text-[#666]">{run.target ?? "No target recorded"}</span>
                </span>
                <span className="text-xs capitalize text-[#666]">{run.status ?? "unknown"}</span>
                <ArrowRight className="h-4 w-4 flex-shrink-0 text-[#555] transition-transform duration-200 group-hover:translate-x-0.5 group-hover:text-[#aaa]" aria-hidden="true" />
              </button>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}

function StatusCard({
  icon,
  eyebrow,
  title,
  detail,
  action,
}: {
  icon: ReactNode;
  eyebrow: string;
  title: string;
  detail: string;
  action?: ReactNode;
}) {
  return (
    <section className="rounded-2xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-5 transition-colors duration-200 hover:border-[#333]">
      <div className="flex items-center justify-between text-[#888]">
        <div className="flex items-center gap-2">
          {icon}
          <span className="text-xs font-semibold uppercase tracking-[0.14em]">{eyebrow}</span>
        </div>
      </div>
      <div className="mt-4 flex items-end justify-between gap-3">
        <p className="truncate text-xl font-semibold text-white">{title}</p>
        {action}
      </div>
      <p className="mt-1 truncate text-xs text-[#777]">{detail}</p>
    </section>
  );
}
