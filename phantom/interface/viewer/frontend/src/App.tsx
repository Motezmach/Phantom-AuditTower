import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowLeft,
  ArrowRight,
  AlertCircle,
  Bot,
  ChevronDown,
  Download,
  LayoutDashboard,
  Loader2,
  History,
  Square,
  Ban,
  CheckCircle2,
  BookMarked,
} from "lucide-react";
import type { Vulnerability, VulnerabilitySeverity } from "@/types/issues";
import { SEVERITY_COLORS } from "@/types/issues";
import { getSeverityDot } from "@/lib/vulnerability-utils";
import VulnerabilityDetail from "@/components/vulnerability/VulnerabilityDetail";
import { ContentSection } from "@/components/vulnerability/ContentSection";
import { IssueSeveritySummary } from "@/components/IssueSeveritySummary";
import AgentGraph from "@/components/live/AgentGraph";
import { buildGraphAgents } from "@/components/live/AgentTranscript";
import AgentDetailModal from "@/components/live/AgentDetailModal";
import { ScanPromptComposer } from "@/components/live/ScanPromptComposer";
import DashboardHome from "@/components/DashboardHome";
import TargetsView from "@/components/TargetsView";
import ScanView from "@/components/ScanView";
import { severityCounts, type ParsedRunSummary } from "@/lib/local-run-parser";
import {
  fetchAll,
  fetchCapabilities,
  fetchDashboardInfo,
  fetchRunSummary,
  fetchScans,
  fetchRuns,
  fetchTranscript,
  fetchVulnerabilities,
  reportPdfUrl,
  stopScan,
  type DashboardInfo,
  type LoadedRun,
  type RunReviewSummary,
  type RunsPayload,
} from "@/data/serverSource";
import { runTitle } from "@/lib/target-utils";
import Sidebar from "@/components/Sidebar";
import ThemeToggle from "@/components/ThemeToggle";
import PastRunsView from "@/components/PastRunsView";
import { RunDetails } from "@/components/RunDetails";
import { TrustToast } from "@/components/TrustToast";
import PlaybookView from "@/components/PlaybookView";
import { findPlaybook, findPlaybookById, listPlaybooks, loadPlaybooks, PLAYBOOKS_CHANGED_EVENT } from "@/lib/playbook-store";
import { findRejection, loadRejections, REJECTIONS_CHANGED_EVENT } from "@/lib/rejection-store";

export type View = "dashboard" | "targets" | "scan" | "overview" | "issues" | "agents" | "history" | "playbooks";

const TRUST_BANNER =
  "Your findings stay on your machine. They're rendered here locally in your browser and never uploaded or stored by Phantom.";

const SEVERITY_ORDER: VulnerabilitySeverity[] = ["critical", "high", "medium", "low"];
const POLL_MS = 500;

export default function App() {
  const [activeRun, setActiveRun] = useState<string | null>(null);
  const [run, setRun] = useState<LoadedRun | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [view, setView] = useState<View>("overview");
  const [runs, setRuns] = useState<RunsPayload | null>(null);
  // Bumped whenever the rejection registry changes so the findings list
  // re-renders its "Rejected" labels.
  const [rejectionsVersion, setRejectionsVersion] = useState(0);
  const [dashboardMode, setDashboardMode] = useState<boolean | null>(null);
  // Whether this dashboard can launch/stop scans. `phantom serve` can; the
  // in-TUI dashboard cannot (it owns the scan), so target/scan views are hidden.
  const [canManageScans, setCanManageScans] = useState(false);
  const [dashboardInfo, setDashboardInfo] = useState<DashboardInfo | null>(null);
  const [playbookCount, setPlaybookCount] = useState(() => listPlaybooks().length);
  // Whether this viewer can steer a live scan. The TUI and dashboard both
  // expose the same coordinator-backed capability.
  const [canSteer, setCanSteer] = useState(false);

  const refreshRuns = useCallback(async () => {
    try {
      setRuns(await fetchRuns());
    } catch {
      /* history list is best-effort */
    }
  }, []);

  useEffect(() => {
    void refreshRuns();
    void loadPlaybooks();
    void loadRejections();
    fetchDashboardInfo()
      .then((info) => {
        setDashboardInfo(info);
        setDashboardMode(info.mode === "dashboard");
        setCanManageScans(info.canManageScans);
        if (info.mode === "dashboard") {
          if (info.defaultRun) {
            // Launched for a specific live run (the in-TUI dashboard): land on
            // that run with full audit features, not the workspace home.
            setActiveRun(info.defaultRun);
          } else {
            setView("dashboard");
          }
        }
      })
      .catch(() => {
        // Older viewers or a transient startup failure safely behave as the
        // existing run viewer.
        setDashboardMode(false);
      });
    // Capabilities never change over a session, so fetch once on mount.
    fetchCapabilities()
      .then((caps) => setCanSteer(caps.can_steer))
      .catch(() => {
        /* absence of steering is the safe default */
      });
  }, [refreshRuns]);

  useEffect(() => {
    const refreshPlaybookCount = () => setPlaybookCount(listPlaybooks().length);
    window.addEventListener(PLAYBOOKS_CHANGED_EVENT, refreshPlaybookCount);
    return () => window.removeEventListener(PLAYBOOKS_CHANGED_EVENT, refreshPlaybookCount);
  }, []);

  useEffect(() => {
    const bump = () => setRejectionsVersion((value) => value + 1);
    window.addEventListener(REJECTIONS_CHANGED_EVENT, bump);
    return () => window.removeEventListener(REJECTIONS_CHANGED_EVENT, bump);
  }, []);

  // Live polling, scoped to the active run. Re-runs when the active run changes
  // so switching to a past run (?run=<name>) reloads its data; a finished run
  // does a single full fetch and stops.
  const finishedRef = useRef(false);
  useEffect(() => {
    if (dashboardMode === null || (dashboardMode && activeRun === null)) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    finishedRef.current = false;

    const schedule = () => {
      timer = setTimeout(tick, POLL_MS);
    };

    const tick = async () => {
      if (cancelled) return;
      try {
        const { summary, raw, finished, review } = await fetchRunSummary(activeRun);
        if (cancelled) return;
        if (finished && !finishedRef.current) {
          finishedRef.current = true;
          const full = await fetchAll(activeRun);
          if (!cancelled) setRun(full);
          return; // stop polling
        }
        const [transcript, vulnerabilities] = await Promise.all([
          fetchTranscript(activeRun).catch(() => ({ agents: [], events: [] })),
          fetchVulnerabilities(summary.runId, activeRun).catch(() => [] as Vulnerability[]),
        ]);
        if (cancelled) return;
        setRun((prev) => ({
          summary,
          raw,
          finished,
          review,
          transcript,
          vulnerabilities,
          reportMarkdown: prev?.reportMarkdown ?? null,
        }));
        schedule();
      } catch (e) {
        if (cancelled) return;
        setError(e instanceof Error ? e.message : "Could not load run data.");
        schedule();
      }
    };

    (async () => {
      try {
        const full = await fetchAll(activeRun);
        if (cancelled) return;
        setRun(full);
        if (full.finished) {
          finishedRef.current = true;
        } else {
          schedule();
        }
      } catch (e) {
        if (cancelled) return;
        setError(e instanceof Error ? e.message : "Could not load run data.");
        schedule();
      }
    })();

    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [activeRun, dashboardMode]);

  const counts = useMemo(
    () => (run ? severityCounts(run.vulnerabilities) : null),
    [run]
  );
  // The standalone viewer loads its run as the server's default and therefore
  // has no dashboard selection in `activeRun`. Keep the persisted run name so
  // run-scoped actions (such as replay) work in both viewer modes.
  const loadedRunName = activeRun ?? run?.summary.runName ?? null;

  // Review actions happen from a finding detail view. Refresh the finished
  // run when signing/rejecting/restoring so Overview and the export CTA update
  // without requiring navigation or a full page reload.
  useEffect(() => {
    if (!run?.finished || !loadedRunName) return;
    const refreshReviewedRun = () => {
      // Review actions change the report gate, not the scan transcript or
      // candidate ledger. Refresh only the run summary so a deliberate
      // review_required response never becomes a browser-console error and
      // cannot trigger an event-refresh loop through the review stores.
      void fetchRunSummary(loadedRunName)
        .then(({ summary, raw, finished, review }) => setRun((previous) => previous
          ? { ...previous, summary, raw, finished, review }
          : previous))
        .catch(() => {
          /* The next explicit view refresh will retry; the server remains authoritative. */
        });
    };
    window.addEventListener(PLAYBOOKS_CHANGED_EVENT, refreshReviewedRun);
    window.addEventListener(REJECTIONS_CHANGED_EVENT, refreshReviewedRun);
    return () => {
      window.removeEventListener(PLAYBOOKS_CHANGED_EVENT, refreshReviewedRun);
      window.removeEventListener(REJECTIONS_CHANGED_EVENT, refreshReviewedRun);
    };
  }, [loadedRunName, run?.finished]);

  const selected = run?.vulnerabilities.find((v) => v.id === selectedId) ?? null;
  const agentCount = run?.transcript.agents.length ?? 0;

  // Per-run guard for the default view: land on Agents while a scan is live,
  // Overview once it finishes. Applied at most once per run and never once the
  // user has navigated manually (userSetView flips the guard).
  const initialViewAppliedRef = useRef(false);

  // Reset the guard whenever the active run changes so the newly selected run
  // gets its own default.
  useEffect(() => {
    // Dashboard-selected runs intentionally open on Overview. The classic
    // in-run viewer keeps its existing live-agent default.
    initialViewAppliedRef.current = dashboardMode === true;
  }, [activeRun, dashboardMode]);

  useEffect(() => {
    if (initialViewAppliedRef.current || !run) return;
    if (run.finished) {
      initialViewAppliedRef.current = true;
      setView("overview");
    } else if (!dashboardMode && agentCount > 0) {
      // Live and agents have appeared: default to the agent graph. If it is
      // live but no agents exist yet, wait (do not apply, do not set the flag).
      initialViewAppliedRef.current = true;
      setView("agents");
    }
  }, [run, agentCount, dashboardMode]);

  // User-initiated navigation: mark the default guard applied so the per-run
  // default effect never yanks the user off the view they chose.
  const userSetView = useCallback((v: View) => {
    initialViewAppliedRef.current = true;
    setView(v);
  }, []);

  const selectRun = useCallback((name: string) => {
    setActiveRun(name);
    setSelectedId(null);
    setRun(null);
    setError(null);
    setView("overview");
    // Reset the guard so the per-run default applies to the newly selected run.
    initialViewAppliedRef.current = false;
  }, []);

  const handleRunDeleted = useCallback(
    (name: string) => {
      // If the deleted run was the one on screen, clear it so the poller doesn't
      // 404 on /api/run; then refresh the history list.
      if (name === activeRun) {
        setActiveRun(null);
        setSelectedId(null);
        setRun(null);
      }
      void refreshRuns();
    },
    [activeRun, refreshRuns],
  );

  const openHistory = useCallback(() => {
    void refreshRuns();
    userSetView("history");
  }, [refreshRuns, userSetView]);

  const openDashboard = useCallback(() => {
    setActiveRun(null);
    setSelectedId(null);
    setRun(null);
    setError(null);
    userSetView("dashboard");
    void refreshRuns();
  }, [refreshRuns, userSetView]);

  const openTargets = useCallback(() => {
    setActiveRun(null);
    setSelectedId(null);
    setRun(null);
    setError(null);
    userSetView("targets");
  }, [userSetView]);

  const openScan = useCallback(() => {
    setActiveRun(null);
    setSelectedId(null);
    setRun(null);
    setError(null);
    userSetView("scan");
  }, [userSetView]);

  const openPlaybooks = useCallback(() => {
    setActiveRun(null);
    setSelectedId(null);
    setRun(null);
    setError(null);
    userSetView("playbooks");
  }, [userSetView]);

  const openIssues = useCallback(() => {
    setSelectedId(null);
    userSetView("issues");
  }, [userSetView]);

  const openOverview = useCallback(() => {
    userSetView("overview");
    void refreshRuns();
  }, [refreshRuns, userSetView]);

  const openRunFromScan = useCallback((name: string) => {
    selectRun(name);
    initialViewAppliedRef.current = false;
  }, [selectRun]);

  return (
    <div className="min-h-screen bg-canvas text-foreground flex">
      <Sidebar
        view={view}
        onSelectView={(v) => {
          // Clicking a sidebar view always lands on that section's top level,
          // so leaving a specific issue's detail view and clicking "Issues"
          // returns to the full findings list.
          setSelectedId(null);
          if (v === "history") openHistory();
          else userSetView(v);
        }}
        issuesCount={run?.vulnerabilities.length ?? 0}
        agentCount={agentCount}
        runCount={runs?.count ?? 0}
        playbookCount={playbookCount}
        onOpenHistory={openHistory}
        dashboardMode={dashboardMode === true}
        canManageScans={canManageScans}
        onOpenDashboard={openDashboard}
        onOpenOverview={openOverview}
        onOpenTargets={openTargets}
        onOpenScan={openScan}
        onOpenPlaybooks={openPlaybooks}
      />

      <div className="flex-1 min-w-0">
        {/* Top bar */}
        <div className="border-b border-[var(--neutral-222)]">
          <div className="max-w-[88rem] mx-auto px-3 sm:px-6 py-4 flex items-center gap-1.5">
            <div className="flex items-center gap-1.5 opacity-90 lg:hidden">
              <img src="./logo.svg" alt="Phantom" className="w-10 h-8 object-cover" />
              <div className="text-base text-foreground font-medium tracking-tight">Phantom</div>
            </div>
            {run && <LiveIndicator finished={run.finished} />}
            <div className="ml-auto flex items-center gap-3">
              <ThemeToggle />
              {dashboardInfo && <LlmStatus info={dashboardInfo} />}
              {runs && !runs.locked && runs.runs.length > 0 && (
                <RunSwitcher
                  runs={runs}
                  activeRun={activeRun}
                  launchedName={runTitle(run?.summary.targets[0] ?? null, run?.summary.runName ?? run?.summary.runId ?? "Current run")}
                  onSelect={selectRun}
                />
              )}
            </div>
          </div>
        </div>

        <div className="max-w-[88rem] mx-auto px-3 sm:px-6 py-8 sm:py-12 space-y-6">
          {error && !run && view !== "history" && view !== "dashboard" && view !== "targets" && (
            <div className="rounded-lg px-4 py-3 flex gap-3 items-start border border-red-500/30 bg-red-500/5">
              <AlertCircle className="w-5 h-5 flex-shrink-0 mt-0.5 text-red-400" aria-hidden="true" />
              <p className="text-sm text-red-300">{error}</p>
            </div>
          )}

          {/* Keyed wrapper: re-mounts on every view / finding / run change so the
              page-in transition replays. */}
          <div
            key={`${activeRun ?? "launched"}:${view}:${selectedId ?? ""}`}
            className="animate-page-in space-y-6"
          >
          {dashboardMode && activeRun === null && view === "dashboard" ? (
            <DashboardHome
              info={dashboardInfo}
              runs={runs}
              onOpenTargets={openTargets}
              onOpenScan={openScan}
              onOpenRun={selectRun}
            />
          ) : dashboardMode && activeRun === null && view === "targets" ? (
            <TargetsView />
          ) : dashboardMode && activeRun === null && view === "scan" ? (
            <ScanView info={dashboardInfo} onOpenTargets={openTargets} onOpenRun={openRunFromScan} />
          ) : dashboardMode && activeRun === null && view === "playbooks" ? (
            <PlaybookView />
          ) : dashboardMode && activeRun === null && (view === "overview" || view === "issues" || view === "agents") ? (
            <RunSelectionPrompt section={view} onOpenHistory={openHistory} />
          ) : view === "history" ? (
            <div className="space-y-4">
              <div className="flex items-center gap-2">
                <History className="w-5 h-5 text-[var(--neutral-888)]" aria-hidden="true" />
                <h1 className="text-2xl font-semibold text-foreground">Past runs</h1>
              </div>
              <PastRunsView
                runs={runs}
                activeRun={activeRun}
                onSelectRun={selectRun}
                onDeleted={handleRunDeleted}
              />
            </div>
          ) : !run && !error ? (
            <div className="rounded-xl border border-[var(--neutral-222)] bg-[rgb(var(--contrast-rgb)/0.02)] p-10 text-center">
              <div className="w-6 h-6 mx-auto mb-3 rounded-full border-2 border-[var(--neutral-333)] border-t-white animate-spin" />
              <p className="text-sm text-[var(--neutral-888)]">Loading run data…</p>
            </div>
          ) : run && counts ? (
            <>
              <SummaryHeader summary={run.summary} />

              {/* Tab strip: shown on small screens where the sidebar is hidden. */}
              <div className="flex gap-5 border-b border-[var(--neutral-2a2a2a)] lg:hidden">
                <TabButton active={view === "overview"} onClick={() => userSetView("overview")}>
                  Pentest Overview
                </TabButton>
                <TabButton active={view === "issues"} onClick={() => userSetView("issues")}>
                  Issues{run.vulnerabilities.length > 0 ? ` (${run.vulnerabilities.length})` : ""}
                </TabButton>
                {agentCount > 0 && (
                  <TabButton active={view === "agents"} onClick={() => userSetView("agents")}>
                    Agents ({agentCount})
                  </TabButton>
                )}
              </div>

              {view === "overview" ? (
                <OverviewTab
                  summary={run.summary}
                  counts={counts}
                  total={run.vulnerabilities.length}
                  reportMarkdown={run.reportMarkdown}
                  raw={run.raw}
                  finished={run.finished}
                  runName={loadedRunName}
                  review={run.review}
                  dashboardMode={dashboardMode === true}
                  onOpenIssues={openIssues}
                />
              ) : view === "agents" && agentCount > 0 ? (
                <AgentsTab run={run} canSteer={canSteer} />
              ) : selected ? (
                <div className="space-y-4">
                  <button
                    onClick={() => setSelectedId(null)}
                    className="cursor-pointer inline-flex items-center gap-1.5 text-sm text-[var(--neutral-888)] hover:text-foreground transition-colors"
                  >
                    <ArrowLeft className="w-4 h-4" /> Back to all findings
                  </button>
                  <VulnerabilityDetail
                    vulnerability={selected}
                    runName={loadedRunName}
                    playbookId={
                      selected.playbook?.id && findPlaybookById(selected.playbook.id)
                        ? selected.playbook.id
                        : null
                    }
                    replayEnabled={!!loadedRunName}
                    playbookEnabled={dashboardMode === true && !!loadedRunName}
                    targetName={runTitle(run?.summary.targets[0] ?? null, run?.summary.runName ?? run?.summary.runId ?? "Current target")}
                  />
                </div>
              ) : (
                <FindingsList
                  vulnerabilities={run.vulnerabilities}
                  finished={run.finished}
                  onSelect={(id) => setSelectedId(id)}
                  runName={loadedRunName}
                  rejectionsEnabled={dashboardMode === true}
                  rejectionsVersion={rejectionsVersion}
                />
              )}
            </>
          ) : null}
          </div>
        </div>
      </div>
      <TrustToast message={TRUST_BANNER} />
    </div>
  );
}

function RunSelectionPrompt({
  section,
  onOpenHistory,
}: {
  section: "overview" | "issues" | "agents";
  onOpenHistory: () => void;
}) {
  const isAgents = section === "agents";
  const isOverview = section === "overview";
  return (
    <div className="flex min-h-[420px] items-center justify-center rounded-2xl border border-[var(--neutral-222)] bg-[rgb(var(--contrast-rgb)/0.02)] px-6 py-12 text-center">
      <div className="max-w-md">
        <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl border border-blue-400/25 bg-blue-500/10 text-blue-400">
          {isAgents ? (
            <Bot className="h-5 w-5" aria-hidden="true" />
          ) : isOverview ? (
            <LayoutDashboard className="h-5 w-5" aria-hidden="true" />
          ) : (
            <AlertCircle className="h-5 w-5" aria-hidden="true" />
          )}
        </div>
        <h1 className="mt-5 text-xl font-semibold text-foreground">
          Select a past run to view {isAgents ? "its agent graph" : isOverview ? "its overview" : "its issues"}
        </h1>
        <p className="mt-2 text-sm leading-6 text-[var(--neutral-888)]">
          This workspace is not attached to a scan yet. Choose a completed or live run from Past runs to open the
          existing Phantom viewer.
        </p>
        <button
          onClick={onOpenHistory}
          className="mt-6 inline-flex items-center gap-2 rounded-lg bg-blue-500 px-4 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-blue-400"
        >
          <History className="h-4 w-4" aria-hidden="true" />
          Browse past runs
        </button>
      </div>
    </div>
  );
}

function LlmStatus({ info }: { info: DashboardInfo }) {
  const model = info.llm.model ?? "not configured";
  return (
    <div
      className="hidden max-w-[260px] items-center gap-2 text-xs text-[var(--neutral-888)] sm:flex"
      title={info.llm.configured ? "LLM configured from PHANTOM_LLM" : "Set PHANTOM_LLM before scanning"}
    >
      <span
        className={`relative h-1.5 w-1.5 flex-shrink-0 rounded-full ${
          info.llm.configured ? "bg-emerald-400" : "bg-amber-400"
        }`}
      >
        {info.llm.configured && (
          <span className="absolute inset-0 animate-ping rounded-full bg-emerald-400 opacity-40" />
        )}
      </span>
      <span className="text-[var(--neutral-666)]">LLM</span>
      <span className="truncate font-mono text-[var(--neutral-aaa)]">{model}</span>
    </div>
  );
}

function RunSwitcher({
  runs,
  activeRun,
  launchedName,
  onSelect,
}: {
  runs: RunsPayload;
  activeRun: string | null;
  launchedName: string;
  onSelect: (name: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const activeEntry = runs.runs.find((r) => r.name === activeRun);
  const current = activeEntry ? runTitle(activeEntry.target, activeEntry.name) : launchedName;
  return (
    <div className="relative">
      <button
        onClick={() => setOpen((o) => !o)}
        onBlur={() => setTimeout(() => setOpen(false), 150)}
        aria-label="Switch pentest"
        className="flex items-center gap-2 rounded-lg border border-[var(--neutral-3a3a3a)] bg-[rgb(var(--contrast-rgb)/0.05)] px-3 py-2 text-sm text-foreground transition-colors hover:border-[var(--neutral-555)] hover:bg-[rgb(var(--contrast-rgb)/0.09)]"
      >
        <History className="h-4 w-4 flex-shrink-0 text-[var(--neutral-888)]" aria-hidden="true" />
        <span className="flex-shrink-0 text-[var(--neutral-888)]">Pentest</span>
        <span className="max-w-[260px] truncate font-medium">{current}</span>
        <ChevronDown className="h-4 w-4 flex-shrink-0 text-[var(--neutral-aaa)]" aria-hidden="true" />
      </button>
      {open && (
        <div
          className="absolute right-0 z-50 mt-2 max-h-96 w-96 overflow-y-auto rounded-xl py-1.5 shadow-2xl"
          style={{ border: "1px solid var(--neutral-3a3a3a)", background: "var(--neutral-0a0a0a)" }}
        >
          <div className="border-b border-[var(--neutral-222)] px-3 py-2 text-[11px] font-semibold uppercase tracking-wide text-[var(--neutral-666)]">
            Switch pentest
          </div>
          {runs.runs.map((r) => {
            const active = r.name === activeRun;
            return (
              <button
                key={r.name}
                onMouseDown={() => onSelect(r.name)}
                className={`flex w-full items-center gap-2 px-3 py-2.5 text-left text-sm transition-colors hover:bg-[rgb(var(--contrast-rgb)/0.06)] ${
                  active ? "bg-[rgb(var(--contrast-rgb)/0.04)] text-foreground" : "text-[var(--neutral-aaa)]"
                }`}
              >
                <span className="min-w-0 flex-1">
                  <span className="block truncate font-medium">{runTitle(r.target, r.name)}</span>
                  {r.target && <span className="block truncate font-mono text-xs text-[var(--neutral-666)]">{r.target}</span>}
                </span>
                {active && <span className="h-2 w-2 flex-shrink-0 rounded-full bg-blue-400" />}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

function LiveIndicator({ finished }: { finished: boolean }) {
  if (finished) {
    return (
      <span className="ml-3 inline-flex items-center gap-1.5 text-xs text-[var(--neutral-888)]">
        <span className="w-1.5 h-1.5 rounded-full bg-[var(--neutral-555)]" />
        Complete
      </span>
    );
  }
  return (
    <span className="ml-3 inline-flex items-center gap-1.5 text-xs text-blue-400">
      <span className="relative flex h-1.5 w-1.5">
        <span className="absolute inline-flex h-full w-full rounded-full bg-blue-400 opacity-75 animate-ping" />
        <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-blue-400" />
      </span>
      Live
    </span>
  );
}

function formatDuration(seconds: number | null): string | null {
  if (seconds == null) return null;
  if (seconds < 60) return `${seconds}s`;
  const m = Math.floor(seconds / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

function SummaryHeader({ summary }: { summary: ParsedRunSummary }) {
  const duration = formatDuration(summary.durationSeconds);
  return (
    <div>
      <h1 className="text-2xl font-semibold text-foreground">
        {runTitle(summary.targets[0] ?? null, summary.runName ?? summary.runId ?? "Pentest results")}
      </h1>
      <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-[var(--neutral-888)]">
        {summary.targets.length > 0 && (
          <span className="font-mono text-[var(--neutral-aaa)]">{summary.targets.join(", ")}</span>
        )}
        {summary.scanMode && <Meta label={summary.scanMode} />}
        {duration && <Meta label={duration} />}
        {summary.status && <Meta label={summary.status} />}
      </div>
    </div>
  );
}

function Meta({ label }: { label: string }) {
  return (
    <>
      <span className="text-[var(--neutral-333)]">·</span>
      <span className="capitalize">{label}</span>
    </>
  );
}

type TriageStatus = "signed" | "rejected" | "needs-review";
type TriageFilter = "all" | TriageStatus;

function FindingsList({
  vulnerabilities,
  finished,
  onSelect,
  runName = null,
  rejectionsEnabled = false,
  rejectionsVersion = 0,
}: {
  vulnerabilities: Vulnerability[];
  finished: boolean;
  onSelect: (id: string) => void;
  runName?: string | null;
  rejectionsEnabled?: boolean;
  // Only used to re-render rows when the rejection registry changes.
  rejectionsVersion?: number;
}) {
  void rejectionsVersion;
  const [filter, setFilter] = useState<TriageFilter>("all");
  const sorted = [...vulnerabilities].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );
  if (sorted.length === 0) {
    return (
      <div className="space-y-4">
        <div className="rounded-xl border border-[var(--neutral-222)] bg-[rgb(var(--contrast-rgb)/0.02)] p-8 text-center text-sm text-[var(--neutral-888)]">
          {finished ? "No findings in this run." : "No findings yet. The pentest is still running…"}
        </div>
      </div>
    );
  }

  const decorated = sorted.map((v) => {
    const playbook = rejectionsEnabled ? findPlaybook(runName, v) : null;
    const markedPlaybook = findPlaybookById(v.playbook?.id);
    const rejected = rejectionsEnabled ? findRejection(runName, v) : null;
    const playbookRegression =
      v.playbook?.status === "reproduced" && !!markedPlaybook?.confirmedByReplayId;
    const signedRecord = playbook ?? markedPlaybook;
    const signed = !rejected && signedRecord?.confirmedByReplayId ? signedRecord : null;
    const signedByPlaybook = !rejected && (!!signed || playbookRegression);
    const status: TriageStatus = rejected ? "rejected" : signedByPlaybook ? "signed" : "needs-review";
    return { v, signed, playbookRegression, rejected, status };
  });
  const counts = {
    signed: decorated.filter((d) => d.status === "signed").length,
    rejected: decorated.filter((d) => d.status === "rejected").length,
    needsReview: decorated.filter((d) => d.status === "needs-review").length,
  };
  const visible =
    filter === "all" ? decorated : decorated.filter((d) => d.status === filter);

  return (
    <div className="space-y-3">
      {rejectionsEnabled && (
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="inline-flex items-center gap-1 rounded-xl border border-[var(--neutral-242424)] bg-[rgb(var(--contrast-rgb)/0.02)] p-1">
            {(
              [
                ["all", "All", sorted.length],
                ["needs-review", "Needs review", counts.needsReview],
                ["signed", "Signed", counts.signed],
                ["rejected", "Rejected", counts.rejected],
              ] as [TriageFilter, string, number][]
            ).map(([value, label, count]) => {
              const active = filter === value;
              return (
                <button
                  key={value}
                  type="button"
                  onClick={() => setFilter(value)}
                  className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold transition-colors ${active ? "bg-foreground text-inverse" : "text-[var(--neutral-888)] hover:text-foreground"}`}
                >
                  {label}
                  <span className={`rounded-full px-1.5 py-0.5 text-[10px] ${active ? "bg-black/10 text-inverse/70" : "bg-foreground/[0.06] text-[var(--neutral-888)]"}`}>{count}</span>
                </button>
              );
            })}
          </div>
          <div className="flex items-center gap-3 text-xs text-[var(--neutral-777)]">
            <span className="inline-flex items-center gap-1.5"><span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />{counts.signed} signed</span>
            <span className="inline-flex items-center gap-1.5"><span className="h-1.5 w-1.5 rounded-full bg-amber-400" />{counts.rejected} rejected</span>
            <span className="inline-flex items-center gap-1.5"><span className="h-1.5 w-1.5 rounded-full bg-[var(--neutral-555)]" />{counts.needsReview} awaiting review</span>
          </div>
        </div>
      )}

      {visible.length === 0 ? (
        <div className="rounded-xl border border-[var(--neutral-222)] bg-[rgb(var(--contrast-rgb)/0.02)] p-8 text-center text-sm text-[var(--neutral-888)]">
          No findings in this view.
        </div>
      ) : (
        <div className="space-y-2">
          {visible.map(({ v, signed, playbookRegression, rejected }) => (
            <button
              key={v.id}
              onClick={() => onSelect(v.id)}
              className={`animate-card-in cursor-pointer w-full text-left rounded-lg border ${rejected ? "border-amber-400/25 hover:border-amber-400/40" : "border-[var(--neutral-222)] hover:border-[var(--neutral-444)]"} bg-[rgb(var(--contrast-rgb)/0.02)] px-4 py-3 transition-colors flex items-center gap-3`}
            >
              <span className={`w-2.5 h-2.5 rounded-full flex-shrink-0 ${getSeverityDot(v.severity)}`} aria-hidden="true" />
              <span className="flex-1 min-w-0">
                <span className="block text-sm font-medium text-foreground truncate">{v.title}</span>
                {v.target && (
                  <span className="block text-xs text-[var(--neutral-666)] font-mono truncate">{v.target}</span>
                )}
                {playbookRegression && !rejected && (
                  <span
                    title={
                      v.playbook?.replay_id
                        ? `Already signed in the Playbook · confirmed replay ${v.playbook.replay_id}`
                        : "Already signed in the Playbook"
                    }
                    className="mt-1 inline-flex items-center gap-1 text-[11px] font-medium text-emerald-300"
                  >
                    <BookMarked className="h-3 w-3" aria-hidden="true" />
                    Playbook reproduced
                  </span>
                )}
                {signed && !playbookRegression && (
                  <span
                    title={
                      signed.confirmedByReplayId
                        ? `Signed by ${signed.auditorName} · confirmed replay ${signed.confirmedByReplayId}`
                        : `Signed by ${signed.auditorName}`
                    }
                    className="mt-1 inline-flex items-center gap-1 text-[11px] font-medium text-emerald-300"
                  >
                    <CheckCircle2 className="h-3 w-3" aria-hidden="true" />
                    Signed
                  </span>
                )}
                {rejected && (
                  <span
                    title={`Rejected by ${rejected.auditorName}: ${rejected.reason}`}
                    className="mt-1 inline-flex items-center gap-1 text-[11px] font-medium text-amber-300"
                  >
                    <Ban className="h-3 w-3" aria-hidden="true" />
                    Rejected (false positive)
                  </span>
                )}
              </span>
              <span
                className={`text-xs font-semibold px-2 py-0.5 rounded-full border capitalize ${SEVERITY_COLORS[v.severity]}`}
              >
                {v.severity}
              </span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

/** Strip a single leading markdown heading (report sections embed their own). */
function stripLeadingHeading(md: string): string {
  return md.replace(/^\s*#{1,6}[ \t]+.*(?:\r?\n)+/, "").trimStart();
}

function dedupeHeadings(md: string): string {
  const out: string[] = [];
  let lastHeading: string | null = null;
  for (const line of md.split("\n")) {
    const m = line.match(/^#{1,6}\s+(.*)$/);
    if (m) {
      const norm = m[1].trim().toLowerCase();
      if (norm === lastHeading) continue;
      lastHeading = norm;
    } else if (line.trim() !== "") {
      lastHeading = null;
    }
    out.push(line);
  }
  return out.join("\n");
}

/** Primary local CTA: download the completed run as a PDF. */
function DownloadReportCta({
  runName,
  initialReview,
}: {
  runName: string | null;
  initialReview: RunReviewSummary;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [review, setReview] = useState(initialReview);

  const refreshReview = async () => {
    if (!runName) return initialReview;
    const latest = await fetchRunSummary(runName);
    setReview(latest.review);
    return latest.review;
  };

  useEffect(() => {
    setReview(initialReview);
    void refreshReview().catch(() => {
      /* The server enforces the same gate if the status refresh is unavailable. */
    });
  }, [runName, initialReview]);

  const download = async () => {
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      const latestReview = await refreshReview();
      if (!latestReview.reportReady) {
        throw new Error("Review at least one finding before exporting the report.");
      }
      const response = await fetch(reportPdfUrl(runName), {
        credentials: "same-origin",
        cache: "no-store",
      });
      if (!response.ok) {
        let detail = "Could not download the PDF report.";
        try {
          const payload = (await response.json()) as { error?: string };
          if (payload.error === "run_not_finished") detail = "The run is not finished yet.";
          if (payload.error === "review_required") detail = "Review at least one finding before exporting the report.";
          if (payload.error === "forbidden") detail = "The viewer session expired. Reopen the viewer and try again.";
        } catch {
          /* Keep the user-facing fallback above. */
        }
        throw new Error(detail);
      }

      const contentType = response.headers.get("Content-Type") ?? "";
      if (!contentType.toLowerCase().includes("application/pdf")) {
        throw new Error("The server did not return a PDF report.");
      }

      const blob = await response.blob();
      const disposition = response.headers.get("Content-Disposition") ?? "";
      const filename = disposition.match(/filename="?([^";]+)"?/i)?.[1] ?? "phantom-report.pdf";
      const objectUrl = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = objectUrl;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not download the PDF report.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="rounded-xl border border-[var(--neutral-252525)] bg-[rgb(var(--contrast-rgb)/0.02)] px-4 py-3.5">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex min-w-0 items-center gap-3">
        <div
          className="flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-lg border border-blue-400/25 bg-blue-400/10"
        >
          <Download className="h-4 w-4 text-blue-400" aria-hidden="true" />
        </div>
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold text-foreground">Download the PDF report for this run</p>
          <p className="mt-0.5 text-xs text-[var(--neutral-888)]">
            Generate the report locally and save it directly to your device.
          </p>
        </div>
        </div>
        <button
          type="button"
          onClick={() => void download()}
          disabled={busy || !review.reportReady}
          title={!review.reportReady ? "Review at least one finding to unlock the report." : undefined}
          className="inline-flex flex-shrink-0 cursor-pointer items-center gap-2 rounded-lg bg-blue-500 px-3.5 py-2 text-xs font-semibold text-white shadow-sm transition-colors hover:bg-blue-400 disabled:cursor-not-allowed disabled:opacity-45"
        >
          {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" /> : <Download className="h-3.5 w-3.5" aria-hidden="true" />}
          {busy ? "Preparing…" : "Download PDF"}
        </button>
      </div>
      {!error && !review.reportReady && (
        <p className="mt-2 text-xs text-[var(--neutral-888)]">
          Report locked until one candidate is signed or rejected · {review.pendingCount} awaiting review
        </p>
      )}
      {!error && review.reportReady && review.signedCount === 0 && review.rejectedCount > 0 && (
        <p className="mt-2 text-xs text-[var(--neutral-888)]">
          No findings were signed; the export will contain the reviewed assessment with no confirmed findings.
        </p>
      )}
      {error && <p className="mt-2 text-xs text-red-300">{error}</p>}
    </div>
  );
}

function OverviewTab({
  summary,
  counts,
  total,
  reportMarkdown,
  raw,
  finished,
  runName,
  review,
  dashboardMode,
  onOpenIssues,
}: {
  summary: ParsedRunSummary;
  counts: Record<VulnerabilitySeverity, number>;
  total: number;
  reportMarkdown: string | null;
  raw: Record<string, unknown>;
  finished: boolean;
  runName: string | null;
  review: RunReviewSummary;
  dashboardMode: boolean;
  onOpenIssues: () => void;
}) {
  const sections = (
    [
      ["Executive Summary", summary.executiveSummary],
      ["Technical Analysis", summary.technicalAnalysis],
      ["Methodology", summary.methodology],
      ["Recommendations", summary.recommendations],
    ] as const
  )
    .filter(([, content]) => !!content)
    .map(([title, content]) => ({ title, content: stripLeadingHeading(content as string) }));

  return (
    <div className="space-y-6">
      <div className="animate-card-in">
        <RunDetails raw={raw} durationSeconds={summary.durationSeconds} />
      </div>

      {total > 0 && (
        <div className="animate-card-in">
          <button
            type="button"
            onClick={onOpenIssues}
            className="dashboard-button group w-full cursor-pointer rounded-xl border border-[var(--neutral-222)] bg-[rgb(var(--contrast-rgb)/0.02)] p-5 text-left transition-all duration-300 ease-out hover:-translate-y-0.5 hover:border-blue-400/40 hover:bg-[rgba(59,130,246,0.045)] hover:shadow-[0_12px_32px_rgba(0,0,0,0.28)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400/70 focus-visible:ring-offset-2 focus-visible:ring-offset-black"
            aria-label={`View all ${total} issues for this run`}
          >
            <IssueSeveritySummary findings={{ total, ...counts }} />
            <span className="mt-4 inline-flex items-center gap-1.5 text-xs font-semibold text-[var(--neutral-777)] transition-colors duration-300 group-hover:text-blue-300">
              View all issues
              <ArrowRight className="h-3.5 w-3.5 transition-transform duration-300 group-hover:translate-x-1" aria-hidden="true" />
            </span>
          </button>
        </div>
      )}

      {/* Primary CTA: hidden until the run is finished so only a complete
          report is downloaded. */}
      {finished && (
        <div className="animate-card-in">
          <DownloadReportCta runName={runName} initialReview={review} />
        </div>
      )}

      {!finished && dashboardMode && runName && (
        <div className="animate-card-in">
          <StopScanCta runName={runName} />
        </div>
      )}

      {sections.length > 0 ? (
        <div className="animate-card-in rounded-xl border border-[var(--neutral-222)] bg-[rgb(var(--contrast-rgb)/0.02)] p-5 space-y-8">
          {sections.map((s) => (
            <ContentSection key={s.title} title={s.title} content={s.content} />
          ))}
        </div>
      ) : reportMarkdown ? (
        <div className="animate-card-in rounded-xl border border-[var(--neutral-222)] bg-[rgb(var(--contrast-rgb)/0.02)] p-5">
          <ContentSection content={dedupeHeadings(reportMarkdown)} />
        </div>
      ) : (
        total === 0 && (
          <p className="text-sm text-[var(--neutral-888)]">No summary available for this run yet.</p>
        )
      )}

    </div>
  );
}

function StopScanCta({ runName }: { runName: string }) {
  const [stopping, setStopping] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const requestStop = async () => {
    if (stopping) return;
    setStopping(true);
    setError(null);
    try {
      const scans = await fetchScans();
      const active = scans.active ?? scans.jobs.find(
        (job) =>
          job.run_name === runName && (job.status === "preparing" || job.status === "running")
      );
      if (!active) {
        setError("No active dashboard scan was found for this run.");
        setStopping(false);
        return;
      }
      const result = await stopScan(active.id);
      if (!result.ok) {
        setError(result.message);
        setStopping(false);
      }
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not stop this scan.");
      setStopping(false);
    }
  };

  return (
    <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-amber-400/20 bg-amber-400/[0.04] px-5 py-4">
      <div className="flex items-start gap-3">
        <Square className="mt-0.5 h-4 w-4 flex-shrink-0 text-amber-300" aria-hidden="true" />
        <div>
          <p className="text-sm font-semibold text-foreground">Scan in progress</p>
          <p className="mt-1 text-xs text-[var(--neutral-888)]">
            Stop the live Phantom run gracefully. Partial evidence remains available for review.
          </p>
          {error && <p className="mt-2 text-xs text-red-300">{error}</p>}
        </div>
      </div>
      <button
        type="button"
        onClick={() => void requestStop()}
        disabled={stopping}
        className="dashboard-button inline-flex items-center gap-2 rounded-lg border border-amber-300/30 px-3.5 py-2 text-sm font-semibold text-amber-200 transition-all hover:border-amber-200/60 hover:bg-amber-300/10 disabled:cursor-wait disabled:opacity-60"
      >
        {stopping ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Square className="h-3.5 w-3.5 fill-current" aria-hidden="true" />}
        {stopping ? "Stopping…" : "Stop scan"}
      </button>
    </div>
  );
}

function TabButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className={`cursor-pointer relative pb-2.5 text-sm font-semibold transition-colors ${
        active ? "text-foreground" : "text-[var(--neutral-666)] hover:text-foreground"
      }`}
    >
      {children}
      {active && <span className="absolute bottom-0 inset-x-0 h-0.5 bg-foreground rounded-full" />}
    </button>
  );
}

function AgentsTab({ run, canSteer }: { run: LoadedRun; canSteer: boolean }) {
  const { agents, events } = run.transcript;
  const graphAgents = useMemo(() => buildGraphAgents(agents, events), [agents, events]);
  // Clicking a graph node opens the agent's transcript in a modal; no node selected means no modal.
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const selectedAgent = selectedId ? (agents.find((a) => a.id === selectedId) ?? null) : null;

  // Live steering is only possible in-process (canSteer) while the scan runs.
  const steerable = canSteer && !run.finished;

  return (
    <div className="space-y-5">
      <div className="rounded-xl border border-[var(--neutral-222)] bg-[rgb(var(--contrast-rgb)/0.02)] p-5">
        <div className="flex items-center gap-2">
          <Bot className="w-4 h-4 text-[var(--neutral-888)]" aria-hidden="true" />
          <h2 className="text-sm font-semibold text-foreground">Agent graph</h2>
          <span className="text-xs text-[var(--neutral-666)]">
            {agents.length} agent{agents.length === 1 ? "" : "s"}
          </span>
        </div>
        <p className="mt-1 mb-4 text-xs text-[var(--neutral-666)]">
          Click an agent to open its full transcript.
        </p>
        <div className="h-[480px] rounded-lg border border-[var(--neutral-1a1a1a)] overflow-hidden">
          <AgentGraph
            agents={graphAgents}
            selectedAgentId={selectedId}
            onSelectAgent={(id) => setSelectedId(id)}
            eventsLoaded
            eventsEmpty={graphAgents.size === 0}
            scanCompleted={run.finished}
          />
        </div>
      </div>

      {/* Live steering: only in-process while the scan runs. Otherwise omitted. */}
      {steerable && <ScanPromptComposer agents={agents} />}

      <AgentDetailModal
        open={selectedAgent !== null}
        agent={selectedAgent}
        events={events}
        steerable={steerable}
        onClose={() => setSelectedId(null)}
      />
    </div>
  );
}
