/** Best-effort local viewer event reporting. No cloud URLs or user data. */
export function track(
  event: string,
  props: Record<string, string | undefined> = {}
): void {
  try {
    const body: Record<string, string> = { event };
    for (const [key, value] of Object.entries(props)) {
      if (value !== undefined) body[key] = value;
    }
    const payload = JSON.stringify(body);
    if (typeof navigator !== "undefined" && navigator.sendBeacon) {
      navigator.sendBeacon("/api/event", payload);
    } else {
      void fetch("/api/event", { method: "POST", body: payload, keepalive: true });
    }
  } catch {
    // Viewer telemetry must never affect the local report experience.
  }
}
