import { useEffect, useState } from "react";
import { Moon, Sun } from "lucide-react";

const STORAGE_KEY = "phantom_theme";

export default function ThemeToggle() {
  const [light, setLight] = useState(() => document.documentElement.dataset.theme === "light");

  useEffect(() => {
    document.documentElement.dataset.theme = light ? "light" : "dark";
    try { localStorage.setItem(STORAGE_KEY, light ? "light" : "dark"); } catch { /* Session-only when storage is unavailable. */ }
  }, [light]);

  useEffect(() => {
    const sync = (event: StorageEvent) => {
      if (event.key === STORAGE_KEY) setLight(event.newValue === "light");
    };
    window.addEventListener("storage", sync);
    return () => window.removeEventListener("storage", sync);
  }, []);

  return (
    <button
      type="button"
      role="switch"
      aria-checked={light}
      aria-label="Light mode"
      title={light ? "Switch to dark mode" : "Switch to light mode"}
      className="theme-toggle"
      onClick={() => setLight((value) => !value)}
    >
      <Sun aria-hidden="true" className={light ? "theme-icon-active" : ""} />
      <Moon aria-hidden="true" className={!light ? "theme-icon-active" : ""} />
    </button>
  );
}
