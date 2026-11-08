import { createContext, useCallback, useContext, useLayoutEffect, useMemo, useState, type ReactNode } from "react";
import { readTokens, type Tokens } from "./echartsTheme";

export type Theme = "dark" | "light";

interface ThemeCtx {
  theme: Theme;
  toggleTheme: () => void;
  present: boolean;
  togglePresent: () => void;
  tokens: Tokens;
  chartTheme: string;
}

const Ctx = createContext<ThemeCtx | null>(null);

function initialTheme(): Theme {
  return document.documentElement.dataset.theme === "light" ? "light" : "dark";
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setTheme] = useState<Theme>(initialTheme);
  const [present, setPresent] = useState(() => document.documentElement.dataset.present === "1");
  const [tokens, setTokens] = useState<Tokens>(() => readTokens());

  // Apply before paint so charts re-init with the right colours on the same frame.
  useLayoutEffect(() => {
    document.documentElement.dataset.theme = theme;
    try {
      localStorage.setItem("ctiops-theme", theme);
    } catch {
      /* storage unavailable: theme still applies for this session */
    }
    setTokens(readTokens());
  }, [theme]);

  useLayoutEffect(() => {
    if (present) document.documentElement.dataset.present = "1";
    else delete document.documentElement.dataset.present;
  }, [present]);

  const toggleTheme = useCallback(() => setTheme((t) => (t === "dark" ? "light" : "dark")), []);
  const togglePresent = useCallback(() => setPresent((p) => !p), []);

  const value = useMemo(
    () => ({ theme, toggleTheme, present, togglePresent, tokens, chartTheme: `ti-${theme}` }),
    [theme, toggleTheme, present, togglePresent, tokens],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useTheme(): ThemeCtx {
  const v = useContext(Ctx);
  if (!v) throw new Error("useTheme must be used inside ThemeProvider");
  return v;
}
