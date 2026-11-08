/** Formatting helpers for chart tooltips (ported from Mintverse lib/format.ts). */
const nf = new Intl.NumberFormat("en-US");

/** Chart tooltips render HTML and many labels come from outside sources: escape them first. */
export const escapeHtml = (s: unknown) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

export const fmtNum = (n: number | null | undefined) => (n == null ? "—" : nf.format(n));

export function fmtDay(s: string | null | undefined, opts: Intl.DateTimeFormatOptions = { month: "short", day: "numeric", year: "numeric" }) {
  if (!s) return "—";
  const d = new Date(s.length === 10 ? `${s}T00:00:00Z` : s.length === 7 ? `${s}-01T00:00:00Z` : s);
  return Number.isNaN(d.getTime()) ? s : d.toLocaleDateString("en-US", { timeZone: "UTC", ...opts });
}

export const fmtYm = (ym: string) => fmtDay(ym, { month: "short", year: "2-digit" });

/** Is this change good or bad news? For threat counts up is bad; `null` means neutral. */
export function deltaTone(delta: number | null | undefined, upIsBad: boolean | null = true): "bad" | "good" | "flat" {
  if (!delta || upIsBad == null) return "flat";
  return delta > 0 === upIsBad ? "bad" : "good";
}

export function downloadCsv(filename: string, header: string[], rows: (string | number | null | undefined)[][]) {
  const esc = (v: unknown) => {
    const s = v == null ? "" : String(v);
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const csv = [header, ...rows].map((r) => r.map(esc).join(",")).join("\n");
  const url = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
  const a = Object.assign(document.createElement("a"), { href: url, download: filename });
  a.click();
  URL.revokeObjectURL(url);
}
