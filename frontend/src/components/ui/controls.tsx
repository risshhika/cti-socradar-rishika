import type { ReactNode } from "react";
import { Search, X } from "lucide-react";
import s from "./controls.module.css";

/** One filter row above everything it scopes. */
export function FilterBar({ children }: { children: ReactNode }) {
  return (
    <div className={s.bar} role="toolbar" aria-label="Filters">
      {children}
    </div>
  );
}

export function SearchInput({ value, onChange, placeholder }: { value: string; onChange: (v: string) => void; placeholder: string }) {
  return (
    <label className={s.search}>
      <Search size={15} />
      <input
        className={s.input}
        type="search"
        value={value}
        placeholder={placeholder}
        aria-label={placeholder}
        onChange={(e) => onChange(e.target.value)}
      />
    </label>
  );
}

export function Select({
  value, onChange, options, label,
}: { value: string; onChange: (v: string) => void; options: { value: string; label: string }[]; label: string }) {
  return (
    <select className={s.select} value={value} onChange={(e) => onChange(e.target.value)} aria-label={label}>
      {options.map((o) => (
        <option key={o.value} value={o.value}>
          {o.label}
        </option>
      ))}
    </select>
  );
}

export function Segmented<T extends string>({
  value, onChange, options, label,
}: { value: T; onChange: (v: T) => void; options: { value: T; label: string }[]; label: string }) {
  return (
    <div className={s.seg} role="group" aria-label={label}>
      {options.map((o) => (
        <button key={o.value} aria-pressed={o.value === value} onClick={() => onChange(o.value)}>
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function Toggle({ pressed, onChange, children }: { pressed: boolean; onChange: (v: boolean) => void; children: ReactNode }) {
  return (
    <button className={s.toggle} aria-pressed={pressed} onClick={() => onChange(!pressed)}>
      {children}
    </button>
  );
}

export interface ActiveFilter {
  key: string;
  label: string;
  onRemove: () => void;
}

export function FilterChips({ filters, onClear, count }: { filters: ActiveFilter[]; onClear: () => void; count?: ReactNode }) {
  if (!filters.length) return count ? <div className={s.chips}>{count}</div> : null;
  return (
    <div className={s.chips}>
      {count}
      {filters.map((f) => (
        <span key={f.key} className={s.chip}>
          {f.label}
          <button onClick={f.onRemove} aria-label={`Remove filter ${f.label}`}>
            <X size={12} />
          </button>
        </span>
      ))}
      <button className={s.clear} onClick={onClear}>
        Clear all
      </button>
    </div>
  );
}

export function StatStrip({ items }: { items: { label: string; value: ReactNode; sub?: ReactNode }[] }) {
  return (
    <div className={s.stats}>
      {items.map((i) => (
        <div key={i.label} className={s.stat}>
          <div className={s.statLabel}>{i.label}</div>
          <div className={s.statValue}>{i.value}</div>
          {i.sub && <div className={s.statSub}>{i.sub}</div>}
        </div>
      ))}
    </div>
  );
}
