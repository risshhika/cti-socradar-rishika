import { formatDistanceToNowStrict, format, parseISO } from 'date-fns'

export const fmtInt = (n: number | null | undefined) => (n == null ? '–' : new Intl.NumberFormat('en-US').format(n))
export const fmtPct = (n: number | null | undefined, digits = 0) => (n == null ? '–' : `${(n * 100).toFixed(digits)}%`)
export const fmtUsd = (n: number | null | undefined) => (n == null ? '–' : new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD', maximumFractionDigits: 0 }).format(n))
export const fmtDate = (s: string | null | undefined, pattern = 'yyyy-MM-dd') => { if (!s) return '–'; try { return format(parseISO(s), pattern) } catch { return s } }
export const fmtDateTime = (s: string | null | undefined) => fmtDate(s, 'yyyy-MM-dd HH:mm')
export const fmtAgo = (s: string | null | undefined) => { if (!s) return '–'; try { return formatDistanceToNowStrict(parseISO(s), { addSuffix: true }) } catch { return s } }
export const fmtDuration = (sec: number | null | undefined) => { if (sec == null) return '–'; if (sec < 60) return `${sec.toFixed(0)}s`; const m = Math.floor(sec / 60); return `${m}m ${Math.round(sec - m * 60)}s` }
export const fmtMonth = (ym: string) => { try { return format(parseISO(`${ym}-01`), 'MMM yyyy') } catch { return ym } }
export const truncate = (s: string | null | undefined, n = 60) => (!s ? '' : s.length > n ? `${s.slice(0, n - 1)}…` : s)
export const cx = (...parts: (string | false | null | undefined)[]) => parts.filter(Boolean).join(' ')
