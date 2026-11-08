import { useCallback } from 'react'
import { useSearchParams } from 'react-router-dom'

/** URL-backed filter state so views are shareable. */
export function useFilters<K extends string>(defaults: Partial<Record<K, string>> = {}) {
  const [sp, setSp] = useSearchParams()
  const get = useCallback((k: K): string => sp.get(k) ?? defaults[k] ?? '', [sp, defaults])
  const set = useCallback((k: K, v: string | number | boolean | null | undefined, resetPage = true) => {
    setSp((prev) => {
      const next = new URLSearchParams(prev)
      if (v === undefined || v === null || v === '' || v === false) next.delete(k); else next.set(k, String(v))
      if (resetPage && k !== 'page') next.delete('page')
      return next
    }, { replace: true })
  }, [setSp])
  const clear = useCallback(() => setSp(new URLSearchParams(), { replace: true }), [setSp])
  const page = Number(sp.get('page') ?? 1)
  return { get, set, clear, page, setPage: (p: number) => set('page' as K, p, false), raw: sp }
}
