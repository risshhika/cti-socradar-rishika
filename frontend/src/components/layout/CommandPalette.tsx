import { useEffect, useState } from 'react'
import { Command } from 'cmdk'
import * as Dialog from '@radix-ui/react-dialog'
import { useNavigate } from 'react-router-dom'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Boxes, Building2, FileSearch, Loader2, Moon, Play, Presentation, Search, Users } from 'lucide-react'
import s from '../ui/CommandPalette.module.css'
import { NAV } from './nav'
import { api } from '../../lib/api'
import { useTheme } from '../../theme/ThemeProvider'
import { Kbd } from '../ui'
import { flag } from '../../charts/countries'

function useDebounced<T>(v: T, ms = 200) {
  const [d, setD] = useState(v)
  useEffect(() => { const id = setTimeout(() => setD(v), ms); return () => clearTimeout(id) }, [v, ms])
  return d
}

/** ⌘K palette (ported from Mintverse): jump to any page, search entities across both modules, run actions. */
export function CommandPalette({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const [q, setQ] = useState('')
  const dq = useDebounced(q.trim())
  const navigate = useNavigate()
  const qc = useQueryClient()
  const { toggleTheme, togglePresent } = useTheme()
  const enabled = open && dq.length >= 2
  const actors = useQuery({ queryKey: ['palette', 'actors', dq], queryFn: () => api.landscape.actors({ q: dq }), enabled })
  const campaigns = useQuery({ queryKey: ['palette', 'campaigns', dq], queryFn: () => api.phishing.campaigns({ q: dq }), enabled })
  const victims = useQuery({ queryKey: ['palette', 'victims', dq], queryFn: () => api.landscape.victims({ q: dq, size: 6 }), enabled })
  const kits = useQuery({ queryKey: ['palette', 'kits'], queryFn: api.phishing.kits, enabled: open })
  useEffect(() => { if (!open) setQ('') }, [open])
  const go = (fn: () => void) => { onOpenChange(false); fn() }
  const fetching = actors.isFetching || campaigns.isFetching || victims.isFetching
  const kitHits = dq.length >= 2 ? (kits.data ?? []).filter((k) => `${k.name} ${k.family ?? ''} ${k.slug}`.toLowerCase().includes(dq.toLowerCase())).slice(0, 5) : []
  const run = (name: string) => api.pipelines.trigger(name).then(() => qc.invalidateQueries({ queryKey: ['pipelines'] })).catch(() => undefined)
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className={s.overlay} />
        <Dialog.Content className={s.content} aria-label="Command palette" aria-describedby={undefined}>
          <Dialog.Title className="sr-only">Search and commands</Dialog.Title>
          <Command label="Search" shouldFilter={!dq}>
            <div className={s.inputRow}>
              <Search size={16} />
              <Command.Input className={s.input} value={q} onValueChange={setQ} placeholder="Actor, campaign, victim, kit, or a page…" autoFocus />
              {fetching && <Loader2 size={14} className="spin" />}
              <Kbd>esc</Kbd>
            </div>
            <Command.List className={s.list}>
              <Command.Empty className={s.empty}>{q.trim().length < 2 ? 'Type at least two characters' : 'Nothing matches'}</Command.Empty>
              {!!actors.data?.length && (
                <Command.Group heading="Ransomware actors" className={s.group}>
                  {actors.data.slice(0, 6).map((a) => (
                    <Command.Item key={a.id} className={s.item} value={`actor-${a.slug}`} onSelect={() => go(() => navigate(`/landscape/actors/${encodeURIComponent(a.slug)}`))}>
                      <Users size={15} /><div className={s.itemText}><span className={s.itemTitle}>{a.name}</span><span className={s.itemSub}>{a.victim_count_window} victims in window · {a.victim_count_scope} in scope · {a.status}</span></div>
                    </Command.Item>
                  ))}
                </Command.Group>
              )}
              {!!campaigns.data?.length && (
                <Command.Group heading="Phishing campaigns" className={s.group}>
                  {campaigns.data.slice(0, 6).map((c) => (
                    <Command.Item key={c.id} className={s.item} value={`campaign-${c.id}`} onSelect={() => go(() => navigate(`/phishing/campaigns/${c.id}`))}>
                      <Boxes size={15} /><div className={s.itemText}><span className={s.itemTitle}>{c.name} <span className="muted">{c.brand ?? ''}</span></span><span className={s.itemSub}>{c.sample_count} samples · {c.domain_count} domains · {c.kit_name ?? 'no kit'}</span></div>
                    </Command.Item>
                  ))}
                </Command.Group>
              )}
              {!!victims.data?.items.length && (
                <Command.Group heading="Victims" className={s.group}>
                  {victims.data.items.slice(0, 6).map((v) => (
                    <Command.Item key={v.id} className={s.item} value={`victim-${v.id}`} onSelect={() => go(() => navigate(`/landscape/victims?q=${encodeURIComponent(v.victim)}&in_scope=`))}>
                      <Building2 size={15} /><div className={s.itemText}><span className={s.itemTitle}>{flag(v.country)} {v.victim}</span><span className={s.itemSub}>{v.group} · {v.sector ?? 'unknown sector'} · {v.month ?? ''}</span></div>
                    </Command.Item>
                  ))}
                </Command.Group>
              )}
              {!!kitHits.length && (
                <Command.Group heading="Phishing kits" className={s.group}>
                  {kitHits.map((k) => (
                    <Command.Item key={k.id} className={s.item} value={`kit-${k.slug}`} onSelect={() => go(() => navigate(`/phishing/kits/${k.id}`))}>
                      <FileSearch size={15} /><div className={s.itemText}><span className={s.itemTitle}>{k.name}</span><span className={s.itemSub}>{k.source} · {k.sample_count} samples · {k.campaign_count} campaigns</span></div>
                    </Command.Item>
                  ))}
                </Command.Group>
              )}
              {!dq && (
                <>
                  <Command.Group heading="Go to" className={s.group}>
                    {NAV.flatMap((g) => g.items.map((item) => ({ ...item, group: g.label }))).map((item) => (
                      <Command.Item key={item.to} className={s.item} value={`nav ${item.label} ${item.group}`} onSelect={() => go(() => navigate(item.to))}>
                        <item.icon size={15} /><div className={s.itemText}><span className={s.itemTitle}>{item.label}</span><span className={s.itemSub}>{item.group}</span></div>
                      </Command.Item>
                    ))}
                  </Command.Group>
                  <Command.Group heading="Actions" className={s.group}>
                    <Command.Item className={s.item} value="run phishing pipeline" onSelect={() => go(() => run('phishing'))}><Play size={15} /><span>Run phishing pipeline (P4)</span></Command.Item>
                    <Command.Item className={s.item} value="run landscape pipeline" onSelect={() => go(() => run('landscape'))}><Play size={15} /><span>Run landscape pipeline (P6)</span></Command.Item>
                    <Command.Item className={s.item} value="toggle theme" onSelect={() => go(toggleTheme)}><Moon size={15} /><span>Toggle theme</span></Command.Item>
                    <Command.Item className={s.item} value="presentation mode" onSelect={() => go(togglePresent)}><Presentation size={15} /><span>Toggle presentation mode</span></Command.Item>
                  </Command.Group>
                </>
              )}
            </Command.List>
          </Command>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}
