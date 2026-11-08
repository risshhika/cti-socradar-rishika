import {
  Activity, Boxes, Building2, ClipboardCheck, DollarSign, FileSearch, FileText, Fish, LayoutDashboard, Radar, Settings,
  ShieldCheck, ScanSearch, Users, Workflow, type LucideIcon,
} from 'lucide-react'

export interface NavItem { to: string; label: string; icon: LucideIcon; badge?: 'campaigns' | 'scope' }
export interface NavGroup { label: string; tag?: string; items: NavItem[] }

export const NAV: NavGroup[] = [
  { label: 'Command', items: [{ to: '/', label: 'Command Center', icon: LayoutDashboard }] },
  {
    label: 'Phishing intelligence', tag: 'P4',
    items: [
      { to: '/phishing', label: 'Campaign overview', icon: Fish },
      { to: '/phishing/campaigns', label: 'Campaigns', icon: Boxes, badge: 'campaigns' },
      { to: '/phishing/kits', label: 'Kit fingerprints', icon: FileSearch },
      { to: '/phishing/samples', label: 'Samples', icon: ScanSearch },
      { to: '/phishing/detections', label: 'Detections', icon: ShieldCheck },
    ],
  },
  {
    label: 'Threat landscape', tag: 'P6',
    items: [
      { to: '/landscape', label: 'Sector dashboard', icon: Radar },
      { to: '/landscape/victims', label: 'Victim tracker', icon: Building2, badge: 'scope' },
      { to: '/landscape/actors', label: 'Ransomware actors', icon: Users },
      { to: '/landscape/iab', label: 'Access brokers', icon: DollarSign },
      { to: '/landscape/briefings', label: 'Monthly briefings', icon: FileText },
    ],
  },
  {
    label: 'System',
    items: [
      { to: '/pipelines', label: 'Pipelines & runs', icon: Workflow },
      { to: '/review', label: 'Analyst review', icon: ClipboardCheck },
      { to: '/settings', label: 'Scope & settings', icon: Settings },
    ],
  },
]
export const SYSTEM_ICON = Activity
