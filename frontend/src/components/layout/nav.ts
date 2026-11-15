import {
  AtSign,
  Activity, Boxes, Building2, ClipboardCheck, DollarSign, FileSearch, FileText, Fish, LayoutDashboard, Radar, Settings,
  ShieldCheck, ScanSearch, SpellCheck, Users, Workflow, FileBarChart, type LucideIcon,
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
      { to: '/phishing/leads', label: 'Typosquat leads', icon: SpellCheck },
      { to: '/phishing/detections', label: 'Detections', icon: ShieldCheck },
      { to: '/phishing/report', label: 'Executive report', icon: FileBarChart },
    ],
  },
  {
    label: 'Threat landscape', tag: 'P6',
    items: [
      { to: '/landscape', label: 'Sector dashboard', icon: Radar },
      { to: '/landscape/victims', label: 'Victim tracker', icon: Building2, badge: 'scope' },
      { to: '/landscape/actors', label: 'Ransomware actors', icon: Users },
      { to: '/landscape/iab', label: 'Access brokers', icon: DollarSign },
      { to: '/landscape/x', label: 'X broker monitor', icon: AtSign },
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
