import type { ReactNode } from 'react';
import { ShieldAlert, Cpu } from 'lucide-react';
import { getDomainMeta, getSeverityMeta } from './tokens';

interface BadgeProps {
  children: ReactNode;
  className?: string;
  title?: string;
}

export function Badge({ children, className = '', title }: BadgeProps) {
  return (
    <span
      title={title}
      className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded border text-[10px] font-mono leading-none tracking-wide whitespace-nowrap ${className}`}
    >
      {children}
    </span>
  );
}

export function SeverityBadge({
  severity,
  showDot = true,
}: {
  severity?: string | null;
  showDot?: boolean;
}) {
  const meta = getSeverityMeta(severity);
  return (
    <Badge className={meta.badgeClass}>
      {showDot && <span className={`w-1.5 h-1.5 rounded-full ${meta.dotClass}`} />}
      {meta.label}
    </Badge>
  );
}

export function KevBadge() {
  return (
    <Badge
      title="CISA Known Exploited Vulnerabilities — 已知在野利用"
      className="bg-red-500/20 text-red-300 border-red-500/50 font-semibold"
    >
      <ShieldAlert size={10} />
      KEV 在野
    </Badge>
  );
}

export function DomainBadge({ domain }: { domain?: string }) {
  const meta = getDomainMeta(domain);
  return <Badge className={meta.badgeClass}>{meta.label}</Badge>;
}

export function ComponentBadge({ name }: { name: string }) {
  return (
    <Badge
      title={`受影响组件: ${name}`}
      className="bg-cyan-500/10 text-cyan-300 border-cyan-500/30"
    >
      <Cpu size={10} className="opacity-80" />
      <span className="max-w-[180px] truncate">{name}</span>
    </Badge>
  );
}
