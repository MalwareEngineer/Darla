import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { StageRole } from "@/types/api";

const roleConfig: Record<StageRole, { label: string; className: string }> = {
  lure: { label: "Lure", className: "bg-slate-500/20 text-slate-300 border-slate-500/30" },
  redirector: { label: "Redirector", className: "bg-zinc-500/20 text-zinc-300 border-zinc-500/30" },
  bot_check: { label: "Bot Check", className: "bg-amber-500/20 text-amber-400 border-amber-500/30" },
  interstitial: { label: "Interstitial", className: "bg-sky-500/20 text-sky-400 border-sky-500/30" },
  email_gate: { label: "Email Gate", className: "bg-violet-500/20 text-violet-400 border-violet-500/30" },
  cred_capture: { label: "Cred Capture", className: "bg-red-500/20 text-red-400 border-red-500/30" },
  decoy: { label: "Decoy", className: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30" },
  post_submit: { label: "Post-Submit", className: "bg-teal-500/20 text-teal-400 border-teal-500/30" },
  unknown: { label: "Unknown", className: "bg-neutral-500/20 text-neutral-400 border-neutral-500/30" },
};

export function StageRoleBadge({ role, className }: { role: StageRole; className?: string }) {
  const config = roleConfig[role] ?? { label: role, className: "" };
  return (
    <Badge variant="outline" className={cn("text-[10px] font-medium", config.className, className)}>
      {config.label}
    </Badge>
  );
}
