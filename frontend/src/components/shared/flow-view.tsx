import { Link } from "react-router-dom";
import { ChevronRight, Package, Layers } from "lucide-react";
import { StageRoleBadge } from "@/components/shared/stage-role-badge";
import { KitStatusBadge } from "@/components/shared/kit-status-badge";
import { cn } from "@/lib/utils";
import type { FlowKitNode, FlowStageNode, KitStatus } from "@/types/api";

function navLabel(method?: string | null): string {
  if (!method) return "→";
  return (
    {
      initial: "start",
      http_3xx: "3xx",
      meta_refresh: "meta",
      js_location: "js",
      turnstile_solved: "turnstile",
      gate_solved: "gate",
      cta_click: "click",
      form_submit: "submit",
    }[method] ?? method
  );
}

function StageChip({ stage }: { stage: FlowStageNode }) {
  return (
    <Link
      to={`/stages/${stage.id}`}
      className="group flex flex-col gap-1 rounded-md border border-border bg-card px-2.5 py-2 hover:border-primary/50 transition-colors min-w-[140px]"
      title={stage.url ?? undefined}
    >
      <StageRoleBadge role={stage.role} />
      <span className="font-mono text-[11px] text-muted-foreground truncate max-w-[180px]">
        {stage.host ?? stage.url ?? "—"}
      </span>
      <div className="flex items-center gap-2 text-[10px] text-muted-foreground/70">
        {stage.dwell_seconds != null && <span>{stage.dwell_seconds.toFixed(1)}s</span>}
        {stage.resource_count > 0 && (
          <span className="flex items-center gap-0.5">
            <Layers className="h-2.5 w-2.5" />
            {stage.resource_count}
          </span>
        )}
        {stage.aitm_baseline && (
          <span className="text-orange-400">wraps {stage.aitm_baseline}</span>
        )}
      </div>
    </Link>
  );
}

function KitFlowRow({ node, depth }: { node: FlowKitNode; depth: number }) {
  return (
    <div>
      <div
        className="flex items-start gap-2 py-2"
        style={{ paddingLeft: `${depth * 20}px` }}
      >
        <div className="flex flex-col gap-1.5 pt-1 min-w-[150px]">
          <div className="flex items-center gap-1.5">
            <Package className="h-3.5 w-3.5 text-muted-foreground" />
            <Link
              to={`/kits/${node.kit_id}`}
              className="font-mono text-[11px] hover:underline truncate max-w-[160px]"
              title={node.source_url}
            >
              {node.source_url}
            </Link>
          </div>
          <div className="flex items-center gap-1.5">
            <KitStatusBadge status={node.status as KitStatus} />
            {node.discovery_method && (
              <span className="text-[10px] text-muted-foreground">{node.discovery_method}</span>
            )}
          </div>
        </div>

        {node.stages.length > 0 ? (
          <div className="flex items-center gap-1 flex-wrap">
            {node.stages.map((stage, i) => (
              <div key={stage.id} className="flex items-center gap-1">
                {i > 0 && (
                  <div className="flex flex-col items-center text-muted-foreground/60">
                    <ChevronRight className="h-3.5 w-3.5" />
                    <span className="text-[9px] -mt-1">{navLabel(stage.nav_method)}</span>
                  </div>
                )}
                <StageChip stage={stage} />
              </div>
            ))}
          </div>
        ) : (
          <div className="flex items-center pt-2 text-[11px] text-muted-foreground/60 italic">
            no stages captured
          </div>
        )}
      </div>

      {node.children.map((child) => (
        <KitFlowRow key={child.kit_id} node={child} depth={depth + 1} />
      ))}
    </div>
  );
}

export function FlowView({ nodes, className }: { nodes: FlowKitNode[]; className?: string }) {
  if (!nodes.length) {
    return <p className="text-sm text-muted-foreground">No flow data available</p>;
  }
  return (
    <div className={cn("space-y-1 overflow-x-auto", className)}>
      {nodes.map((n) => (
        <KitFlowRow key={n.kit_id} node={n} depth={0} />
      ))}
    </div>
  );
}
