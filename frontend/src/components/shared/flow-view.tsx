import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useQueries } from "@tanstack/react-query";
import { ChevronRight, Package, Layers } from "lucide-react";
import { StageRoleBadge } from "@/components/shared/stage-role-badge";
import { KitStatusBadge } from "@/components/shared/kit-status-badge";
import { StageLightbox, type LightboxStage } from "@/components/shared/stage-lightbox";
import { kits as kitsApi } from "@/lib/api";
import { cn } from "@/lib/utils";
import type {
  FlowKitNode,
  FlowStageNode,
  KitStatus,
  ScreenshotsResponse,
} from "@/types/api";

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

function shotFor(
  path: string | null | undefined,
  shots: ScreenshotsResponse | undefined,
): string | undefined {
  if (!path || !shots) return undefined;
  const base = path.split("/").pop();
  return shots.screenshots.find((s) => s.filename === base)?.data_uri;
}

/** Depth-first flatten of the flow tree into kit nodes in display order. */
function flattenKits(nodes: FlowKitNode[]): FlowKitNode[] {
  const out: FlowKitNode[] = [];
  const walk = (n: FlowKitNode) => {
    out.push(n);
    n.children.forEach(walk);
  };
  nodes.forEach(walk);
  return out;
}

function StageChip({
  stage,
  thumb,
  onOpen,
}: {
  stage: FlowStageNode;
  thumb?: string;
  onOpen: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onOpen}
      className="group flex flex-col gap-1 rounded-md border border-border bg-card px-2.5 py-2 text-left hover:border-primary/50 transition-colors min-w-[140px]"
      title={stage.url ?? undefined}
    >
      <StageRoleBadge role={stage.role} />
      {thumb ? (
        <img
          src={thumb}
          alt=""
          loading="lazy"
          className="h-20 w-full rounded border border-border object-cover object-top"
        />
      ) : (
        <div className="h-20 w-full rounded border border-dashed border-border/60" />
      )}
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
    </button>
  );
}

function KitFlowRow({
  node,
  depth,
  shotsByKit,
  indexOf,
  onOpen,
}: {
  node: FlowKitNode;
  depth: number;
  shotsByKit: Map<string, ScreenshotsResponse | undefined>;
  indexOf: (stageId: string) => number;
  onOpen: (i: number) => void;
}) {
  const shots = shotsByKit.get(node.kit_id);
  return (
    <div>
      <div className="flex items-start gap-2 py-2" style={{ paddingLeft: `${depth * 20}px` }}>
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
                <StageChip
                  stage={stage}
                  thumb={shotFor(stage.screenshot_path, shots)}
                  onOpen={() => onOpen(indexOf(stage.id))}
                />
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
        <KitFlowRow
          key={child.kit_id}
          node={child}
          depth={depth + 1}
          shotsByKit={shotsByKit}
          indexOf={indexOf}
          onOpen={onOpen}
        />
      ))}
    </div>
  );
}

export function FlowView({ nodes, className }: { nodes: FlowKitNode[]; className?: string }) {
  const flatKits = useMemo(() => flattenKits(nodes), [nodes]);

  // Fetch every kit's screenshots once, in flow order.
  const results = useQueries({
    queries: flatKits.map((k) => ({
      queryKey: ["kit-screenshots", k.kit_id],
      queryFn: () => kitsApi.screenshots(k.kit_id),
      enabled: k.stages.some((s) => s.screenshot_path),
      staleTime: 60_000,
    })),
  });
  const shotsByKit = useMemo(() => {
    const m = new Map<string, ScreenshotsResponse | undefined>();
    flatKits.forEach((k, i) => m.set(k.kit_id, results[i]?.data));
    return m;
  }, [flatKits, results]);

  // Flatten stages in display order for the lightbox, resolving each shot.
  const flatStages: LightboxStage[] = useMemo(() => {
    const out: LightboxStage[] = [];
    for (const k of flatKits) {
      for (const stage of k.stages) {
        out.push({
          stage,
          kitId: k.kit_id,
          dataUri: shotFor(stage.screenshot_path, shotsByKit.get(k.kit_id)),
        });
      }
    }
    return out;
  }, [flatKits, shotsByKit]);

  const indexById = useMemo(() => {
    const m = new Map<string, number>();
    flatStages.forEach((s, i) => m.set(s.stage.id, i));
    return m;
  }, [flatStages]);

  const [lightbox, setLightbox] = useState<number | null>(null);

  if (!nodes.length) {
    return <p className="text-sm text-muted-foreground">No flow data available</p>;
  }

  return (
    <div className={cn("space-y-1 overflow-x-auto", className)}>
      {nodes.map((n) => (
        <KitFlowRow
          key={n.kit_id}
          node={n}
          depth={0}
          shotsByKit={shotsByKit}
          indexOf={(id) => indexById.get(id) ?? 0}
          onOpen={setLightbox}
        />
      ))}
      {lightbox !== null && (
        <StageLightbox
          stages={flatStages}
          index={lightbox}
          onIndex={setLightbox}
          onClose={() => setLightbox(null)}
        />
      )}
    </div>
  );
}
