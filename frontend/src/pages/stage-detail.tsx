import { useParams, Link } from "react-router-dom";
import { useStage, useSimilarStages } from "@/hooks/use-stages";
import { useKitScreenshots } from "@/hooks/use-kits";
import { StageRoleBadge } from "@/components/shared/stage-role-badge";
import { PageLoading } from "@/components/shared/loading";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import type { StageComparison } from "@/types/api";

function verdictColor(v: string): string {
  return (
    {
      same: "text-emerald-400",
      similar: "text-amber-400",
      different: "text-red-400",
      unknown: "text-muted-foreground",
    }[v] ?? "text-muted-foreground"
  );
}

function ComparisonSummary({ cmp }: { cmp: StageComparison }) {
  return (
    <div className="space-y-0.5">
      {cmp.signals
        .filter((s) => s.score !== null)
        .map((s) => (
          <div key={s.name} className="flex items-center gap-2 text-[11px]">
            <span className="w-28 text-muted-foreground">{s.name}</span>
            <span className={verdictColor(s.verdict)}>{s.detail}</span>
          </div>
        ))}
    </div>
  );
}

export function StageDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { data: stage, isLoading } = useStage(id!);
  const { data: similar } = useSimilarStages(id!);
  const { data: screenshots } = useKitScreenshots(stage?.kit_id ?? "", !!stage?.kit_id);

  if (isLoading || !stage) return <PageLoading />;

  const shotName = stage.screenshot_path?.split("/").pop();
  const shot = screenshots?.screenshots.find((s) => s.filename === shotName);
  const scripts = (stage.fingerprint?.script_shas as string[] | undefined) ?? [];
  const endpoints = (stage.fingerprint?.endpoints as string[] | undefined) ?? [];

  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <div className="flex items-center gap-3">
          <StageRoleBadge role={stage.role} className="text-xs" />
          <h1 className="text-xl font-bold tracking-tight">Stage {stage.seq}</h1>
          {stage.aitm_baseline && (
            <Badge variant="outline" className="text-[10px] text-orange-400 border-orange-500/30">
              wraps {stage.aitm_baseline}
            </Badge>
          )}
        </div>
        <div className="flex items-center gap-3 text-sm text-muted-foreground">
          <Link to={`/kits/${stage.kit_id}`} className="font-mono hover:underline">
            kit {stage.kit_id.slice(0, 8)}
          </Link>
          {stage.host && <span className="font-mono">{stage.host}</span>}
          {stage.dwell_seconds != null && <span>{stage.dwell_seconds.toFixed(1)}s dwell</span>}
          {stage.nav_method && <span>via {stage.nav_method}</span>}
        </div>
        {stage.url && (
          <p className="font-mono text-xs text-muted-foreground break-all">{stage.url}</p>
        )}
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        {shot && (
          <Card>
            <CardHeader><CardTitle className="text-sm font-medium">Screenshot</CardTitle></CardHeader>
            <CardContent>
              <img src={shot.data_uri} alt="stage" className="rounded-md border border-border w-full" />
            </CardContent>
          </Card>
        )}

        <Card>
          <CardHeader><CardTitle className="text-sm font-medium">Fingerprint</CardTitle></CardHeader>
          <CardContent className="space-y-1.5 text-xs font-mono">
            <Row k="TLSH (raw)" v={stage.tlsh_raw} />
            <Row k="TLSH (rendered)" v={stage.tlsh_rendered} />
            <Row k="skeleton" v={stage.skeleton_hash} />
            <Row k="request shape" v={stage.request_shape_hash} />
            <Row k="screenshot pHash" v={stage.screenshot_phash} />
            <div className="pt-2">
              <span className="text-muted-foreground">scripts: </span>{scripts.length}
              <span className="text-muted-foreground ml-3">endpoints: </span>{endpoints.length}
            </div>
            {endpoints.length > 0 && (
              <ul className="pt-1 space-y-0.5">
                {endpoints.map((e) => (
                  <li key={e} className="text-orange-300 break-all">{e}</li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">
            Resources ({stage.resources.length})
          </CardTitle>
        </CardHeader>
        <CardContent>
          {stage.resources.length ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Initiator</TableHead>
                  <TableHead>URL</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>SHA-256</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {stage.resources.map((r) => (
                  <TableRow key={r.id}>
                    <TableCell><Badge variant="outline" className="text-[10px]">{r.initiator}</Badge></TableCell>
                    <TableCell className="font-mono text-[11px] max-w-md truncate">{r.url}</TableCell>
                    <TableCell className="text-[11px] text-muted-foreground">{r.content_type}</TableCell>
                    <TableCell className="font-mono text-[10px] text-muted-foreground">{r.sha256?.slice(0, 12)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <p className="text-sm text-muted-foreground">No sub-resources captured</p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">
            Similar {stage.role.replace("_", " ")} stages
          </CardTitle>
        </CardHeader>
        <CardContent>
          {similar && similar.length ? (
            <div className="space-y-3">
              {similar.map((m) => (
                <div key={m.stage_id} className="rounded-md border border-border p-3">
                  <div className="flex items-center justify-between">
                    <Link to={`/stages/${m.stage_id}`} className="font-mono text-xs hover:underline">
                      {m.host ?? m.url ?? m.stage_id.slice(0, 8)}
                    </Link>
                    <span className={`text-xs font-medium ${verdictColor(m.verdict)}`}>
                      {m.verdict} ({(m.score * 100).toFixed(0)}%)
                    </span>
                  </div>
                  <div className="mt-1.5">
                    <ComparisonSummary cmp={m.comparison} />
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No comparable stages found</p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function Row({ k, v }: { k: string; v?: string | null }) {
  return (
    <div className="flex gap-3">
      <span className="w-32 text-muted-foreground">{k}</span>
      <span className="break-all">{v ?? "—"}</span>
    </div>
  );
}
