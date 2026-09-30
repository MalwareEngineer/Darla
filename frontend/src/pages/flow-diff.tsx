import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useInvestigations } from "@/hooks/use-investigations";
import { useFlowDiff } from "@/hooks/use-stages";
import { StageRoleBadge } from "@/components/shared/stage-role-badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import type { StageRole } from "@/types/api";

function verdictColor(v?: string | null): string {
  return (
    {
      same: "text-emerald-400",
      similar: "text-amber-400",
      different: "text-red-400",
    }[v ?? ""] ?? "text-muted-foreground"
  );
}

export function FlowDiffPage() {
  const [params, setParams] = useSearchParams();
  const { data: invs } = useInvestigations(0, 200);
  const a = params.get("a") ?? "";
  const b = params.get("b") ?? "";
  const [roleFilter, setRoleFilter] = useState<string>("all");
  const { data: diff, isLoading } = useFlowDiff(a, b);

  const setSide = (side: "a" | "b", value: string) => {
    const next = new URLSearchParams(params);
    next.set(side, value);
    setParams(next);
  };

  const options = invs?.items ?? [];

  const pairs = (diff?.pairs ?? []).filter(
    (p) => roleFilter === "all" || p.role === roleFilter,
  );

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Flow Diff</h1>
        <p className="text-sm text-muted-foreground">
          Align two investigations' attack flows stage-by-stage and see where they
          share infrastructure and where they diverge.
        </p>
      </div>

      <div className="flex flex-wrap items-end gap-4">
        <SidePicker label="Investigation A" value={a} onChange={(v) => setSide("a", v)} options={options} />
        <SidePicker label="Investigation B" value={b} onChange={(v) => setSide("b", v)} options={options} />
        <div className="space-y-1">
          <label className="text-xs text-muted-foreground">Role</label>
          <Select value={roleFilter} onValueChange={(v) => v && setRoleFilter(v)}>
            <SelectTrigger className="w-40"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All roles</SelectItem>
              <SelectItem value="bot_check">Bot check</SelectItem>
              <SelectItem value="interstitial">Interstitial</SelectItem>
              <SelectItem value="email_gate">Email gate</SelectItem>
              <SelectItem value="cred_capture">Cred capture</SelectItem>
              <SelectItem value="decoy">Decoy</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      {a && b ? (
        <Card>
          <CardHeader><CardTitle className="text-sm font-medium">Aligned stages</CardTitle></CardHeader>
          <CardContent>
            {isLoading ? (
              <p className="text-sm text-muted-foreground">Comparing…</p>
            ) : pairs.length ? (
              <div className="space-y-2">
                {pairs.map((p, i) => (
                  <div key={i} className="grid grid-cols-[1fr_auto_1fr] items-center gap-3 rounded-md border border-border p-2.5">
                    <div className="flex items-center gap-2 min-w-0">
                      {p.kind !== "only_b" ? (
                        <>
                          {p.role && <StageRoleBadge role={p.role as StageRole} />}
                          <span className="font-mono text-[11px] text-muted-foreground truncate">{p.a_host ?? "—"}</span>
                        </>
                      ) : (
                        <span className="text-[11px] text-muted-foreground/50 italic">— missing —</span>
                      )}
                    </div>
                    <div className="text-center min-w-[120px]">
                      {p.kind === "match" ? (
                        <span className={`text-xs font-medium ${verdictColor(p.comparison?.verdict)}`}>
                          {p.comparison?.verdict}
                          {p.comparison && ` ${(p.comparison.score * 100).toFixed(0)}%`}
                        </span>
                      ) : (
                        <Badge variant="outline" className="text-[10px]">
                          {p.kind === "only_a" ? "only in A" : "only in B"}
                        </Badge>
                      )}
                    </div>
                    <div className="flex items-center gap-2 min-w-0 justify-end">
                      {p.kind !== "only_a" ? (
                        <>
                          <span className="font-mono text-[11px] text-muted-foreground truncate">{p.b_host ?? "—"}</span>
                          {p.role && <StageRoleBadge role={p.role as StageRole} />}
                        </>
                      ) : (
                        <span className="text-[11px] text-muted-foreground/50 italic">— missing —</span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">No stages to compare.</p>
            )}
          </CardContent>
        </Card>
      ) : (
        <p className="text-sm text-muted-foreground">Pick two investigations to compare.</p>
      )}
    </div>
  );
}

function SidePicker({
  label, value, onChange, options,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: { id: string; name?: string }[];
}) {
  return (
    <div className="space-y-1">
      <label className="text-xs text-muted-foreground">{label}</label>
      <Select value={value} onValueChange={(v) => v && onChange(v)}>
        <SelectTrigger className="w-64"><SelectValue placeholder="Select…" /></SelectTrigger>
        <SelectContent>
          {options.map((o) => (
            <SelectItem key={o.id} value={o.id}>
              {o.name ?? o.id.slice(0, 8)}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
}
