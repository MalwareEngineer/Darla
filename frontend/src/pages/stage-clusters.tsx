import { useState } from "react";
import { useStageClusters, useStageCooccurrence } from "@/hooks/use-stages";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { cn } from "@/lib/utils";

const ROLES = [
  { value: "bot_check", label: "Bot check" },
  { value: "interstitial", label: "Interstitial" },
  { value: "email_gate", label: "Email gate" },
  { value: "cred_capture", label: "Cred capture" },
  { value: "decoy", label: "Decoy" },
];

export function StageClustersPage() {
  const [role, setRole] = useState("bot_check");
  const [roleA, setRoleA] = useState("bot_check");
  const [roleB, setRoleB] = useState("cred_capture");
  const { data: clusters } = useStageClusters(role);
  const { data: cooc } = useStageCooccurrence(roleA, roleB);

  const maxCount = cooc
    ? Math.max(
        1,
        ...Object.values(cooc.matrix).flatMap((row) => Object.values(row)),
      )
    : 1;

  const label = (id: string, list?: { cluster_id: string; hosts: string[]; size: number }[]) => {
    const c = list?.find((x) => x.cluster_id === id);
    const host = c?.hosts[0];
    return host ? `${host} (${c?.size})` : id;
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Stage Clusters</h1>
        <p className="text-sm text-muted-foreground">
          Families of same-role stages across all investigations, and how bot checks
          pair with credential backends — the PhaaS mix-and-match view.
        </p>
      </div>

      <Card>
        <CardHeader className="flex-row items-center justify-between space-y-0">
          <CardTitle className="text-sm font-medium">Clusters by role</CardTitle>
          <Select value={role} onValueChange={(v) => v && setRole(v)}>
            <SelectTrigger className="w-40"><SelectValue /></SelectTrigger>
            <SelectContent>
              {ROLES.map((r) => (
                <SelectItem key={r.value} value={r.value}>{r.label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </CardHeader>
        <CardContent>
          {clusters && clusters.length ? (
            <div className="space-y-2">
              {clusters.map((c) => (
                <div key={c.cluster_id} className="flex items-center gap-3 rounded-md border border-border p-2.5">
                  <span className="text-xs font-medium w-24">{c.size} stage{c.size !== 1 && "s"}</span>
                  <span className="font-mono text-[11px] text-muted-foreground truncate">
                    {c.hosts.slice(0, 5).join(", ") || "—"}
                    {c.hosts.length > 5 && ` +${c.hosts.length - 5}`}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No clusters for this role yet.</p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex-row items-center justify-between space-y-0">
          <CardTitle className="text-sm font-medium">Co-occurrence matrix</CardTitle>
          <div className="flex items-center gap-2">
            <Select value={roleA} onValueChange={(v) => v && setRoleA(v)}>
              <SelectTrigger className="w-36"><SelectValue /></SelectTrigger>
              <SelectContent>
                {ROLES.map((r) => <SelectItem key={r.value} value={r.value}>{r.label}</SelectItem>)}
              </SelectContent>
            </Select>
            <span className="text-muted-foreground text-xs">×</span>
            <Select value={roleB} onValueChange={(v) => v && setRoleB(v)}>
              <SelectTrigger className="w-36"><SelectValue /></SelectTrigger>
              <SelectContent>
                {ROLES.map((r) => <SelectItem key={r.value} value={r.value}>{r.label}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>
        </CardHeader>
        <CardContent className="overflow-x-auto">
          {cooc && cooc.clusters_a.length && cooc.clusters_b.length ? (
            <table className="border-collapse text-[11px]">
              <thead>
                <tr>
                  <th className="p-2" />
                  {cooc.clusters_b.map((cb) => (
                    <th key={cb.cluster_id} className="p-2 font-mono font-normal text-muted-foreground max-w-[120px] truncate">
                      {label(cb.cluster_id, cooc.clusters_b)}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {cooc.clusters_a.map((ca) => (
                  <tr key={ca.cluster_id}>
                    <td className="p-2 font-mono text-muted-foreground max-w-[140px] truncate">
                      {label(ca.cluster_id, cooc.clusters_a)}
                    </td>
                    {cooc.clusters_b.map((cb) => {
                      const n = cooc.matrix[ca.cluster_id]?.[cb.cluster_id] ?? 0;
                      const intensity = n / maxCount;
                      return (
                        <td key={cb.cluster_id} className="p-1 text-center">
                          <div
                            className={cn(
                              "rounded px-2 py-1.5 min-w-[36px]",
                              n === 0 ? "text-muted-foreground/30" : "text-white font-medium",
                            )}
                            style={n > 0 ? { backgroundColor: `rgba(239, 68, 68, ${0.25 + intensity * 0.6})` } : undefined}
                          >
                            {n || "·"}
                          </div>
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="text-sm text-muted-foreground">
              Not enough clustered stages to build a matrix yet.
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
