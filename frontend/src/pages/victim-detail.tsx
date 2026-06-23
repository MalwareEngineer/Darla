import { useMemo } from "react";
import { Link, useParams } from "react-router-dom";
import {
  ArrowLeft,
  Mail,
  CalendarClock,
  Activity,
  StickyNote,
  Terminal,
} from "lucide-react";

import {
  useVictim,
  useVictimObservations,
} from "@/hooks/use-victims";
import { PageLoading } from "@/components/shared/loading";
import { KitStatusBadge } from "@/components/shared/kit-status-badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import type {
  VictimObservationSource,
  VictimType,
} from "@/types/api";

const TYPE_LABEL: Record<VictimType, string> = {
  user: "User",
  exec: "Exec",
  distro: "Distro",
  shared_mailbox: "Shared mailbox",
  service: "Service",
  unknown: "Unknown",
};

const TYPE_BADGE_VARIANT: Record<
  VictimType,
  "default" | "secondary" | "outline" | "destructive"
> = {
  user: "secondary",
  exec: "destructive",
  distro: "outline",
  shared_mailbox: "outline",
  service: "outline",
  unknown: "outline",
};

const SOURCE_LABEL: Record<VictimObservationSource, string> = {
  oauth_state: "OAuth state",
  oauth_login_hint: "OAuth login_hint",
  aitm_url_fragment: "AITM URL fragment",
  eml_to: "EML To-header",
  eml_cc: "EML Cc-header",
  eml_bcc: "EML Bcc-header",
  kit_content: "Kit content",
  other: "Other",
};

function formatTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString();
}

// ---------------------------------------------------------------------------
// Read-only notes card.  Edits moved to the `darla-admin victim reload`
// CSV path (RFC §9 / Phase 6b) — victim records are PII-bearing and the
// authoritative path now goes through the operator CLI under AWS-IAM
// rather than the HTTP API.
// ---------------------------------------------------------------------------

function NotesCard({ value }: { value: string | null }) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium flex items-center gap-2">
          <StickyNote className="h-4 w-4" />
          Operator notes
        </CardTitle>
      </CardHeader>
      <CardContent>
        <p className="text-sm text-muted-foreground whitespace-pre-wrap">
          {value || "No notes recorded."}
        </p>
      </CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Inline notice that this record is managed via the operator CLI.  Lives
// at the top of the page so an analyst clicking around realises the
// edit affordances they're used to have moved out-of-band.
// ---------------------------------------------------------------------------

function CliManagedNotice() {
  return (
    <div className="flex items-start gap-2 rounded-md border border-amber-500/30 bg-amber-500/5 p-3 text-xs text-muted-foreground">
      <Terminal className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-600" />
      <div>
        <span className="font-medium text-foreground">Managed via CLI.</span>
        {" "}Update display name, type, or notes by editing the HR CSV
        and running{" "}
        <code className="font-mono text-foreground">
          darla-admin victim reload --source &lt;csv&gt;
        </code>{" "}
        from inside the API container. Pipeline-driven first/last-seen
        timestamps continue to update automatically as new kits are
        analysed.
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Source-channel breakdown — cheap client-side aggregation over the
// observations response so we don't need a dedicated backend stats
// endpoint for it.  Pagination caveat: when total > limit, this only
// reflects the current page.  100 is the default limit, which covers
// almost every real victim's full observation history.
// ---------------------------------------------------------------------------

function SourceBreakdown({
  observations,
}: {
  observations: { source: VictimObservationSource }[];
}) {
  const counts = useMemo(() => {
    const m: Partial<Record<VictimObservationSource, number>> = {};
    for (const o of observations) {
      m[o.source] = (m[o.source] ?? 0) + 1;
    }
    return Object.entries(m).sort((a, b) => (b[1] ?? 0) - (a[1] ?? 0));
  }, [observations]);

  if (counts.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">No observations yet.</p>
    );
  }

  const max = Math.max(...counts.map(([, n]) => n ?? 0));

  return (
    <div className="space-y-2">
      {counts.map(([source, count]) => (
        <div
          key={source}
          className="flex items-center gap-3 text-sm"
        >
          <span className="w-44 shrink-0 text-muted-foreground">
            {SOURCE_LABEL[source as VictimObservationSource] ?? source}
          </span>
          <div className="flex-1 h-2 rounded-full bg-muted overflow-hidden">
            <div
              className="h-full bg-emerald-500/80 transition-all"
              style={{ width: `${((count ?? 0) / max) * 100}%` }}
            />
          </div>
          <span className="w-10 text-right font-mono">{count}</span>
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function VictimDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { data: victim, isLoading } = useVictim(id);
  const { data: obsData } = useVictimObservations(id, 0, 100);

  if (isLoading || !victim || !id) return <PageLoading />;

  return (
    <div className="space-y-6">
      <div>
        <Link
          to="/phishprint"
          className="inline-flex items-center text-sm text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="h-4 w-4 mr-1" />
          PhishPrint
        </Link>
      </div>

      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div className="space-y-2 min-w-0">
          <div className="flex items-center gap-2">
            <Mail className="h-5 w-5 text-muted-foreground shrink-0" />
            <h1 className="text-2xl font-bold tracking-tight font-mono break-all">
              {victim.email}
            </h1>
          </div>
          {victim.display_name ? (
            <span className="text-base text-foreground">
              {victim.display_name}
            </span>
          ) : (
            <span className="text-sm text-muted-foreground italic">
              No display name configured
            </span>
          )}
        </div>

        <div className="flex items-center gap-3">
          <span className="text-xs text-muted-foreground">Type</span>
          <Badge
            variant={TYPE_BADGE_VARIANT[victim.type]}
            className="text-sm px-3 py-1"
          >
            {TYPE_LABEL[victim.type]}
          </Badge>
        </div>
      </div>

      <CliManagedNotice />

      <Card>
        <CardContent className="grid gap-4 p-4 md:grid-cols-4">
          <div>
            <span className="text-xs text-muted-foreground flex items-center gap-1">
              <Activity className="h-3 w-3" />
              Type
            </span>
            <div className="mt-1">
              <Badge variant={TYPE_BADGE_VARIANT[victim.type]}>
                {TYPE_LABEL[victim.type]}
              </Badge>
            </div>
          </div>
          <div>
            <span className="text-xs text-muted-foreground">Domain</span>
            <p className="font-mono text-sm mt-1">{victim.domain}</p>
          </div>
          <div>
            <span className="text-xs text-muted-foreground flex items-center gap-1">
              <CalendarClock className="h-3 w-3" />
              First seen
            </span>
            <p className="text-sm mt-1">{formatTime(victim.first_seen)}</p>
          </div>
          <div>
            <span className="text-xs text-muted-foreground flex items-center gap-1">
              <CalendarClock className="h-3 w-3" />
              Last seen
            </span>
            <p className="text-sm mt-1">{formatTime(victim.last_seen)}</p>
          </div>
          <div>
            <span className="text-xs text-muted-foreground">
              Total observations
            </span>
            <p className="text-sm mt-1 font-medium">
              {obsData?.total ?? "—"}
            </p>
          </div>
        </CardContent>
      </Card>

      <NotesCard value={victim.notes} />

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium">
            Source-channel breakdown
          </CardTitle>
        </CardHeader>
        <CardContent>
          <SourceBreakdown observations={obsData?.items ?? []} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">
            Observations
            {obsData && (
              <span className="text-xs text-muted-foreground font-normal ml-2">
                ({obsData.total})
              </span>
            )}
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Observed</TableHead>
                <TableHead>Source</TableHead>
                <TableHead>Kit</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>SHA256</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(obsData?.items ?? []).map((o) => (
                <TableRow key={o.id}>
                  <TableCell
                    className="text-xs whitespace-nowrap text-muted-foreground"
                    title={o.observed_at}
                  >
                    {formatTime(o.observed_at)}
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className="text-xs">
                      {SOURCE_LABEL[o.source]}
                    </Badge>
                  </TableCell>
                  <TableCell className="font-mono text-xs max-w-md truncate">
                    <Link
                      to={`/kits/${o.kit.id}`}
                      className="hover:underline"
                    >
                      {o.kit.source_url}
                    </Link>
                  </TableCell>
                  <TableCell>
                    <KitStatusBadge status={o.kit.status as never} />
                  </TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground">
                    {o.kit.sha256?.slice(0, 12) ?? "—"}
                  </TableCell>
                </TableRow>
              ))}
              {obsData && obsData.items.length === 0 && (
                <TableRow>
                  <TableCell
                    colSpan={5}
                    className="text-center text-muted-foreground py-8"
                  >
                    No observations recorded yet.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
