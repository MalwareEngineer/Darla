import { useState, useMemo } from "react";
import { useKitNetworkLog } from "@/hooks/use-kits";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { ChevronRight } from "lucide-react";
import type { NetworkEvent } from "@/types/api";

interface Props {
  kitId: string;
  enabled: boolean;
}

interface PairedEvent {
  url: string;
  request?: NetworkEvent;
  response?: NetworkEvent;
}

function statusColor(status?: number): string {
  if (!status) return "text-muted-foreground";
  if (status >= 200 && status < 300) return "text-green-400";
  if (status >= 300 && status < 400) return "text-yellow-400";
  return "text-red-400";
}

function statusBg(status?: number): string {
  if (!status) return "";
  if (status >= 200 && status < 300) return "border-l-2 border-l-green-500/40";
  if (status >= 300 && status < 400) return "border-l-2 border-l-yellow-500/40";
  return "border-l-2 border-l-red-500/40";
}

function methodVariant(method?: string): "default" | "secondary" | "outline" {
  if (!method) return "outline";
  if (method === "GET") return "secondary";
  return "default";
}

function shortenUrl(url: string): string {
  try {
    const u = new URL(url);
    return u.pathname + u.search;
  } catch {
    return url;
  }
}

function hostname(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

export function TabNetwork({ kitId, enabled }: Props) {
  const { data, isLoading } = useKitNetworkLog(kitId, enabled);
  const [typeFilter, setTypeFilter] = useState("all");
  const [expandedRow, setExpandedRow] = useState<number | null>(null);

  const events = useMemo(() => data?.events ?? [], [data]);

  // Pair requests with responses by URL
  const paired = useMemo(() => {
    const map = new Map<string, PairedEvent>();
    const ordered: PairedEvent[] = [];

    for (const e of events) {
      const key = e.url;
      if (!map.has(key)) {
        const entry: PairedEvent = { url: key };
        map.set(key, entry);
        ordered.push(entry);
      }
      const entry = map.get(key)!;
      if (e.type === "request") {
        entry.request = e;
      } else {
        entry.response = e;
      }
    }
    return ordered;
  }, [events]);

  const resourceTypes = useMemo(() => {
    const types = new Set<string>();
    for (const p of paired) {
      const rt = p.request?.resource_type ?? p.response?.resource_type;
      if (rt) types.add(rt);
    }
    return ["all", ...Array.from(types).sort()];
  }, [paired]);

  const filtered = useMemo(() => {
    if (typeFilter === "all") return paired;
    return paired.filter((p) => {
      const rt = p.request?.resource_type ?? p.response?.resource_type;
      return rt === typeFilter;
    });
  }, [paired, typeFilter]);

  if (isLoading) {
    return <p className="text-sm text-muted-foreground py-8 text-center">Loading network log...</p>;
  }

  if (events.length === 0) {
    return <p className="text-sm text-muted-foreground py-8 text-center">No network events captured</p>;
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-xs text-muted-foreground">Filter:</span>
        {resourceTypes.map((type) => (
          <Badge
            key={type}
            variant={typeFilter === type ? "default" : "outline"}
            className="cursor-pointer text-xs"
            onClick={() => {
              setTypeFilter(type);
              setExpandedRow(null);
            }}
          >
            {type}
          </Badge>
        ))}
        <span className="text-xs text-muted-foreground ml-auto">
          {filtered.length} requests · {data?.total ?? events.length} raw events
        </span>
      </div>

      <div className="max-h-[600px] overflow-auto rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-[30px]" />
              <TableHead className="w-[60px]">Method</TableHead>
              <TableHead className="w-[60px]">Status</TableHead>
              <TableHead className="w-full">URL</TableHead>
              <TableHead className="w-[100px]">Type</TableHead>
              <TableHead className="w-[80px]">Time</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filtered.map((pair, i) => (
              <PairedRow
                key={i}
                pair={pair}
                expanded={expandedRow === i}
                onToggle={() => setExpandedRow(expandedRow === i ? null : i)}
              />
            ))}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}

function PairedRow({
  pair,
  expanded,
  onToggle,
}: {
  pair: PairedEvent;
  expanded: boolean;
  onToggle: () => void;
}) {
  const req = pair.request;
  const res = pair.response;
  const method = req?.method ?? res?.method;
  const status = res?.status;
  const resourceType = req?.resource_type ?? res?.resource_type;
  const reqTime = req?.timestamp;
  const resTime = res?.timestamp;
  const delta = reqTime != null && resTime != null ? resTime - reqTime : null;
  const hasHeaders = !!(req?.headers || res?.headers);
  const host = hostname(pair.url);
  const path = shortenUrl(pair.url);

  return (
    <>
      <TableRow
        className={`cursor-pointer hover:bg-muted/50 ${statusBg(status)}`}
        onClick={onToggle}
      >
        <TableCell className="px-2">
          {hasHeaders && (
            <ChevronRight
              className={`h-3.5 w-3.5 text-muted-foreground transition-transform ${expanded ? "rotate-90" : ""}`}
            />
          )}
        </TableCell>
        <TableCell>
          {method && (
            <Badge variant={methodVariant(method)} className="text-[10px] px-1.5">
              {method}
            </Badge>
          )}
        </TableCell>
        <TableCell className={`font-mono text-xs ${statusColor(status)}`}>
          {status ?? (res ? "—" : <span className="text-yellow-500 text-[10px]">pending</span>)}
        </TableCell>
        <TableCell className="font-mono text-xs max-w-0">
          <div className="truncate" title={pair.url}>
            <span className="text-muted-foreground">{host}</span>
            <span>{path}</span>
          </div>
        </TableCell>
        <TableCell className="text-xs text-muted-foreground">
          {resourceType ?? "—"}
        </TableCell>
        <TableCell className="text-xs text-muted-foreground font-mono">
          {delta != null
            ? `${(delta * 1000).toFixed(0)}ms`
            : reqTime != null
              ? `${reqTime.toFixed(1)}s`
              : "—"}
        </TableCell>
      </TableRow>

      {expanded && hasHeaders && (
        <TableRow>
          <TableCell colSpan={6} className="bg-muted/30 p-0">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-0 divide-x divide-border">
              {req?.headers && (
                <div className="p-3">
                  <p className="text-[10px] font-semibold uppercase text-muted-foreground mb-1.5 tracking-wider">
                    Request Headers
                  </p>
                  <pre className="text-[11px] font-mono overflow-auto max-h-96 whitespace-pre-wrap break-all m-0">
                    {Object.entries(req.headers)
                      .map(([k, v]) => `${k}: ${v}`)
                      .join("\n")}
                  </pre>
                </div>
              )}
              {res?.headers && (
                <div className="p-3">
                  <p className="text-[10px] font-semibold uppercase text-muted-foreground mb-1.5 tracking-wider">
                    Response Headers
                  </p>
                  <pre className="text-[11px] font-mono overflow-auto max-h-96 whitespace-pre-wrap break-all m-0">
                    {Object.entries(res.headers)
                      .map(([k, v]) => `${k}: ${v}`)
                      .join("\n")}
                  </pre>
                </div>
              )}
            </div>
          </TableCell>
        </TableRow>
      )}
    </>
  );
}
