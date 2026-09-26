import { useState } from "react";
import { Link } from "react-router-dom";
import { useIndicators, useIndicatorSearch, useIndicatorStats } from "@/hooks/use-indicators";
import { IocTypeBadge } from "@/components/shared/ioc-type-badge";
import { Pagination } from "@/components/shared/pagination";
import { TableLoading } from "@/components/shared/loading";
import { Card, CardContent } from "@/components/ui/card";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import type { IndicatorType } from "@/types/api";

const IOC_TYPES: (IndicatorType | "all")[] = [
  "all", "email", "c2_url", "domain", "ip_address", "telegram_bot_token",
  "telegram_chat_id", "telegram_handle", "smtp_credential", "cryptocurrency_wallet",
  "phone_number", "base64_block", "source_url",
];

const PAGE_SIZE = 50;

export function IndicatorsPage() {
  const [offset, setOffset] = useState(0);
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState<string>("all");

  const filterParams = {
    offset,
    limit: PAGE_SIZE,
    type_filter: typeFilter === "all" ? undefined : typeFilter as IndicatorType,
  };

  const listQuery = useIndicators(search ? undefined : filterParams);
  const searchQuery = useIndicatorSearch(search, filterParams);
  const { data: stats } = useIndicatorStats();

  const data = search ? searchQuery.data : listQuery.data;
  const isLoading = search ? searchQuery.isLoading : listQuery.isLoading;

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold tracking-tight">Indicators</h1>

      <div className="flex items-center gap-3">
        <Input
          placeholder="Search IOCs..."
          value={search}
          onChange={(e) => { setSearch(e.target.value); setOffset(0); }}
          className="max-w-sm"
        />
        <Select value={typeFilter} onValueChange={(v) => { if (v) { setTypeFilter(v); setOffset(0); } }}>
          <SelectTrigger className="w-48">
            <SelectValue placeholder="Filter type" />
          </SelectTrigger>
          <SelectContent>
            {IOC_TYPES.map((t) => (
              <SelectItem key={t} value={t}>
                {t === "all" ? "All types" : t.replace(/_/g, " ")}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {/* Stats row */}
      {stats && stats.length > 0 && (
        <div className="flex flex-wrap gap-3">
          {stats.map((s) => (
            <div key={s.type} className="flex items-center gap-2 rounded-md border px-3 py-1.5 text-sm">
              <span className="text-muted-foreground">{s.type.replace(/_/g, " ")}</span>
              <span className="font-semibold">{s.count.toLocaleString()}</span>
            </div>
          ))}
        </div>
      )}

      <Card>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="p-4"><TableLoading /></div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Type</TableHead>
                  <TableHead className="w-full">Value</TableHead>
                  <TableHead>Conf.</TableHead>
                  <TableHead>Kit</TableHead>
                  <TableHead>Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(data?.items ?? []).map((ioc) => (
                  <TableRow key={ioc.id}>
                    <TableCell className="whitespace-nowrap"><IocTypeBadge type={ioc.type} /></TableCell>
                    <TableCell className="font-mono text-xs" style={{ maxWidth: 0 }}>
                      <div className="truncate" title={ioc.value}>{ioc.value}</div>
                      {ioc.context && ioc.context !== "kit_source" && (
                        <div className="text-[10px] text-muted-foreground mt-0.5 truncate">{ioc.context}</div>
                      )}
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-xs text-right">{ioc.confidence}%</TableCell>
                    <TableCell className="whitespace-nowrap">
                      <Link to={`/kits/${ioc.kit_id}`} className="text-xs font-mono hover:underline">
                        {ioc.kit_id.slice(0, 8)}
                      </Link>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                      {new Date(ioc.created_at).toLocaleDateString()}
                    </TableCell>
                  </TableRow>
                ))}
                {data?.items.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={5} className="text-center text-muted-foreground py-8">
                      No indicators found
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {data && <Pagination offset={offset} limit={PAGE_SIZE} total={data.total} onOffsetChange={setOffset} />}
    </div>
  );
}
