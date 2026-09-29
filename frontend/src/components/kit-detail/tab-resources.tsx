import { Fragment, useState } from "react";
import { useKitBrowserResources } from "@/hooks/use-kits";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { FileCode, FileJson, FileType, File } from "lucide-react";

interface Props {
  kitId: string;
  enabled: boolean;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function fileIcon(filename: string) {
  const ext = filename.split(".").pop()?.toLowerCase();
  const cls = "h-4 w-4 text-muted-foreground";
  switch (ext) {
    case "js":
    case "php":
    case "html":
    case "htm":
    case "css":
      return <FileCode className={cls} />;
    case "json":
      return <FileJson className={cls} />;
    case "svg":
    case "xml":
      return <FileType className={cls} />;
    default:
      return <File className={cls} />;
  }
}

function statusColor(status?: number | null): string {
  if (!status) return "text-muted-foreground";
  if (status >= 200 && status < 300) return "text-green-400";
  if (status >= 300 && status < 400) return "text-yellow-400";
  return "text-red-400";
}

function splitUrl(url: string): { host: string; path: string } {
  try {
    const u = new URL(url);
    return { host: u.hostname, path: u.pathname + u.search };
  } catch {
    return { host: "", path: url };
  }
}

export function TabResources({ kitId, enabled }: Props) {
  const { data, isLoading } = useKitBrowserResources(kitId, enabled);
  const [expandedRow, setExpandedRow] = useState<number | null>(null);

  if (isLoading) {
    return <p className="text-sm text-muted-foreground py-8 text-center">Loading resources...</p>;
  }

  const resources = data?.resources ?? [];

  if (resources.length === 0) {
    return <p className="text-sm text-muted-foreground py-8 text-center">No browser resources captured</p>;
  }

  return (
    <div className="space-y-2">
      <p className="text-xs text-muted-foreground">
        {resources.length} sub-resource{resources.length !== 1 ? "s" : ""} captured during browser rendering
      </p>
      <div className="max-h-[600px] overflow-auto rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-[60px]">Method</TableHead>
              <TableHead className="w-[60px]">Status</TableHead>
              <TableHead className="w-full">Source URL / File</TableHead>
              <TableHead className="w-[70px]">Time</TableHead>
              <TableHead className="w-[80px]">Size</TableHead>
              <TableHead className="w-[140px]">MIME Type</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {resources.map((res, i) => {
              const src = res.url ? splitUrl(res.url) : null;
              return (
              <Fragment key={res.filename}>
                <TableRow
                  className={`cursor-pointer hover:bg-muted/50 ${res.content ? "" : "opacity-70"}`}
                  onClick={() => res.content ? setExpandedRow(expandedRow === i ? null : i) : undefined}
                >
                  <TableCell>
                    {res.method && (
                      <Badge
                        variant={res.method === "GET" ? "secondary" : "default"}
                        className="text-[10px] px-1.5"
                      >
                        {res.method}
                      </Badge>
                    )}
                  </TableCell>
                  <TableCell className={`font-mono text-xs ${statusColor(res.status)}`}>
                    {res.status ?? "—"}
                  </TableCell>
                  <TableCell className="font-mono text-xs max-w-0">
                    <div className="flex items-center gap-2">
                      {fileIcon(res.filename)}
                      <div className="min-w-0">
                        {src && (
                          <div className="truncate" title={res.url ?? undefined}>
                            <span className="text-muted-foreground">{src.host}</span>
                            <span>{src.path}</span>
                          </div>
                        )}
                        <div
                          className={`truncate ${src ? "text-[10px] text-muted-foreground/70" : ""}`}
                          title={res.filename}
                        >
                          {res.filename}
                        </div>
                      </div>
                    </div>
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground font-mono whitespace-nowrap">
                    {res.timestamp != null ? `${res.timestamp.toFixed(1)}s` : "—"}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                    {formatBytes(res.size)}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    <div className="flex items-center gap-1.5">
                      {res.mime_type ?? "—"}
                      {res.truncated && (
                        <Badge variant="outline" className="text-[10px] text-yellow-400 border-yellow-400/30">
                          truncated
                        </Badge>
                      )}
                      {!res.content && (
                        <span className="text-[10px] text-muted-foreground/50">binary</span>
                      )}
                    </div>
                  </TableCell>
                </TableRow>
                {expandedRow === i && res.content && (
                  <TableRow>
                    <TableCell colSpan={6} className="bg-muted/30 p-0">
                      <pre className="text-[11px] font-mono leading-5 p-3 overflow-auto max-h-[600px] m-0 whitespace-pre">
                        {res.content}
                      </pre>
                    </TableCell>
                  </TableRow>
                )}
              </Fragment>
              );
            })}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
