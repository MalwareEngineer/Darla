import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { useKitDeobfuscationPreview } from "@/hooks/use-kits";
import type { AnalysisResultBrief } from "@/types/api";

interface Props {
  result: AnalysisResultBrief;
  kitId?: string;
}

export function AnalysisResultView({ result, kitId }: Props) {
  const data = result.result_data;
  if (!data) return <FallbackView data={{}} />;

  switch (result.analysis_type) {
    case "hash":
      return <HashView data={data} />;
    case "deobfuscation":
      return <DeobfuscationView data={data} kitId={kitId} />;
    case "ioc_extraction":
      return <IocExtractionView data={data} />;
    case "yara_scan":
      return <YaraScanView data={data} />;
    case "similarity":
      return <SimilarityView data={data} />;
    case "redirect_chain":
      return <RedirectChainView data={data} />;
    default:
      return <FallbackView data={data} />;
  }
}

function HashView({ data }: { data: Record<string, unknown> }) {
  const fields = ["sha256", "md5", "sha1", "tlsh", "file_size"];
  const present = fields.filter((f) => data[f]);
  if (present.length === 0) return <FallbackView data={data} />;

  return (
    <div className="grid grid-cols-1 gap-2">
      {present.map((field) => (
        <div key={field} className="flex items-baseline gap-2">
          <span className="text-xs text-muted-foreground w-16 shrink-0 uppercase">{field}</span>
          <span className="font-mono text-xs break-all">{String(data[field])}</span>
        </div>
      ))}
    </div>
  );
}

function DeobfuscationView({ data, kitId }: { data: Record<string, unknown>; kitId?: string }) {
  const details = Array.isArray(data.details) ? data.details : [];
  const decoded = (data.decoded_count as number) ?? (data.files_decoded as number) ?? details.length;
  const { data: preview } = useKitDeobfuscationPreview(kitId ?? "", !!kitId && decoded > 0);
  const [expandedFile, setExpandedFile] = useState<number | null>(null);

  const pairs = preview?.pairs ?? [];

  return (
    <div className="space-y-3">
      <p className="text-xs text-muted-foreground">{decoded} file{decoded !== 1 ? "s" : ""} deobfuscated</p>
      {(pairs.length > 0 ? pairs : details).map((item: Record<string, unknown>, i: number) => {
        const pair = pairs[i];
        const file = String(item.file ?? item.filename ?? `file ${i + 1}`);
        const layers = item.layers as number | undefined;
        const techniques = Array.isArray(item.techniques) ? item.techniques : [];
        const hasPreview = pair?.original_content || pair?.deob_content;
        const isExpanded = expandedFile === i;

        return (
          <div key={i} className="border rounded-md overflow-hidden">
            <div
              className={`flex items-center gap-2 flex-wrap px-3 py-2 ${hasPreview ? "cursor-pointer hover:bg-muted/50" : ""}`}
              onClick={() => hasPreview && setExpandedFile(isExpanded ? null : i)}
            >
              {hasPreview && (
                <span className={`text-muted-foreground transition-transform text-xs ${isExpanded ? "rotate-90" : ""}`}>▶</span>
              )}
              <span className="font-mono text-xs text-foreground">{file}</span>
              {layers != null && (
                <Badge variant="outline" className="text-[10px]">
                  {String(layers)} layer{Number(layers) !== 1 ? "s" : ""}
                </Badge>
              )}
              {techniques.map((t: string) => (
                <Badge key={t} variant="secondary" className="text-[10px]">
                  {t}
                </Badge>
              ))}
            </div>
            {isExpanded && hasPreview && (
              <div className="border-t bg-muted/30">
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-0 divide-y lg:divide-y-0 lg:divide-x divide-border">
                  <div className="p-3">
                    <p className="text-[10px] font-semibold uppercase text-muted-foreground mb-1.5 tracking-wider">
                      Original {pair?.original_truncated && <span className="text-yellow-500">(truncated)</span>}
                    </p>
                    <pre className="text-[11px] font-mono overflow-auto max-h-[600px] whitespace-pre-wrap break-all m-0 bg-muted/50 p-2 rounded">
                      {pair?.original_content ?? "Content not available"}
                    </pre>
                  </div>
                  <div className="p-3">
                    <p className="text-[10px] font-semibold uppercase text-muted-foreground mb-1.5 tracking-wider">
                      Deobfuscated {pair?.deob_truncated && <span className="text-yellow-500">(truncated)</span>}
                    </p>
                    <pre className="text-[11px] font-mono overflow-auto max-h-[600px] whitespace-pre-wrap break-all m-0 bg-muted/50 p-2 rounded">
                      {pair?.deob_content ?? "Content not available"}
                    </pre>
                  </div>
                </div>
              </div>
            )}
          </div>
        );
      })}
      {details.length === 0 && decoded > 0 && pairs.length === 0 && <FallbackView data={data} />}
    </div>
  );
}

function IocExtractionView({ data }: { data: Record<string, unknown> }) {
  const total = (data.iocs_extracted as number) ?? (data.total_iocs as number) ?? 0;
  const byType = (data.by_type ?? {}) as Record<string, number>;
  const entries = Object.entries(byType).sort((a, b) => b[1] - a[1]);

  return (
    <div className="space-y-2">
      <p className="text-xs text-muted-foreground">{total} IOC{total !== 1 ? "s" : ""} extracted</p>
      {entries.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {entries.map(([type, count]) => (
            <Badge key={type} variant="outline" className="text-xs gap-1">
              {type} <span className="text-muted-foreground">{count}</span>
            </Badge>
          ))}
        </div>
      )}
      {Array.isArray(data.errors) && data.errors.length > 0 && (
        <div className="text-xs text-red-400 space-y-0.5">
          {(data.errors as string[]).map((e, i) => (
            <p key={i} className="font-mono">{e}</p>
          ))}
        </div>
      )}
    </div>
  );
}

function YaraScanView({ data }: { data: Record<string, unknown> }) {
  const matches = Array.isArray(data.matches) ? data.matches : [];
  const count = (data.match_count as number) ?? matches.length;
  const [expandedRule, setExpandedRule] = useState<number | null>(null);

  return (
    <div className="space-y-3">
      <p className="text-xs text-muted-foreground">
        {count} rule{count !== 1 ? "s" : ""} matched · {String(data.files_scanned ?? 0)} files scanned
      </p>
      {matches.length > 0 && (
        <div className="space-y-2">
          {matches.map((m: Record<string, unknown>, i: number) => {
            const tags = Array.isArray(m.tags) ? m.tags : [];
            const sourceFiles = Array.isArray(m.source_files) ? m.source_files : [];
            const sourceFile = m.source_file ? String(m.source_file) : null;
            const allFiles = sourceFiles.length > 0
              ? (sourceFiles as string[])
              : sourceFile ? [sourceFile] : [];
            const strings = Array.isArray(m.strings) ? m.strings : [];
            const meta = (m.meta ?? {}) as Record<string, unknown>;
            const isExpanded = expandedRule === i;
            const hasDetails = allFiles.length > 0 || strings.length > 0 || Object.keys(meta).length > 0;

            return (
              <div key={i} className="border rounded-md overflow-hidden">
                <div
                  className={`flex items-center gap-2 flex-wrap px-3 py-2 ${hasDetails ? "cursor-pointer hover:bg-muted/50" : ""}`}
                  onClick={() => hasDetails && setExpandedRule(isExpanded ? null : i)}
                >
                  {hasDetails && (
                    <span className={`text-muted-foreground transition-transform text-xs ${isExpanded ? "rotate-90" : ""}`}>▶</span>
                  )}
                  <Badge variant="secondary" className="font-mono text-xs">{String(m.rule)}</Badge>
                  {tags.map((t: string) => (
                    <Badge key={t} variant="outline" className="text-[10px]">{t}</Badge>
                  ))}
                  {allFiles.length > 0 && (
                    <span className="text-[10px] text-muted-foreground ml-auto">
                      {allFiles.length} file{allFiles.length !== 1 ? "s" : ""}
                    </span>
                  )}
                </div>
                {isExpanded && (
                  <div className="border-t bg-muted/30 px-3 py-2 space-y-2">
                    {allFiles.length > 0 && (
                      <div>
                        <p className="text-[10px] font-semibold uppercase text-muted-foreground mb-1 tracking-wider">Matched Files</p>
                        <div className="space-y-0.5">
                          {allFiles.map((f, j) => (
                            <p key={j} className="font-mono text-xs text-foreground">{String(f)}</p>
                          ))}
                        </div>
                      </div>
                    )}
                    {strings.length > 0 && (
                      <div>
                        <p className="text-[10px] font-semibold uppercase text-muted-foreground mb-1 tracking-wider">Matched Strings</p>
                        <pre className="text-[11px] font-mono overflow-auto max-h-96 whitespace-pre-wrap break-all m-0">
                          {strings.map((s: string) => String(s)).join("\n")}
                        </pre>
                      </div>
                    )}
                    {Object.keys(meta).filter(k => k !== "source_file").length > 0 && (
                      <div>
                        <p className="text-[10px] font-semibold uppercase text-muted-foreground mb-1 tracking-wider">Rule Metadata</p>
                        <div className="grid grid-cols-1 gap-0.5">
                          {Object.entries(meta).filter(([k]) => k !== "source_file").map(([k, v]) => (
                            <div key={k} className="flex items-baseline gap-2 text-xs">
                              <span className="text-muted-foreground">{k}:</span>
                              <span className="font-mono break-all">{String(v)}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function SimilarityView({ data }: { data: Record<string, unknown> }) {
  const count = (data.similar_count as number) ?? 0;
  return (
    <div className="space-y-1">
      <p className="text-xs text-muted-foreground">{count} similar kit{count !== 1 ? "s" : ""} found</p>
      {count === 0 && Object.keys(data).length > 1 && <FallbackView data={data} />}
    </div>
  );
}

function RedirectChainView({ data }: { data: Record<string, unknown> }) {
  const chain = Array.isArray(data.chain) ? data.chain : [];
  if (chain.length === 0) return <FallbackView data={data} />;

  return (
    <div className="space-y-1">
      {chain.map((step: Record<string, unknown>, i: number) => (
        <div key={i} className="flex items-center gap-2 text-xs">
          <span className="text-muted-foreground w-4 text-right">{i + 1}</span>
          {!!step.status && (
            <Badge
              variant="outline"
              className={`text-[10px] px-1 ${
                Number(step.status) >= 300 && Number(step.status) < 400
                  ? "text-yellow-400 border-yellow-400/30"
                  : "text-green-400 border-green-400/30"
              }`}
            >
              {String(step.status)}
            </Badge>
          )}
          <span className="font-mono truncate" title={String(step.url ?? "")}>
            {String(step.url ?? "—")}
          </span>
        </div>
      ))}
    </div>
  );
}

function FallbackView({ data }: { data: Record<string, unknown> }) {
  return (
    <pre className="text-xs font-mono bg-muted/50 p-3 rounded-md overflow-auto max-h-[500px]">
      {JSON.stringify(data, null, 2)}
    </pre>
  );
}
