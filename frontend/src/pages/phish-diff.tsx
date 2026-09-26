import { useState } from "react";
import { useSearchParams, Link } from "react-router-dom";
import { useDiffPairGroups, useDiffPairs, useDiffCompare } from "@/hooks/use-diff";
import { useKits, useKitSimilar } from "@/hooks/use-kits";
import { TableLoading } from "@/components/shared/loading";
import { Pagination } from "@/components/shared/pagination";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { ArrowLeft, ArrowRight, Globe, FileText, Search } from "lucide-react";
import ReactDiffViewer, { DiffMethod } from "react-diff-viewer-continued";
import type { DiffableKit, DiffablePair, DiffChangeCategory, SimilarKit } from "@/types/api";

const PAGE_SIZE = 20;

export function PhishDiffPage() {
  const [searchParams] = useSearchParams();
  const kitA = searchParams.get("a");
  const kitB = searchParams.get("b");
  const mode = searchParams.get("mode") || "poly";

  // If both a & b are set, show the diff viewer
  if (kitA && kitB) {
    return <DiffViewer kitAId={kitA} kitBId={kitB} mode={mode} />;
  }

  // If only a is set, show pair picker for that kit
  if (kitA) {
    return mode === "any"
      ? <AnyPairPicker kitId={kitA} />
      : <PolyPairPicker kitId={kitA} />;
  }

  // Otherwise show the tabbed landing
  return <DiffLanding />;
}

// ── Tabbed Landing ──

function DiffLanding() {
  const [searchParams, setSearchParams] = useSearchParams();
  const tab = searchParams.get("mode") || "poly";

  const setTab = (value: string | number | null) => {
    if (value === "poly") {
      setSearchParams({});
    } else {
      setSearchParams({ mode: String(value) });
    }
  };

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">PhishDiff</h1>
        <p className="text-sm text-muted-foreground">
          Compare kit variants side-by-side
        </p>
      </div>

      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="poly">Poly</TabsTrigger>
          <TabsTrigger value="any">Any</TabsTrigger>
        </TabsList>

        <TabsContent value="poly">
          <PolyBrowser />
        </TabsContent>

        <TabsContent value="any">
          <AnyBrowser />
        </TabsContent>
      </Tabs>
    </div>
  );
}

// ── Poly Browser (polymorphic pairs) ──

function PolyBrowser() {
  const [offset, setOffset] = useState(0);
  const { data, isLoading } = useDiffPairGroups({ offset, limit: PAGE_SIZE });

  if (isLoading) return <TableLoading />;

  if (!data?.groups.length) {
    return (
      <Card>
        <CardContent className="py-10 text-center text-muted-foreground">
          No diffable kit pairs found. Kits must share the same domain, have TLSH
          distance &le; 30, and file size ratio &lt; 1.15.
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      {data.groups.map((group) => (
        <Card key={group.domain}>
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <Globe className="h-4 w-4 text-muted-foreground" />
              {group.domain}
              <Badge variant="secondary" className="ml-auto">
                {group.pair_count} pair{group.pair_count !== 1 && "s"}
              </Badge>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {group.kits.map((kit) => (
                <KitRow key={kit.id} kit={kit} mode="poly" />
              ))}
            </div>
          </CardContent>
        </Card>
      ))}
      <Pagination
        offset={offset}
        limit={PAGE_SIZE}
        total={data.total}
        onOffsetChange={setOffset}
      />
    </div>
  );
}

// ── Any Browser (all kits with TLSH) ──

function AnyBrowser() {
  const [offset, setOffset] = useState(0);
  const [search, setSearch] = useState("");
  const { data, isLoading } = useKits({
    offset,
    limit: PAGE_SIZE,
    status_filter: "analyzed",
  });

  const filtered = data?.items.filter((kit) => {
    if (!kit.tlsh) return false;
    if (!search) return true;
    return kit.source_url.toLowerCase().includes(search.toLowerCase());
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Filter by URL..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
          />
        </div>
      </div>

      {isLoading ? (
        <TableLoading />
      ) : !filtered?.length ? (
        <Card>
          <CardContent className="py-10 text-center text-muted-foreground">
            No analyzed kits with TLSH hashes found.
          </CardContent>
        </Card>
      ) : (
        <>
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm text-muted-foreground">
                Select a kit to compare (TLSH &le; 100)
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {filtered.map((kit) => (
                  <KitRow
                    key={kit.id}
                    kit={{
                      id: kit.id,
                      source_url: kit.source_url,
                      tlsh: kit.tlsh,
                      file_size: kit.file_size,
                      status: kit.status,
                      created_at: kit.created_at,
                    }}
                    mode="any"
                  />
                ))}
              </div>
            </CardContent>
          </Card>
          {data && (
            <Pagination
              offset={offset}
              limit={PAGE_SIZE}
              total={data.total}
              onOffsetChange={setOffset}
            />
          )}
        </>
      )}
    </div>
  );
}

// ── Shared kit row ──

function KitRow({ kit, mode }: { kit: DiffableKit; mode: string }) {
  return (
    <Link
      to={`/phish-diff?a=${kit.id}&mode=${mode}`}
      className="flex items-center gap-3 rounded-md border px-3 py-2 text-sm hover:bg-muted/50 transition-colors"
    >
      <FileText className="h-4 w-4 shrink-0 text-muted-foreground" />
      <span className="flex-1 truncate font-mono text-xs">{kit.source_url}</span>
      <span className="text-xs text-muted-foreground">
        {kit.file_size ? `${(kit.file_size / 1024).toFixed(1)}KB` : "—"}
      </span>
      <span className="text-xs text-muted-foreground">
        {new Date(kit.created_at).toLocaleDateString()}
      </span>
      <ArrowRight className="h-3 w-3 text-muted-foreground" />
    </Link>
  );
}

// ── Poly Pair Picker ──

function PolyPairPicker({ kitId }: { kitId: string }) {
  const { data: pairs, isLoading } = useDiffPairs(kitId);

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <Link to="/phish-diff">
          <Button variant="ghost" size="sm">
            <ArrowLeft className="mr-1 h-4 w-4" /> Back
          </Button>
        </Link>
        <h1 className="text-2xl font-bold tracking-tight">Select Comparison Kit</h1>
      </div>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm text-muted-foreground">
            Kit A: <span className="font-mono">{kitId.slice(0, 8)}...</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <TableLoading />
          ) : !pairs?.length ? (
            <p className="text-sm text-muted-foreground py-4 text-center">
              No diffable partners found for this kit.
            </p>
          ) : (
            <div className="space-y-2">
              {pairs.map((pair) => (
                <PairRow key={pair.id} kitAId={kitId} pair={pair} mode="poly" />
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ── Any Pair Picker ──

function AnyPairPicker({ kitId }: { kitId: string }) {
  const { data: similar, isLoading } = useKitSimilar(kitId, 100);

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <Link to="/phish-diff?mode=any">
          <Button variant="ghost" size="sm">
            <ArrowLeft className="mr-1 h-4 w-4" /> Back
          </Button>
        </Link>
        <h1 className="text-2xl font-bold tracking-tight">Select Comparison Kit</h1>
        <Badge variant="outline" className="text-xs">TLSH &le; 100</Badge>
      </div>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm text-muted-foreground">
            Kit A: <span className="font-mono">{kitId.slice(0, 8)}...</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <TableLoading />
          ) : !similar?.length ? (
            <p className="text-sm text-muted-foreground py-4 text-center">
              No similar kits found within TLSH distance 100.
            </p>
          ) : (
            <div className="space-y-2">
              {similar.map((s) => (
                <SimilarRow key={s.id} kitAId={kitId} similar={s} />
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function PairRow({ kitAId, pair, mode }: { kitAId: string; pair: DiffablePair; mode: string }) {
  return (
    <Link
      to={`/phish-diff?a=${kitAId}&b=${pair.id}&mode=${mode}`}
      className="flex items-center gap-3 rounded-md border px-3 py-2 text-sm hover:bg-muted/50 transition-colors"
    >
      <FileText className="h-4 w-4 shrink-0 text-muted-foreground" />
      <span className="flex-1 truncate font-mono text-xs">{pair.source_url}</span>
      <Badge variant="outline" className="text-xs">
        TLSH: {pair.distance}
      </Badge>
      <Badge variant="outline" className="text-xs">
        ratio: {pair.size_ratio.toFixed(2)}
      </Badge>
      <ArrowRight className="h-3 w-3 text-muted-foreground" />
    </Link>
  );
}

function SimilarRow({ kitAId, similar }: { kitAId: string; similar: SimilarKit }) {
  return (
    <Link
      to={`/phish-diff?a=${kitAId}&b=${similar.id}&mode=any`}
      className="flex items-center gap-3 rounded-md border px-3 py-2 text-sm hover:bg-muted/50 transition-colors"
    >
      <FileText className="h-4 w-4 shrink-0 text-muted-foreground" />
      <span className="flex-1 truncate font-mono text-xs">{similar.source_url}</span>
      <Badge variant="outline" className="text-xs">
        TLSH: {similar.distance}
      </Badge>
      <ArrowRight className="h-3 w-3 text-muted-foreground" />
    </Link>
  );
}

// ── Diff Viewer (shared by both modes) ──

function DiffViewer({ kitAId, kitBId, mode }: { kitAId: string; kitBId: string; mode: string }) {
  const [normalize, setNormalize] = useState(false);
  const { data, isLoading, error } = useDiffCompare(kitAId, kitBId, normalize);

  const backUrl = mode === "any"
    ? `/phish-diff?a=${kitAId}&mode=any`
    : `/phish-diff?a=${kitAId}&mode=poly`;

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <Link to={backUrl}>
          <Button variant="ghost" size="sm">
            <ArrowLeft className="mr-1 h-4 w-4" /> Back
          </Button>
        </Link>
        <h1 className="text-2xl font-bold tracking-tight">Kit Comparison</h1>
        <label className="ml-auto flex items-center gap-2 cursor-pointer text-sm">
          <input
            type="checkbox"
            checked={normalize}
            onChange={(e) => setNormalize(e.target.checked)}
            className="h-4 w-4 rounded border-border"
          />
          Normalize
        </label>
      </div>

      {isLoading ? (
        <TableLoading />
      ) : error ? (
        <Card>
          <CardContent className="py-10 text-center text-destructive">
            {error.message}
          </CardContent>
        </Card>
      ) : data ? (
        <>
          {/* Summary card */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Card>
              <CardContent className="pt-4">
                <div className="text-sm text-muted-foreground">Structural Similarity</div>
                <div className="text-2xl font-bold">
                  {(data.summary.structural_similarity * 100).toFixed(1)}%
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-4">
                <div className="text-sm text-muted-foreground">TLSH Distance</div>
                <div className="text-2xl font-bold">
                  {data.summary.tlsh_distance ?? "—"}
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-4">
                <div className="text-sm text-muted-foreground">Change Categories</div>
                <div className="mt-1 flex flex-wrap gap-1">
                  {data.summary.change_categories.map((c: DiffChangeCategory) => (
                    <Badge key={c.category} variant="secondary" className="text-xs">
                      {c.category} ({c.count})
                    </Badge>
                  ))}
                  {!data.summary.change_categories.length && (
                    <span className="text-sm text-muted-foreground">None detected</span>
                  )}
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Kit URL headers */}
          <div className="grid grid-cols-2 gap-4">
            <Card>
              <CardContent className="py-2">
                <div className="text-xs text-muted-foreground">Kit A</div>
                <Link to={`/kits/${kitAId}`} className="text-xs font-mono hover:underline truncate block">
                  {data.kit_a.source_url}
                </Link>
                {data.kit_a.file_size && (
                  <span className="text-xs text-muted-foreground">
                    {(data.kit_a.file_size / 1024).toFixed(1)}KB
                  </span>
                )}
              </CardContent>
            </Card>
            <Card>
              <CardContent className="py-2">
                <div className="text-xs text-muted-foreground">Kit B</div>
                <Link to={`/kits/${kitBId}`} className="text-xs font-mono hover:underline truncate block">
                  {data.kit_b.source_url}
                </Link>
                {data.kit_b.file_size && (
                  <span className="text-xs text-muted-foreground">
                    {(data.kit_b.file_size / 1024).toFixed(1)}KB
                  </span>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Diff viewer */}
          <Card>
            <CardContent className="p-0 overflow-auto">
              <ReactDiffViewer
                oldValue={data.kit_a.content}
                newValue={data.kit_b.content}
                splitView
                compareMethod={DiffMethod.LINES}
                leftTitle="Kit A"
                rightTitle="Kit B"
                styles={{
                  contentText: { fontSize: "12px", fontFamily: "monospace" },
                }}
              />
            </CardContent>
          </Card>
        </>
      ) : null}
    </div>
  );
}
