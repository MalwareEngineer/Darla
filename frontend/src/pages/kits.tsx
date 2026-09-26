import { useState, useMemo, useRef } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useKits, useSubmitKit, useUploadKit, useBulkSubmitKits, useBulkUploadKits, useSearchKits, useBulkDeleteKits } from "@/hooks/use-kits";
import { KitStatusBadge } from "@/components/shared/kit-status-badge";
import { EntityLinkSelectors } from "@/components/shared/entity-link-selectors";
import { Pagination } from "@/components/shared/pagination";
import { TableLoading } from "@/components/shared/loading";
import { Card, CardContent } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Plus, Upload, X, FileText, Search, Trash2 } from "lucide-react";
import { toast } from "sonner";
import type { KitStatus, KitSummary } from "@/types/api";

const STATUSES: (KitStatus | "all")[] = ["all", "pending", "downloading", "analyzing", "analyzed", "failed"];
const PAGE_SIZE = 25;

/** Parse search input into structured params. Supports:
 *  - `yara:RuleName` → yara_rule filter
 *  - `tlsh:T1...`   → TLSH similarity search
 *  - anything else   → text search (URL, hash, filename)
 */
function parseSearch(input: string) {
  const trimmed = input.trim();
  if (trimmed.startsWith("yara:")) {
    return { yara_rule: trimmed.slice(5).trim() };
  }
  if (trimmed.startsWith("tlsh:")) {
    return { tlsh: trimmed.slice(5).trim() };
  }
  return { q: trimmed };
}

export function KitsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [offset, setOffset] = useState(0);
  const [statusFilter, setStatusFilter] = useState<string>("all");

  // Search state — initialise from URL ?search= param
  const [searchInput, setSearchInput] = useState(searchParams.get("search") ?? "");
  const [activeSearch, setActiveSearch] = useState(searchParams.get("search") ?? "");

  // Sync when navigated here with a new ?search= (first load is covered
  // by the initializers above).  Adjust-during-render, not an effect.
  const urlSearch = searchParams.get("search") ?? "";
  const [prevUrlSearch, setPrevUrlSearch] = useState(urlSearch);
  if (urlSearch !== prevUrlSearch) {
    setPrevUrlSearch(urlSearch);
    if (urlSearch && urlSearch !== activeSearch) {
      setSearchInput(urlSearch);
      setActiveSearch(urlSearch);
      setOffset(0);
    }
  }

  // Submit URL state
  const [submitOpen, setSubmitOpen] = useState(false);
  const [submitUrls, setSubmitUrls] = useState("");

  // Upload state
  const [uploadOpen, setUploadOpen] = useState(false);
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);

  // Entity linking state (shared by both dialogs)
  const [submitActorId, setSubmitActorId] = useState<string | undefined>();
  const [submitCampaignId, setSubmitCampaignId] = useState<string | undefined>();
  const [submitFamilyId, setSubmitFamilyId] = useState<string | undefined>();
  const [uploadActorId, setUploadActorId] = useState<string | undefined>();
  const [uploadCampaignId, setUploadCampaignId] = useState<string | undefined>();
  const [uploadFamilyId, setUploadFamilyId] = useState<string | undefined>();

  // .txt file import ref
  const txtFileRef = useRef<HTMLInputElement>(null);

  // Selection state
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [deleteOpen, setDeleteOpen] = useState(false);

  // Clear selection on page/filter change (adjust-during-render)
  const selectionScope = `${offset}|${statusFilter}|${activeSearch}`;
  const [prevSelectionScope, setPrevSelectionScope] = useState(selectionScope);
  if (selectionScope !== prevSelectionScope) {
    setPrevSelectionScope(selectionScope);
    setSelectedIds(new Set());
  }

  const isSearching = activeSearch.trim().length > 0;
  const searchParsed = parseSearch(activeSearch);

  const { data: listData, isLoading: listLoading } = useKits({
    offset,
    limit: PAGE_SIZE,
    status_filter: statusFilter === "all" ? undefined : statusFilter as KitStatus,
  });

  const { data: searchData, isLoading: searchLoading } = useSearchKits(
    { ...searchParsed, offset, limit: PAGE_SIZE },
    isSearching,
  );

  const data = isSearching ? searchData : listData;
  const isLoading = isSearching ? searchLoading : listLoading;
  const items = useMemo(() => data?.items ?? [], [data]);

  const pageIds = useMemo(() => items.map((k: KitSummary) => k.id), [items]);
  const allPageSelected = pageIds.length > 0 && pageIds.every((id: string) => selectedIds.has(id));
  const somePageSelected = pageIds.some((id: string) => selectedIds.has(id));

  const submitMutation = useSubmitKit();
  const bulkSubmitMutation = useBulkSubmitKits();
  const uploadMutation = useUploadKit();
  const bulkUploadMutation = useBulkUploadKits();
  const bulkDeleteMutation = useBulkDeleteKits();

  const toggleSelectAll = () => {
    if (allPageSelected) {
      setSelectedIds((prev) => {
        const next = new Set(prev);
        for (const id of pageIds) next.delete(id);
        return next;
      });
    } else {
      setSelectedIds((prev) => {
        const next = new Set(prev);
        for (const id of pageIds) next.add(id);
        return next;
      });
    }
  };

  const toggleSelect = (id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const handleBulkDelete = () => {
    const ids = Array.from(selectedIds);
    bulkDeleteMutation.mutate(ids, {
      onSuccess: (res) => {
        toast.success(`Deleted ${res.deleted} kit${res.deleted !== 1 ? "s" : ""}`);
        setSelectedIds(new Set());
        setDeleteOpen(false);
      },
      onError: (err) => toast.error(err.message),
    });
  };

  const handleSearch = () => {
    setActiveSearch(searchInput);
    setOffset(0);
    // Sync URL
    if (searchInput.trim()) {
      setSearchParams({ search: searchInput.trim() });
    } else {
      setSearchParams({});
    }
  };

  const clearSearch = () => {
    setSearchInput("");
    setActiveSearch("");
    setOffset(0);
    setSearchParams({});
  };

  const handleSubmit = () => {
    const urls = submitUrls
      .split("\n")
      .map((u) => u.trim())
      .filter((u) => u.length > 0);

    if (urls.length === 0) return;

    const entityIds = {
      actor_id: submitActorId,
      campaign_id: submitCampaignId,
      family_id: submitFamilyId,
    };

    const resetSubmit = () => {
      setSubmitUrls("");
      setSubmitOpen(false);
      setSubmitActorId(undefined);
      setSubmitCampaignId(undefined);
      setSubmitFamilyId(undefined);
    };

    if (urls.length === 1) {
      submitMutation.mutate(
        { url: urls[0], entityIds },
        {
          onSuccess: (res) => {
            toast.success(res.duplicate ? "Duplicate kit — already queued" : "Kit submitted for analysis");
            resetSubmit();
          },
          onError: (err) => toast.error(err.message),
        }
      );
    } else {
      bulkSubmitMutation.mutate(
        { urls, entityIds },
        {
          onSuccess: (res) => {
            const msg = res.skipped_duplicate > 0
              ? `${res.submitted} URLs submitted (${res.skipped_duplicate} duplicates skipped)`
              : `${res.submitted} URLs submitted for analysis`;
            toast.success(msg);
            resetSubmit();
          },
          onError: (err) => toast.error(err.message),
        }
      );
    }
  };

  const handleTxtImport = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      const text = reader.result as string;
      const lines = text.split(/\r?\n/).map((l) => l.trim()).filter((l) => l.length > 0);
      if (lines.length > 0) {
        setSubmitUrls((prev) => (prev.trim() ? prev.trim() + "\n" : "") + lines.join("\n"));
      }
    };
    reader.readAsText(file);
    e.target.value = "";
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(e.target.files ?? []);
    if (files.length > 0) {
      setSelectedFiles((prev) => [...prev, ...files]);
    }
    e.target.value = "";
  };

  const removeFile = (index: number) => {
    setSelectedFiles((prev) => prev.filter((_, i) => i !== index));
  };

  const handleUpload = () => {
    if (selectedFiles.length === 0) return;

    const entityIds = {
      actor_id: uploadActorId,
      campaign_id: uploadCampaignId,
      family_id: uploadFamilyId,
    };

    const resetUpload = () => {
      setSelectedFiles([]);
      setUploadOpen(false);
      setUploadActorId(undefined);
      setUploadCampaignId(undefined);
      setUploadFamilyId(undefined);
    };

    if (selectedFiles.length === 1) {
      uploadMutation.mutate(
        { file: selectedFiles[0], entityIds },
        {
          onSuccess: () => {
            toast.success("File uploaded for analysis");
            resetUpload();
          },
          onError: (err) => toast.error(err.message),
        }
      );
    } else {
      bulkUploadMutation.mutate(
        { files: selectedFiles, entityIds },
        {
          onSuccess: (res) => {
            toast.success(`${res.submitted} files uploaded for analysis`);
            resetUpload();
          },
          onError: (err) => toast.error(err.message),
        }
      );
    }
  };

  const isSubmitting = submitMutation.isPending || bulkSubmitMutation.isPending;
  const isUploading = uploadMutation.isPending || bulkUploadMutation.isPending;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold tracking-tight">Kits</h1>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => setUploadOpen(true)}>
            <Upload className="mr-2 h-4 w-4" />
            Upload
          </Button>
          <Dialog open={uploadOpen} onOpenChange={(open) => { setUploadOpen(open); if (!open) { setSelectedFiles([]); setUploadActorId(undefined); setUploadCampaignId(undefined); setUploadFamilyId(undefined); } }}>
            <DialogContent className="sm:max-w-3xl">
              <DialogHeader>
                <DialogTitle>Upload Files for Analysis</DialogTitle>
              </DialogHeader>
              <div className="space-y-3">
                <Input
                  type="file"
                  accept=".zip,.rar,.tar,.gz,.html,.eml,.png,.jpg,.jpeg,.gif,.bmp,.webp,.pdf"
                  multiple
                  onChange={handleFileSelect}
                />
                {selectedFiles.length > 0 && (
                  <div className="space-y-1 max-h-48 overflow-y-auto">
                    {selectedFiles.map((file, i) => (
                      <div key={`${file.name}-${i}`} className="flex items-center gap-2 text-sm text-muted-foreground bg-muted/50 rounded px-2 py-1">
                        <FileText className="h-3.5 w-3.5 shrink-0" />
                        <span className="truncate flex-1 font-mono text-xs">{file.name}</span>
                        <span className="text-xs shrink-0">{(file.size / 1024).toFixed(1)} KB</span>
                        <button onClick={() => removeFile(i)} className="shrink-0 hover:text-foreground">
                          <X className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
                <p className="text-xs text-muted-foreground">
                  {selectedFiles.length === 0
                    ? "Select one or more files (.zip, .rar, .tar, .gz, .html, .eml, .pdf, .png, .jpg)"
                    : `${selectedFiles.length} file${selectedFiles.length !== 1 ? "s" : ""} selected`}
                </p>
                <EntityLinkSelectors
                  actorId={uploadActorId}
                  campaignId={uploadCampaignId}
                  familyId={uploadFamilyId}
                  onActorChange={setUploadActorId}
                  onCampaignChange={setUploadCampaignId}
                  onFamilyChange={setUploadFamilyId}
                />
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => { setUploadOpen(false); setSelectedFiles([]); setUploadActorId(undefined); setUploadCampaignId(undefined); setUploadFamilyId(undefined); }}>
                  Cancel
                </Button>
                <Button onClick={handleUpload} disabled={selectedFiles.length === 0 || isUploading}>
                  {isUploading ? "Uploading..." : `Upload ${selectedFiles.length > 0 ? selectedFiles.length : ""} file${selectedFiles.length !== 1 ? "s" : ""}`}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>

          <Button size="sm" onClick={() => setSubmitOpen(true)}>
            <Plus className="mr-2 h-4 w-4" />
            Submit URLs
          </Button>
          <Dialog open={submitOpen} onOpenChange={(open) => { setSubmitOpen(open); if (!open) setSubmitUrls(""); }}>
            <DialogContent className="sm:max-w-3xl">
              <DialogHeader>
                <DialogTitle>Submit URLs for Analysis</DialogTitle>
              </DialogHeader>
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <label className="text-xs text-muted-foreground">One URL per line</label>
                  <div>
                    <input
                      ref={txtFileRef}
                      type="file"
                      accept=".txt"
                      onChange={handleTxtImport}
                      className="hidden"
                    />
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={() => txtFileRef.current?.click()}
                    >
                      Import from .txt
                    </Button>
                  </div>
                </div>
                <textarea
                  className="flex min-h-24 w-full rounded-md border border-input bg-transparent px-3 py-2 text-sm shadow-xs placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 font-mono"
                  placeholder={"https://example.com/kit1.zip\nhttps://example.com/kit2.zip\nhttps://example.com/kit3.zip"}
                  value={submitUrls}
                  onChange={(e) => setSubmitUrls(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) handleSubmit();
                  }}
                />
                <p className="text-xs text-muted-foreground">
                  {submitUrls.split("\n").filter((u) => u.trim()).length > 0
                    ? `${submitUrls.split("\n").filter((u) => u.trim()).length} URL${submitUrls.split("\n").filter((u) => u.trim()).length !== 1 ? "s" : ""}`
                    : "Ctrl+Enter to submit"}
                </p>
                <EntityLinkSelectors
                  actorId={submitActorId}
                  campaignId={submitCampaignId}
                  familyId={submitFamilyId}
                  onActorChange={setSubmitActorId}
                  onCampaignChange={setSubmitCampaignId}
                  onFamilyChange={setSubmitFamilyId}
                />
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => { setSubmitOpen(false); setSubmitUrls(""); setSubmitActorId(undefined); setSubmitCampaignId(undefined); setSubmitFamilyId(undefined); }}>
                  Cancel
                </Button>
                <Button onClick={handleSubmit} disabled={isSubmitting || !submitUrls.trim()}>
                  {isSubmitting ? "Submitting..." : "Submit"}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {/* Search + Filter bar */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-lg">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search URL, hash, yara:RuleName, tlsh:T1..."
            className="pl-9 font-mono text-sm"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") handleSearch();
              if (e.key === "Escape") clearSearch();
            }}
          />
          {activeSearch && (
            <button
              className="absolute right-2.5 top-2.5 text-muted-foreground hover:text-foreground"
              onClick={clearSearch}
            >
              <X className="h-4 w-4" />
            </button>
          )}
        </div>
        {!isSearching && (
          <Select value={statusFilter} onValueChange={(v) => { if (v) { setStatusFilter(v); setOffset(0); } }}>
            <SelectTrigger className="w-40">
              <SelectValue placeholder="Filter status" />
            </SelectTrigger>
            <SelectContent>
              {STATUSES.map((s) => (
                <SelectItem key={s} value={s}>
                  {s === "all" ? "All statuses" : s.charAt(0).toUpperCase() + s.slice(1)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}
        {isSearching && (
          <Badge variant="secondary" className="text-xs whitespace-nowrap">
            {searchParsed.yara_rule ? `YARA: ${searchParsed.yara_rule}` :
             searchParsed.tlsh ? "TLSH similarity" :
             `Text: ${searchParsed.q}`}
            {data && ` (${data.total} result${data.total !== 1 ? "s" : ""})`}
          </Badge>
        )}
      </div>

      {/* Selection action bar */}
      {selectedIds.size > 0 && (
        <div className="flex items-center gap-3 rounded-md border border-destructive/30 bg-destructive/5 px-4 py-2">
          <span className="text-sm font-medium">
            {selectedIds.size} kit{selectedIds.size !== 1 ? "s" : ""} selected
          </span>
          <Button
            variant="destructive"
            size="sm"
            onClick={() => setDeleteOpen(true)}
          >
            <Trash2 className="mr-1.5 h-3.5 w-3.5" />
            Delete
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setSelectedIds(new Set())}
          >
            Clear
          </Button>
        </div>
      )}

      {/* Bulk delete confirmation */}
      <Dialog open={deleteOpen} onOpenChange={setDeleteOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete {selectedIds.size} kit{selectedIds.size !== 1 ? "s" : ""}?</DialogTitle>
          </DialogHeader>
          <p className="text-sm text-muted-foreground">
            This will permanently delete the selected kits and all their associated data
            (child kits, indicators, analysis results). This action cannot be undone.
          </p>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleBulkDelete}
              disabled={bulkDeleteMutation.isPending}
            >
              {bulkDeleteMutation.isPending ? "Deleting..." : `Delete ${selectedIds.size} kit${selectedIds.size !== 1 ? "s" : ""}`}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Card>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="p-4">
              <TableLoading rows={PAGE_SIZE} />
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[40px] px-2">
                    <input
                      type="checkbox"
                      checked={allPageSelected}
                      ref={(el) => {
                        if (el) el.indeterminate = somePageSelected && !allPageSelected;
                      }}
                      onChange={toggleSelectAll}
                      className="h-4 w-4 rounded border-input accent-primary cursor-pointer"
                    />
                  </TableHead>
                  <TableHead className="w-[100px]">Status</TableHead>
                  <TableHead>Source URL</TableHead>
                  <TableHead>SHA256</TableHead>
                  <TableHead>Size</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead>Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((kit: KitSummary) => (
                  <TableRow
                    key={kit.id}
                    className={`cursor-pointer hover:bg-muted/50 ${selectedIds.has(kit.id) ? "bg-primary/5" : ""}`}
                  >
                    <TableCell className="px-2" onClick={(e) => e.stopPropagation()}>
                      <input
                        type="checkbox"
                        checked={selectedIds.has(kit.id)}
                        onChange={() => toggleSelect(kit.id)}
                        className="h-4 w-4 rounded border-input accent-primary cursor-pointer"
                      />
                    </TableCell>
                    <TableCell>
                      <KitStatusBadge status={kit.status} />
                    </TableCell>
                    <TableCell className="max-w-[350px] truncate font-mono text-xs">
                      <Link to={`/kits/${kit.id}`} className="hover:underline">
                        {kit.source_url}
                      </Link>
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {kit.sha256 ? `${kit.sha256.slice(0, 12)}...` : "—"}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {kit.file_size ? `${(kit.file_size / 1024).toFixed(1)} KB` : "—"}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {kit.source_feed ?? "—"}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                      {new Date(kit.created_at).toLocaleString()}
                    </TableCell>
                  </TableRow>
                ))}
                {items.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center text-muted-foreground py-8">
                      {isSearching ? "No kits match your search" : "No kits found"}
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {data && (
        <Pagination offset={offset} limit={PAGE_SIZE} total={data.total} onOffsetChange={setOffset} />
      )}
    </div>
  );
}
