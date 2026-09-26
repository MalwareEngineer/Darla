import { useState, useMemo } from "react";
import { Link } from "react-router-dom";
import { useInvestigations, useCreateInvestigation, useCreateInvestigationFromFile, useBulkDeleteInvestigations } from "@/hooks/use-investigations";
import { EntityLinkSelectors } from "@/components/shared/entity-link-selectors";
import { Pagination } from "@/components/shared/pagination";
import { TableLoading } from "@/components/shared/loading";
import { Card, CardContent } from "@/components/ui/card";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import {
  Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Plus, Trash2 } from "lucide-react";
import { toast } from "sonner";

const PAGE_SIZE = 25;
const FILE_ACCEPT = ".zip,.rar,.tar,.gz,.html,.eml,.png,.jpg,.jpeg,.gif,.bmp,.webp,.pdf";

export function InvestigationsPage() {
  const [offset, setOffset] = useState(0);
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [submitMode, setSubmitMode] = useState<"url" | "file">("url");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [actorId, setActorId] = useState<string | undefined>();
  const [campaignId, setCampaignId] = useState<string | undefined>();
  const [familyId, setFamilyId] = useState<string | undefined>();

  // Selection state
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [deleteOpen, setDeleteOpen] = useState(false);

  // Clear selection on page change (adjust-during-render, not an effect)
  const [selectionOffset, setSelectionOffset] = useState(offset);
  if (offset !== selectionOffset) {
    setSelectionOffset(offset);
    setSelectedIds(new Set());
  }

  const { data, isLoading } = useInvestigations(offset, PAGE_SIZE);
  const create = useCreateInvestigation();
  const createFromFile = useCreateInvestigationFromFile();
  const bulkDeleteMutation = useBulkDeleteInvestigations();

  const items = useMemo(() => data?.items ?? [], [data]);
  const pageIds = useMemo(() => items.map((inv) => inv.id), [items]);
  const allPageSelected = pageIds.length > 0 && pageIds.every((id) => selectedIds.has(id));
  const somePageSelected = pageIds.some((id) => selectedIds.has(id));

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
        toast.success(`Deleted ${res.deleted} investigation${res.deleted !== 1 ? "s" : ""}`);
        setSelectedIds(new Set());
        setDeleteOpen(false);
      },
      onError: (err) => toast.error(err.message),
    });
  };

  const resetForm = () => {
    setName("");
    setUrl("");
    setSubmitMode("url");
    setSelectedFile(null);
    setActorId(undefined);
    setCampaignId(undefined);
    setFamilyId(undefined);
  };

  const isCreating = create.isPending || createFromFile.isPending;
  const canSubmit = name.trim() && (submitMode === "url" ? url.trim() : selectedFile);

  const handleCreate = () => {
    if (!name.trim()) return;

    const onSuccess = () => {
      toast.success("Investigation started");
      resetForm();
      setOpen(false);
    };
    const onError = (err: Error) => toast.error(err.message);

    if (submitMode === "url") {
      if (!url.trim()) return;
      create.mutate(
        {
          name: name.trim(),
          url: url.trim(),
          actor_id: actorId,
          campaign_id: campaignId,
          family_id: familyId,
        },
        { onSuccess, onError }
      );
    } else {
      if (!selectedFile) return;
      const formData = new FormData();
      formData.append("name", name.trim());
      formData.append("file", selectedFile);
      if (actorId) formData.append("actor_id", actorId);
      if (campaignId) formData.append("campaign_id", campaignId);
      if (familyId) formData.append("family_id", familyId);
      createFromFile.mutate(formData, { onSuccess, onError });
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold tracking-tight">Investigations</h1>
        <Button size="sm" onClick={() => setOpen(true)}>
          <Plus className="mr-2 h-4 w-4" />
          New Investigation
        </Button>
        <Dialog open={open} onOpenChange={(o) => { setOpen(o); if (!o) resetForm(); }}>
          <DialogContent className="sm:max-w-3xl">
            <DialogHeader>
              <DialogTitle>Start Investigation</DialogTitle>
            </DialogHeader>
            <div className="space-y-4">
              <div>
                <label className="text-xs text-muted-foreground mb-1 block">Investigation Name *</label>
                <Input
                  placeholder="e.g. Tycoon2FA voicemail campaign April 2026"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
              </div>

              <div>
                <label className="text-xs text-muted-foreground mb-1 block">Source</label>
                <div className="flex gap-1 mb-2">
                  <Button
                    type="button"
                    variant={submitMode === "url" ? "default" : "outline"}
                    size="sm"
                    onClick={() => setSubmitMode("url")}
                  >
                    URL
                  </Button>
                  <Button
                    type="button"
                    variant={submitMode === "file" ? "default" : "outline"}
                    size="sm"
                    onClick={() => setSubmitMode("file")}
                  >
                    File
                  </Button>
                </div>
                {submitMode === "url" ? (
                  <Input
                    placeholder="https://..."
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                  />
                ) : (
                  <div className="space-y-2">
                    <Input
                      type="file"
                      accept={FILE_ACCEPT}
                      onChange={(e) => setSelectedFile(e.target.files?.[0] ?? null)}
                    />
                    {selectedFile && (
                      <p className="text-xs text-muted-foreground">
                        {selectedFile.name} ({(selectedFile.size / 1024).toFixed(1)} KB)
                      </p>
                    )}
                  </div>
                )}
              </div>

              <EntityLinkSelectors
                actorId={actorId}
                campaignId={campaignId}
                familyId={familyId}
                onActorChange={setActorId}
                onCampaignChange={setCampaignId}
                onFamilyChange={setFamilyId}
              />
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => { setOpen(false); resetForm(); }}>
                Cancel
              </Button>
              <Button onClick={handleCreate} disabled={isCreating || !canSubmit}>
                {isCreating ? "Starting..." : "Start"}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {/* Selection action bar */}
      {selectedIds.size > 0 && (
        <div className="flex items-center gap-3 rounded-md border border-destructive/30 bg-destructive/5 px-4 py-2">
          <span className="text-sm font-medium">
            {selectedIds.size} investigation{selectedIds.size !== 1 ? "s" : ""} selected
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
            <DialogTitle>Delete {selectedIds.size} investigation{selectedIds.size !== 1 ? "s" : ""}?</DialogTitle>
          </DialogHeader>
          <p className="text-sm text-muted-foreground">
            This will permanently delete the selected investigations. Root kits and their
            descendants will be cascade-deleted. Other linked kits will be preserved but
            unlinked. This action cannot be undone.
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
              {bulkDeleteMutation.isPending ? "Deleting..." : `Delete ${selectedIds.size} investigation${selectedIds.size !== 1 ? "s" : ""}`}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Card>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="p-4"><TableLoading /></div>
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
                  <TableHead>Status</TableHead>
                  <TableHead>Name</TableHead>
                  <TableHead>Total Kits</TableHead>
                  <TableHead>Depth</TableHead>
                  <TableHead>Max Depth</TableHead>
                  <TableHead>Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((inv) => (
                  <TableRow
                    key={inv.id}
                    className={`${selectedIds.has(inv.id) ? "bg-primary/5" : ""}`}
                  >
                    <TableCell className="px-2" onClick={(e) => e.stopPropagation()}>
                      <input
                        type="checkbox"
                        checked={selectedIds.has(inv.id)}
                        onChange={() => toggleSelect(inv.id)}
                        className="h-4 w-4 rounded border-input accent-primary cursor-pointer"
                      />
                    </TableCell>
                    <TableCell>
                      <Badge variant={inv.status === "completed" ? "default" : "secondary"}>
                        {inv.status}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <Link to={`/investigations/${inv.id}`} className="hover:underline">
                        {inv.name ?? inv.id.slice(0, 8)}
                      </Link>
                    </TableCell>
                    <TableCell>{inv.total_kits}</TableCell>
                    <TableCell>{inv.total_depth_reached}</TableCell>
                    <TableCell>{inv.max_depth}</TableCell>
                    <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                      {new Date(inv.created_at).toLocaleString()}
                    </TableCell>
                  </TableRow>
                ))}
                {items.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center text-muted-foreground py-8">
                      No investigations yet
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
