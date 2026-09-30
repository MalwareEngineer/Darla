import { useState } from "react";
import { useParams, Link, useNavigate } from "react-router-dom";
import { useInvestigation, useInvestigationTree, useUpdateInvestigation, useDeleteInvestigation } from "@/hooks/use-investigations";
import { useInvestigationFlow } from "@/hooks/use-stages";
import { FlowView } from "@/components/shared/flow-view";
import { EditableDescription } from "@/components/shared/editable-description";
import { KitStatusBadge } from "@/components/shared/kit-status-badge";
import { PageLoading } from "@/components/shared/loading";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Trash2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import type { InvestigationTreeNode } from "@/types/api";

export function InvestigationDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { data: inv, isLoading } = useInvestigation(id!);
  const { data: tree } = useInvestigationTree(id!);
  const { data: flow } = useInvestigationFlow(id!);
  const updateMutation = useUpdateInvestigation();
  const deleteMutation = useDeleteInvestigation();
  const [deleteOpen, setDeleteOpen] = useState(false);

  if (isLoading || !inv) return <PageLoading />;

  const handleDelete = () => {
    deleteMutation.mutate(id!, {
      onSuccess: () => {
        toast.success("Investigation deleted");
        navigate("/investigations");
      },
      onError: (err) => toast.error(err.message),
    });
  };

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div className="space-y-1">
          <h1 className="text-2xl font-bold tracking-tight">
            {inv.name ?? `Investigation ${inv.id.slice(0, 8)}`}
          </h1>
          <div className="flex items-center gap-3 text-sm text-muted-foreground">
            <Badge variant={inv.status === "completed" ? "default" : "secondary"}>
              {inv.status}
            </Badge>
            <span>{inv.total_kits} kits</span>
            <span>depth {inv.total_depth_reached}/{inv.max_depth}</span>
            <span>{new Date(inv.created_at).toLocaleString()}</span>
          </div>
        </div>
        <Button variant="destructive" size="sm" onClick={() => setDeleteOpen(true)}>
          <Trash2 className="mr-1.5 h-3.5 w-3.5" />
          Delete
        </Button>
      </div>

      {/* Delete confirmation dialog */}
      <Dialog open={deleteOpen} onOpenChange={setDeleteOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete investigation?</DialogTitle>
          </DialogHeader>
          <p className="text-sm text-muted-foreground">
            This will permanently delete this investigation. The root kit and all its
            descendant kits will be cascade-deleted along with their indicators and
            analysis results. Other linked kits will be preserved but unlinked.
          </p>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleDelete}
              disabled={deleteMutation.isPending}
            >
              {deleteMutation.isPending ? "Deleting..." : "Delete Investigation"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <EditableDescription
        value={inv.description}
        onSave={(description) =>
          updateMutation.mutate(
            { id: id!, description },
            {
              onSuccess: () => toast.success("Description updated"),
              onError: (err) => toast.error(err.message),
            }
          )
        }
        isPending={updateMutation.isPending}
      />

      {inv.root_kit && (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-medium">Root Kit</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-3">
              <KitStatusBadge status={inv.root_kit.status} />
              <Link to={`/kits/${inv.root_kit.id}`} className="font-mono text-sm hover:underline">
                {inv.root_kit.source_url}
              </Link>
            </div>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader className="flex-row items-center justify-between space-y-0">
          <CardTitle className="text-sm font-medium">Attack Flow</CardTitle>
          <Link to={`/flow-diff?a=${id}`} className="text-xs text-primary hover:underline">
            Compare with another flow →
          </Link>
        </CardHeader>
        <CardContent>
          <FlowView nodes={flow ?? []} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">Investigation Tree</CardTitle>
        </CardHeader>
        <CardContent>
          {tree && tree.length > 0 ? (
            <div className="space-y-1">
              {tree.map((node) => (
                <TreeNodeView key={node.kit.id} node={node} depth={0} />
              ))}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No tree data available</p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function TreeNodeView({ node, depth }: { node: InvestigationTreeNode; depth: number }) {
  return (
    <div>
      <div
        className={cn("flex items-center gap-2 rounded-md px-2 py-1.5 hover:bg-muted/50")}
        style={{ paddingLeft: `${depth * 24 + 8}px` }}
      >
        {depth > 0 && <span className="text-muted-foreground">└─</span>}
        <KitStatusBadge status={node.kit.status} />
        <Link to={`/kits/${node.kit.id}`} className="font-mono text-xs hover:underline truncate max-w-md">
          {node.kit.source_url}
        </Link>
        {node.discovery_method && (
          <Badge variant="outline" className="text-[10px]">
            {node.discovery_method}
          </Badge>
        )}
      </div>
      {node.nav_path && node.nav_path.length > 1 && (
        <div
          className="flex items-center gap-1 flex-wrap text-[10px] text-muted-foreground font-mono py-0.5"
          style={{ paddingLeft: `${depth * 24 + 28}px` }}
          title="Hosts the browser navigated through during this render"
        >
          <span className="text-muted-foreground/70">via</span>
          {node.nav_path.map((host, i) => (
            <span key={`${host}-${i}`} className="flex items-center gap-1">
              {i > 0 && <span className="text-muted-foreground/50">→</span>}
              <span>{host}</span>
            </span>
          ))}
        </div>
      )}
      {node.children.map((child) => (
        <TreeNodeView key={child.kit.id} node={child} depth={depth + 1} />
      ))}
    </div>
  );
}
