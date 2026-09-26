import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Pencil, Check, X } from "lucide-react";

interface EditableDescriptionProps {
  value: string | undefined | null;
  onSave: (value: string) => void;
  isPending?: boolean;
}

export function EditableDescription({ value, onSave, isPending }: EditableDescriptionProps) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(value ?? "");

  // Re-seed the draft when the saved value changes (adjust-during-render
  // pattern — avoids the extra render pass of a setState-in-effect).
  const [prevValue, setPrevValue] = useState(value);
  if (value !== prevValue) {
    setPrevValue(value);
    setDraft(value ?? "");
  }

  const handleSave = () => {
    onSave(draft);
    setEditing(false);
  };

  const handleCancel = () => {
    setDraft(value ?? "");
    setEditing(false);
  };

  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm font-medium">Description</CardTitle>
          {!editing && (
            <Button variant="ghost" size="sm" className="h-7 px-2" onClick={() => setEditing(true)}>
              <Pencil className="h-3.5 w-3.5" />
            </Button>
          )}
        </div>
      </CardHeader>
      <CardContent>
        {editing ? (
          <div className="space-y-2">
            <textarea
              className="flex min-h-[80px] w-full rounded-md border border-input bg-transparent px-3 py-2 text-sm shadow-sm placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-ring resize-y"
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              placeholder="Add a description..."
              autoFocus
            />
            <div className="flex gap-2">
              <Button size="sm" className="h-7" onClick={handleSave} disabled={isPending}>
                <Check className="h-3.5 w-3.5 mr-1" />
                {isPending ? "Saving..." : "Save"}
              </Button>
              <Button size="sm" variant="ghost" className="h-7" onClick={handleCancel}>
                <X className="h-3.5 w-3.5 mr-1" />
                Cancel
              </Button>
            </div>
          </div>
        ) : (
          <p
            className="text-sm text-muted-foreground cursor-pointer hover:text-foreground transition-colors"
            onClick={() => setEditing(true)}
          >
            {value || "No description — click to add"}
          </p>
        )}
      </CardContent>
    </Card>
  );
}
