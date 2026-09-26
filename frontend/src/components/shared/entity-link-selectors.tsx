import { useMemo } from "react";
import { useActors } from "@/hooks/use-actors";
import { useCampaigns } from "@/hooks/use-campaigns";
import { useFamilies } from "@/hooks/use-families";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

interface EntityLinkSelectorsProps {
  actorId: string | undefined;
  campaignId: string | undefined;
  familyId: string | undefined;
  onActorChange: (id: string | undefined) => void;
  onCampaignChange: (id: string | undefined) => void;
  onFamilyChange: (id: string | undefined) => void;
}

// Sentinel for the "None" option.  Base UI Select doesn't allow
// ``value=""`` on a SelectItem (it conflicts with the unselected
// state), so we use a distinct token here and translate at the
// component boundary.  Callers continue to receive ``undefined`` for
// no selection, same as before.
const NONE = "__none__";

// Base UI's ``<Select.Value>`` does NOT automatically render the
// selected ``<SelectItem>``'s children — by default it renders the
// raw ``value`` prop (a UUID in our case).  To map id → human-
// readable name we pass a children render function that looks the
// value up in a Map built from the loaded entity list.  Memoizing
// the Map prevents rebuilding on every render of the parent.

export function EntityLinkSelectors({
  actorId,
  campaignId,
  familyId,
  onActorChange,
  onCampaignChange,
  onFamilyChange,
}: EntityLinkSelectorsProps) {
  const { data: actorsData } = useActors(0, 200);
  const { data: campaignsData } = useCampaigns({ offset: 0, limit: 200 });
  const { data: familiesData } = useFamilies(0, 200);

  const actorNamesById = useMemo(
    () => new Map((actorsData?.items ?? []).map((a) => [a.id, a.name])),
    [actorsData],
  );
  const campaignNamesById = useMemo(
    () => new Map((campaignsData?.items ?? []).map((c) => [c.id, c.name])),
    [campaignsData],
  );
  const familyNamesById = useMemo(
    () => new Map((familiesData?.items ?? []).map((f) => [f.id, f.name])),
    [familiesData],
  );

  // Render-fn factory: returns "None" for the sentinel/empty case,
  // otherwise the entity's name (falling back to the raw value if
  // the names cache hasn't loaded yet — beats showing a blank
  // trigger).
  const renderName = (names: Map<string, string>) =>
    (value: string | null) => {
      if (!value || value === NONE) return "None";
      return names.get(value) ?? value;
    };

  return (
    <div className="space-y-2">
      <p className="text-xs text-muted-foreground font-medium">Link to (optional)</p>
      <div className="grid grid-cols-3 gap-3">
        <div>
          <label className="text-xs text-muted-foreground mb-1 block">Actor</label>
          <Select
            value={actorId ?? NONE}
            onValueChange={(v) =>
              onActorChange(v === NONE || v == null ? undefined : v)
            }
          >
            <SelectTrigger className="w-full">
              <SelectValue placeholder="None">
                {renderName(actorNamesById)}
              </SelectValue>
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={NONE}>None</SelectItem>
              {(actorsData?.items ?? []).map((a) => (
                <SelectItem key={a.id} value={a.id}>{a.name}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div>
          <label className="text-xs text-muted-foreground mb-1 block">Campaign</label>
          <Select
            value={campaignId ?? NONE}
            onValueChange={(v) =>
              onCampaignChange(v === NONE || v == null ? undefined : v)
            }
          >
            <SelectTrigger className="w-full">
              <SelectValue placeholder="None">
                {renderName(campaignNamesById)}
              </SelectValue>
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={NONE}>None</SelectItem>
              {(campaignsData?.items ?? []).map((c) => (
                <SelectItem key={c.id} value={c.id}>{c.name}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div>
          <label className="text-xs text-muted-foreground mb-1 block">Family</label>
          <Select
            value={familyId ?? NONE}
            onValueChange={(v) =>
              onFamilyChange(v === NONE || v == null ? undefined : v)
            }
          >
            <SelectTrigger className="w-full">
              <SelectValue placeholder="None">
                {renderName(familyNamesById)}
              </SelectValue>
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={NONE}>None</SelectItem>
              {(familiesData?.items ?? []).map((f) => (
                <SelectItem key={f.id} value={f.id}>{f.name}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>
    </div>
  );
}
