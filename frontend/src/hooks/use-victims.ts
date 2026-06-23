// Read-only hooks.  Victim edits live behind `darla-admin victim
// reload --source <csv>` (RFC §9, Phase 6b).  The previous
// useUpdateVictim hook was removed alongside its HTTP endpoint.

import { useQuery } from "@tanstack/react-query";
import { victims } from "@/lib/api";
import type { VictimType } from "@/types/api";

interface VictimsListParams {
  offset?: number;
  limit?: number;
  domain?: string;
  type?: VictimType;
  search?: string;
}

export function useVictims(params?: VictimsListParams) {
  return useQuery({
    // The query key intentionally enumerates each filter rather than
    // hashing the whole object so React Query's cache invalidates
    // predictably when one filter changes (and we don't keep stale
    // results from a different filter mix).
    queryKey: [
      "victims",
      params?.offset ?? 0,
      params?.limit ?? 25,
      params?.domain ?? "",
      params?.type ?? "",
      params?.search ?? "",
    ],
    queryFn: () => victims.list(params),
  });
}

export function useVictim(id: string | undefined) {
  return useQuery({
    queryKey: ["victim", id],
    queryFn: () => victims.get(id!),
    enabled: !!id,
  });
}

export function useVictimObservations(
  id: string | undefined,
  offset = 0,
  limit = 100,
) {
  return useQuery({
    queryKey: ["victim", id, "observations", offset, limit],
    queryFn: () => victims.observations(id!, offset, limit),
    enabled: !!id,
  });
}
