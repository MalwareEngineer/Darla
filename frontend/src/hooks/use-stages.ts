import { useQuery } from "@tanstack/react-query";
import { investigations, stages } from "@/lib/api";

export function useInvestigationFlow(id: string) {
  return useQuery({
    queryKey: ["investigation-flow", id],
    queryFn: () => investigations.flow(id),
    enabled: !!id,
  });
}

export function useFlowDiff(id: string, other: string) {
  return useQuery({
    queryKey: ["flow-diff", id, other],
    queryFn: () => investigations.flowDiff(id, other),
    enabled: !!id && !!other,
  });
}

export function useStage(id: string) {
  return useQuery({
    queryKey: ["stage", id],
    queryFn: () => stages.get(id),
    enabled: !!id,
  });
}

export function useSimilarStages(id: string, limit = 50) {
  return useQuery({
    queryKey: ["stage-similar", id, limit],
    queryFn: () => stages.similar(id, limit),
    enabled: !!id,
  });
}

export function useStageClusters(role: string) {
  return useQuery({
    queryKey: ["stage-clusters", role],
    queryFn: () => stages.clusters(role),
    enabled: !!role,
  });
}

export function useStageCooccurrence(roleA: string, roleB: string) {
  return useQuery({
    queryKey: ["stage-cooccurrence", roleA, roleB],
    queryFn: () => stages.cooccurrence(roleA, roleB),
    enabled: !!roleA && !!roleB,
  });
}
