// Read-only hook.  Writes for monitored-domains live behind
// `darla-admin monitored-domain reload <yaml>` (RFC §9, Phase 6b).
// The previous useCreateMonitoredDomain / useUpdateMonitoredDomain /
// useDeleteMonitoredDomain hooks were removed alongside their
// underlying HTTP endpoints.

import { useQuery } from "@tanstack/react-query";
import { monitoredDomains } from "@/lib/api";

export function useMonitoredDomains(offset = 0, limit = 200) {
  return useQuery({
    queryKey: ["monitored-domains", offset, limit],
    queryFn: () => monitoredDomains.list(offset, limit),
  });
}
