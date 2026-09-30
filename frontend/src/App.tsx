import { Routes, Route } from "react-router-dom";
import { Shell } from "@/components/layout/shell";
import { AuthCallback } from "@/auth/Callback";
import { AuthGate } from "@/auth/AuthGate";
import { DashboardPage } from "@/pages/dashboard";
import { KitsPage } from "@/pages/kits";
import { KitDetailPage } from "@/pages/kit-detail";
import { InvestigationsPage } from "@/pages/investigations";
import { InvestigationDetailPage } from "@/pages/investigation-detail";
import { IndicatorsPage } from "@/pages/indicators";
import { ActorsPage } from "@/pages/actors";
import { ActorDetailPage } from "@/pages/actor-detail";
import { CampaignsPage } from "@/pages/campaigns";
import { CampaignDetailPage } from "@/pages/campaign-detail";
import { FamiliesPage } from "@/pages/families";
import { FamilyDetailPage } from "@/pages/family-detail";
import { PhishDiffPage } from "@/pages/phish-diff";
import { StageDetailPage } from "@/pages/stage-detail";
import { FlowDiffPage } from "@/pages/flow-diff";
import { StageClustersPage } from "@/pages/stage-clusters";
import { YaraPage } from "@/pages/yara";
import { PhishMatchPage } from "@/pages/phish-match";
import { PhishMatchInboxPage } from "@/pages/phish-match-inbox";
import { PhishPrintPage } from "@/pages/phishprint";
import { VictimDetailPage } from "@/pages/victim-detail";
import { UnauthorizedPage } from "@/pages/unauthorized";

export function App() {
  return (
    <Routes>
      {/* /auth/callback and /unauthorized render OUTSIDE the AuthGate
          so the gate doesn't redirect away from them mid-flow. */}
      <Route path="auth/callback" element={<AuthCallback />} />
      <Route path="unauthorized" element={<UnauthorizedPage />} />
      {/* Everything else flows through AuthGate, which is a no-op in
          disabled mode and triggers OIDC sign-in otherwise. */}
      <Route
        element={
          <AuthGate>
            <Shell />
          </AuthGate>
        }
      >
        <Route index element={<DashboardPage />} />
        <Route path="kits" element={<KitsPage />} />
        <Route path="kits/:id" element={<KitDetailPage />} />
        <Route path="investigations" element={<InvestigationsPage />} />
        <Route path="investigations/:id" element={<InvestigationDetailPage />} />
        <Route path="indicators" element={<IndicatorsPage />} />
        <Route path="actors" element={<ActorsPage />} />
        <Route path="actors/:id" element={<ActorDetailPage />} />
        <Route path="campaigns" element={<CampaignsPage />} />
        <Route path="campaigns/:id" element={<CampaignDetailPage />} />
        <Route path="families" element={<FamiliesPage />} />
        <Route path="families/:id" element={<FamilyDetailPage />} />
        <Route path="yara" element={<YaraPage />} />
        <Route path="phish-diff" element={<PhishDiffPage />} />
        <Route path="stages/:id" element={<StageDetailPage />} />
        <Route path="flow-diff" element={<FlowDiffPage />} />
        <Route path="stage-clusters" element={<StageClustersPage />} />
        <Route path="phish-match" element={<PhishMatchInboxPage />} />
        <Route path="phish-match/:kitId" element={<PhishMatchPage />} />
        <Route path="phishprint" element={<PhishPrintPage />} />
        <Route path="phishprint/victims/:id" element={<VictimDetailPage />} />
      </Route>
    </Routes>
  );
}
