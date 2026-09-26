import { useMemo } from "react";
import { CheckCircle, XCircle, Circle, Loader2, Minus } from "lucide-react";
import type { AnalysisResultBrief, AnalysisType, KitStatus } from "@/types/api";

interface Props {
  results: AnalysisResultBrief[];
  status: KitStatus;
}

interface PipelineStep {
  type: AnalysisType;
  label: string;
  core: boolean;
}

const CORE_STEPS: PipelineStep[] = [
  { type: "hash", label: "Hash", core: true },
  { type: "deobfuscation", label: "Deobfuscate", core: true },
  { type: "yara_scan", label: "YARA", core: true },
  { type: "ioc_extraction", label: "IOC Extract", core: true },
  { type: "similarity", label: "Similarity", core: true },
];

const CONDITIONAL_STEPS: PipelineStep[] = [
  { type: "eml_parse", label: "EML Parse", core: false },
  { type: "qr_decode", label: "QR Decode", core: false },
  { type: "redirect_chain", label: "Redirects", core: false },
  { type: "external_js_fetch", label: "Ext JS", core: false },
  { type: "link_score", label: "Link Score", core: false },
];

type StepState = "completed" | "error" | "running" | "pending" | "skipped";

export function AnalysisPipeline({ results, status }: Props) {
  const steps = useMemo(() => {
    const resultMap = new Map(results.map((r) => [r.analysis_type, r]));

    // Include conditional steps only if they have results
    const activeSteps = [
      ...CORE_STEPS,
      ...CONDITIONAL_STEPS.filter((s) => resultMap.has(s.type)),
    ];

    // Find the last completed step index to determine the "running" step
    let lastCompletedIdx = -1;
    for (let i = 0; i < activeSteps.length; i++) {
      if (resultMap.has(activeSteps[i].type)) {
        lastCompletedIdx = i;
      }
    }

    return activeSteps.map((step, i) => {
      const result = resultMap.get(step.type);
      let state: StepState;

      if (result) {
        state = result.error ? "error" : "completed";
      } else if (status === "analyzing") {
        state = i === lastCompletedIdx + 1 ? "running" : "pending";
      } else {
        // analyzed or failed — anything without a result was skipped
        state = "skipped";
      }

      return { ...step, state };
    });
  }, [results, status]);

  return (
    <div className="flex items-center gap-0.5 overflow-x-auto py-1">
      {steps.map((step, i) => (
        <div key={step.type} className="flex items-center">
          {i > 0 && (
            <div className={`w-4 h-px mx-0.5 ${
              step.state === "completed" || step.state === "error"
                ? "bg-muted-foreground/40"
                : "bg-muted-foreground/15"
            }`} />
          )}
          <div className="flex flex-col items-center gap-0.5 min-w-[48px]">
            <StepIcon state={step.state} />
            <span className={`text-[10px] leading-tight whitespace-nowrap ${
              step.state === "completed"
                ? "text-muted-foreground"
                : step.state === "error"
                ? "text-red-400"
                : step.state === "running"
                ? "text-foreground"
                : "text-muted-foreground/40"
            }`}>
              {step.label}
            </span>
          </div>
        </div>
      ))}
    </div>
  );
}

function StepIcon({ state }: { state: StepState }) {
  switch (state) {
    case "completed":
      return <CheckCircle className="h-3.5 w-3.5 text-green-400" />;
    case "error":
      return <XCircle className="h-3.5 w-3.5 text-red-400" />;
    case "running":
      return <Loader2 className="h-3.5 w-3.5 text-blue-400 animate-spin" />;
    case "pending":
      return <Circle className="h-3.5 w-3.5 text-muted-foreground/30" />;
    case "skipped":
      return <Minus className="h-3.5 w-3.5 text-muted-foreground/20" />;
  }
}
