import { useCallback, useEffect } from "react";
import { Link } from "react-router-dom";
import { ChevronLeft, ChevronRight, X, ExternalLink, ImageOff } from "lucide-react";
import { StageRoleBadge } from "@/components/shared/stage-role-badge";
import type { FlowStageNode } from "@/types/api";

export interface LightboxStage {
  stage: FlowStageNode;
  kitId: string;
  dataUri?: string;
}

/**
 * Full-screen screenshot viewer that steps forward/back through the flow's
 * stages in order. Left/right arrows (and ← → keys) move between pages;
 * Escape closes. Prev/next wrap is intentionally disabled so the ends are
 * obvious.
 */
export function StageLightbox({
  stages,
  index,
  onIndex,
  onClose,
}: {
  stages: LightboxStage[];
  index: number;
  onIndex: (i: number) => void;
  onClose: () => void;
}) {
  const atStart = index <= 0;
  const atEnd = index >= stages.length - 1;

  const prev = useCallback(() => {
    if (index > 0) onIndex(index - 1);
  }, [index, onIndex]);
  const next = useCallback(() => {
    if (index < stages.length - 1) onIndex(index + 1);
  }, [index, stages.length, onIndex]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "ArrowLeft") prev();
      else if (e.key === "ArrowRight") next();
      else if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [prev, next, onClose]);

  const current = stages[index];
  if (!current) return null;
  const { stage, kitId, dataUri } = current;

  return (
    <div
      className="fixed inset-0 z-50 flex flex-col bg-black/85 backdrop-blur-sm"
      onClick={onClose}
    >
      {/* Header */}
      <div
        className="flex items-center justify-between gap-3 px-4 py-3 text-white"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center gap-3 min-w-0">
          <StageRoleBadge role={stage.role} />
          <span className="text-sm font-medium">
            Stage {stage.seq + 1} of {stages.length}
          </span>
          <span className="font-mono text-xs text-white/60 truncate max-w-[40vw]">
            {stage.url ?? stage.host ?? "—"}
          </span>
        </div>
        <div className="flex items-center gap-3">
          <Link
            to={`/stages/${stage.id}`}
            className="flex items-center gap-1 text-xs text-white/70 hover:text-white"
          >
            <ExternalLink className="h-3.5 w-3.5" /> details
          </Link>
          <Link
            to={`/kits/${kitId}`}
            className="text-xs text-white/70 hover:text-white font-mono"
          >
            kit {kitId.slice(0, 8)}
          </Link>
          <button onClick={onClose} className="rounded p-1 hover:bg-white/10" aria-label="Close">
            <X className="h-5 w-5" />
          </button>
        </div>
      </div>

      {/* Body: prev | image | next */}
      <div className="flex flex-1 items-center gap-2 px-2 pb-4 min-h-0">
        <button
          onClick={(e) => { e.stopPropagation(); prev(); }}
          disabled={atStart}
          className="shrink-0 rounded-full p-2 text-white transition enabled:hover:bg-white/10 disabled:opacity-20"
          aria-label="Previous stage"
        >
          <ChevronLeft className="h-8 w-8" />
        </button>

        <div
          className="flex flex-1 items-center justify-center min-h-0 h-full"
          onClick={(e) => e.stopPropagation()}
        >
          {dataUri ? (
            <img
              src={dataUri}
              alt={`stage ${stage.seq}`}
              className="max-h-full max-w-full rounded-md border border-white/10 object-contain shadow-2xl"
            />
          ) : (
            <div className="flex flex-col items-center gap-2 text-white/40">
              <ImageOff className="h-10 w-10" />
              <span className="text-sm">No screenshot for this stage</span>
            </div>
          )}
        </div>

        <button
          onClick={(e) => { e.stopPropagation(); next(); }}
          disabled={atEnd}
          className="shrink-0 rounded-full p-2 text-white transition enabled:hover:bg-white/10 disabled:opacity-20"
          aria-label="Next stage"
        >
          <ChevronRight className="h-8 w-8" />
        </button>
      </div>

      {/* Filmstrip */}
      <div
        className="flex items-center justify-center gap-1.5 px-4 pb-4 overflow-x-auto"
        onClick={(e) => e.stopPropagation()}
      >
        {stages.map((s, i) => (
          <button
            key={s.stage.id}
            onClick={() => onIndex(i)}
            className={`h-1.5 rounded-full transition-all ${
              i === index ? "w-6 bg-white" : "w-2.5 bg-white/30 hover:bg-white/60"
            }`}
            aria-label={`Go to stage ${i + 1}`}
          />
        ))}
      </div>
    </div>
  );
}
