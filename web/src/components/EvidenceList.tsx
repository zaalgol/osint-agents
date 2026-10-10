import { useQuery } from "@tanstack/react-query";
import { get, markerId, type EvidenceItem } from "../api";
import { ErrorBox, EvidenceQuote, Loading } from "./ui";

// Loads and shows citations ([E:n] markers) with quote, Admiralty code and source.
export function EvidenceList({ inv, markers, preloaded }: {
  inv: number; markers: string[]; preloaded?: Record<string, EvidenceItem>;
}) {
  const missing = markers.filter((m) => !preloaded?.[m]);
  const q = useQuery({
    queryKey: ["evidence", inv, missing.join(",")],
    queryFn: () => get<EvidenceItem[]>(`/api/evidence?inv=${inv}&ids=${missing.map(markerId).join(",")}`),
    enabled: missing.length > 0,
  });
  if (q.isLoading) return <Loading what="Loading evidence" />;
  const byMarker: Record<string, EvidenceItem> = { ...(preloaded ?? {}) };
  for (const e of q.data ?? []) byMarker[e.marker] = e;
  return (
    <div className="stack">
      <ErrorBox error={q.error} />
      {markers.map((m) => byMarker[m] ? <EvidenceQuote key={m} ev={byMarker[m]} /> : <div key={m} className="muted small">{m}</div>)}
    </div>
  );
}
