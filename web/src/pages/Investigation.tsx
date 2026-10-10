import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useParams } from "react-router-dom";
import { get, post, type InvestigationStatus } from "../api";
import { Badge, ErrorBox, Loading, Tabs, useToast } from "../components/ui";
import { OverviewTab } from "../tabs/OverviewTab";
import { CollectTab } from "../tabs/CollectTab";
import { GraphTab } from "../tabs/GraphTab";
import { EntitiesTab } from "../tabs/EntitiesTab";
import { TimelineTab } from "../tabs/TimelineTab";
import { EvidenceTab } from "../tabs/EvidenceTab";
import { FindingsTab } from "../tabs/FindingsTab";
import { ReportsTab } from "../tabs/ReportsTab";
import { AskTab } from "../tabs/AskTab";
import { ReviewList } from "../tabs/ReviewList";
import { LinksTab } from "../tabs/LinksTab";

const TABS = [
  { id: "overview", label: "Overview" },
  { id: "collect", label: "Collect" },
  { id: "graph", label: "Graph" },
  { id: "entities", label: "Entities" },
  { id: "timeline", label: "Timeline" },
  { id: "evidence", label: "Evidence" },
  { id: "findings", label: "Findings" },
  { id: "links", label: "Connections" },
  { id: "ask", label: "Ask Claude" },
  { id: "reports", label: "Reports & export" },
  { id: "review", label: "Review" },
] as const;
type TabId = (typeof TABS)[number]["id"];

export function InvestigationPage() {
  const { id, tab } = useParams();
  const inv = Number(id);
  const nav = useNavigate();
  const status = useQuery({
    queryKey: ["inv", inv, "status"],
    queryFn: () => get<InvestigationStatus>(`/api/inv/${inv}/status`),
    refetchInterval: 6_000,
  });
  const qc = useQueryClient();
  const toast = useToast();
  const archive = useMutation({
    mutationFn: (archived: boolean) => post<{ status: string }>(`/api/inv/${inv}/archive`, { archived }),
    onSuccess: (r) => { qc.invalidateQueries(); toast(`Investigation ${r.status}`); },
    onError: (e: Error) => toast(e.message, true),
  });
  const active = (TABS.some((t) => t.id === tab) ? tab : "overview") as TabId;
  const s = status.data;
  const reviewN = s?.knowledge.review_open ?? 0;

  return (
    <div className="page">
      {status.isLoading && <Loading />}
      <ErrorBox error={status.error} />
      {s && (
        <>
          <div className="spread">
            <div>
              <div className="row">
                <h1>{s.name}</h1>
                {s.profile === "anonymous" ? <Badge tone="tor" title="All collection through Tor">anonymous · Tor</Badge>
                  : <Badge title="direct, then VPN when blocked, then browser">standard network</Badge>}
                <span className="muted small">#{s.id}</span>
                {s.status === "archived" && <Badge tone="warn">archived</Badge>}
              </div>
              <div className="muted">{s.seed.focus ?? "No focus set"}</div>
            </div>
            {s.status === "archived"
              ? <button onClick={() => archive.mutate(false)}>Restore</button>
              : <button className="ghost" title="Hide it and stop its schedule. Evidence and knowledge are kept."
                  onClick={() => window.confirm(`Archive ${s.name}? It is hidden and its schedule stops; nothing is deleted.`) && archive.mutate(true)}>Archive</button>}
          </div>
          <Tabs<TabId>
            tabs={TABS.map((t) => ({ id: t.id, label: t.id === "review" && reviewN ? <>Review <span className="count">{reviewN}</span></> : t.label }))}
            value={active}
            onChange={(t) => nav(`/inv/${inv}/${t}`)}
          />
          {active === "overview" && <OverviewTab inv={inv} status={s} />}
          {active === "collect" && <CollectTab inv={inv} />}
          {active === "graph" && <GraphTab inv={inv} />}
          {active === "entities" && <EntitiesTab inv={inv} />}
          {active === "timeline" && <TimelineTab inv={inv} />}
          {active === "evidence" && <EvidenceTab inv={inv} />}
          {active === "findings" && <FindingsTab inv={inv} />}
          {active === "links" && <LinksTab inv={inv} />}
          {active === "ask" && <AskTab inv={inv} />}
          {active === "reports" && <ReportsTab inv={inv} />}
          {active === "review" && <ReviewList inv={inv} />}
        </>
      )}
    </div>
  );
}
