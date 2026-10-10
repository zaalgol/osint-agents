import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import cytoscape, { type Core, type ElementDefinition } from "cytoscape";
// @ts-expect-error - no type definitions for this layout plugin
import fcose from "cytoscape-fcose";
import { get } from "../api";
import { Empty, ErrorBox, Loading, TYPE_COLORS, typeColor } from "../components/ui";

cytoscape.use(fcose);

interface GraphData { nodes: ElementDefinition[]; edges: ElementDefinition[] }

export function GraphTab({ inv }: { inv: number }) {
  const q = useQuery({ queryKey: ["inv", inv, "graph"], queryFn: () => get<GraphData>(`/api/inv/${inv}/graph`) });
  const box = useRef<HTMLDivElement>(null);
  const cy = useRef<Core | null>(null);
  const nav = useNavigate();
  const [events, setEvents] = useState(false);
  const [mentions, setMentions] = useState(false);
  const [hidden, setHidden] = useState<Set<string>>(new Set(["location"]));
  const [filter, setFilter] = useState("");

  const types = useMemo(() => [...new Set((q.data?.nodes ?? []).map((n) => String(n.data.type)))].sort(), [q.data]);

  useEffect(() => {
    if (!box.current || !q.data) return;
    const nodes = q.data.nodes.filter((n) => !hidden.has(String(n.data.type)));
    const ids = new Set(nodes.map((n) => n.data.id));
    const edges = q.data.edges.filter((e) => ids.has(e.data.source!) && ids.has(e.data.target!) && (events || e.data.label !== "same event") && (mentions || e.data.label !== "mentions"));
    const connected = new Set(edges.flatMap((e) => [e.data.source, e.data.target]));
    const shown = nodes.filter((n) => connected.has(n.data.id) || nodes.length < 60);
    cy.current?.destroy();
    const dark = getComputedStyle(document.documentElement).getPropertyValue("--text").trim();
    cy.current = cytoscape({
      container: box.current,
      elements: [...shown, ...edges],
      maxZoom: 3,
      minZoom: 0.05,
      style: [
        { selector: "node", style: {
          "background-color": (n: cytoscape.NodeSingular) => typeColor(n.data("type")),
          label: "data(label)", color: dark || "#222", "font-size": 10, "text-wrap": "ellipsis",
          "text-max-width": "120px", "text-valign": "bottom", "text-margin-y": 4,
          "min-zoomed-font-size": 7,          // unreadable labels are hidden until you zoom in
          width: (n: cytoscape.NodeSingular) => 12 + Math.min(28, n.degree(false) * 2.2),
          height: (n: cytoscape.NodeSingular) => 12 + Math.min(28, n.degree(false) * 2.2),
        } },
        { selector: "edge", style: {
          width: 1.2, "line-color": "#8894a3", "target-arrow-color": "#8894a3",
          "target-arrow-shape": "triangle", "curve-style": "bezier", label: "data(label)",
          "font-size": 8, color: "#8894a3", "text-rotation": "autorotate", opacity: 0.85,
          "min-zoomed-font-size": 9,
        } },
        { selector: 'edge[label = "same event"]', style: { "line-style": "dashed", "target-arrow-shape": "none", label: "" } },
        { selector: ".dim", style: { opacity: 0.12 } },
        { selector: ".hit", style: { "border-width": 3, "border-color": "#f5a524" } },
      ],
      layout: { name: shown.length > 400 ? "cose" : "fcose", animate: false, nodeRepulsion: 9000, idealEdgeLength: 90 } as cytoscape.LayoutOptions,
    });
    cy.current.one("layoutstop", () => {
      const c = cy.current;
      if (c && c.zoom() > 1.3) { c.zoom(1.3); c.center(); }   // few nodes: don't blow labels up
    });
    if (cy.current.zoom() > 1.3) { cy.current.zoom(1.3); cy.current.center(); }
    cy.current.on("tap", "node", (e) => nav(`/entity/${e.target.data("eid")}?inv=${inv}`));
    cy.current.on("mouseover", "node", (e) => {
      const nb = e.target.closedNeighborhood();
      cy.current!.elements().not(nb).addClass("dim");
    });
    cy.current.on("mouseout", "node", () => cy.current!.elements().removeClass("dim"));
    return () => { cy.current?.destroy(); cy.current = null; };
  }, [q.data, hidden, events, mentions, inv, nav]);

  useEffect(() => {
    const c = cy.current;
    if (!c) return;
    c.nodes().removeClass("hit");
    if (filter.trim().length >= 2) {
      const hits = c.nodes().filter((n) => String(n.data("label")).toLowerCase().includes(filter.toLowerCase()));
      hits.addClass("hit");
      if (hits.length) c.fit(hits, 80);
    }
  }, [filter]);

  if (q.isLoading) return <Loading what="Loading graph" />;
  if (q.error) return <ErrorBox error={q.error} />;
  if (!q.data?.nodes.length) return <Empty>No entities yet. Run collection first.</Empty>;
  return (
    <div className="stack">
      <div className="spread">
        <div className="legend">
          {types.map((t) => (
            <label key={t} className="check" style={{ gap: 4, opacity: hidden.has(t) ? 0.45 : 1 }}>
              <input type="checkbox" checked={!hidden.has(t)} onChange={() => {
                const next = new Set(hidden);
                if (next.has(t)) next.delete(t); else next.add(t);
                setHidden(next);
              }} />
              <span className="dot" style={{ background: TYPE_COLORS[t] ?? "#6c7a89" }} /> {t.replace(/_/g, " ")}
            </label>
          ))}
        </div>
        <div className="row">
          <label className="check small"><input type="checkbox" checked={mentions} onChange={(e) => setMentions(e.target.checked)} /> “mentions” links</label>
          <label className="check small"><input type="checkbox" checked={events} onChange={(e) => setEvents(e.target.checked)} /> co-participation in events</label>
          <input style={{ width: 200 }} placeholder="Find in graph…" value={filter} onChange={(e) => setFilter(e.target.value)} />
          <button className="small" onClick={() => cy.current?.fit(undefined, 30)}>Fit</button>
        </div>
      </div>
      <div ref={box} className="graph-box" />
      <div className="muted small">Click a node to open the entity. Node size = number of connections. Locations are hidden by default (toggle above).</div>
    </div>
  );
}
