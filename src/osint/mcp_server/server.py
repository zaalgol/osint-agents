"""osint MCP server: exposes AnalystTools to headless Claude (stdio transport).

Configured per job by environment variables (set by osint.llm.claude_cli):
  OSINT_INVESTIGATION_ID  investigation that write tools are scoped to (required)
  OSINT_JOB               job name, recorded as the actor ("claude:<job>")
  OSINT_TOOLSET           "read" (Q&A) or "full" (analysis: findings, collection, reports)
  OSINT_MAX_REQUESTS      collection request budget for this job
"""

from __future__ import annotations

import logging
import os
from typing import Any

from mcp.server.mcpserver import MCPServer

from osint.analyst.tools import AnalystTools
from osint.core.config import get_models_config
from osint.core.context import App

INSTRUCTIONS = """Knowledge base of an OSINT system. Every fact comes with evidence markers \
[E:n] (verbatim quotes from preserved, hash-verified sources); findings you record get \
markers [F:n]. Cite only markers returned by these tools. Never invent ids."""


def build_server(tools: AnalystTools, toolset: str = "full") -> MCPServer:
    server = MCPServer("osint", instructions=INSTRUCTIONS)

    # ---------------------------------------------------------------- read
    @server.tool()
    def investigation_overview(investigation: int | str | None = None) -> dict:
        """Start here. Counts, seed and plan, most connected entities, recent events,
        number of findings, and how many entities are shared with other investigations.
        Defaults to the job's investigation."""
        return tools.investigation_overview(investigation)

    @server.tool()
    def search_entities(query: str, type: str | None = None,
                        investigation: int | str | None = None, limit: int = 20) -> list[dict]:
        """Find entities by name/alias (normalized; works across scripts' diacritics).
        Searches ALL investigations unless `investigation` is given."""
        return tools.search_entities(query, type, investigation, limit)

    @server.tool()
    def get_entity(entity_id: int) -> dict:
        """One entity: aliases, investigations it appears in, relations and events, each
        with [E:n] evidence markers."""
        return tools.get_entity(entity_id)

    @server.tool()
    def neighborhood(entity_ids: list[int], hops: int = 1,
                     investigation: int | str | None = None) -> dict:
        """Link graph around entities (relations + shared events), 1-2 hops."""
        return tools.neighborhood(entity_ids, hops, investigation)

    @server.tool()
    def search_documents(query: str, investigation: int | str | None = None,
                         limit: int = 10) -> list[dict]:
        """Full-text search of collected documents (web search syntax: "exact phrase",
        OR, -exclude). Returns snippets with document ids."""
        return tools.search_documents(query, investigation, limit)

    @server.tool()
    def read_document(document_id: int, start: int = 0, length: int = 4000) -> dict:
        """Read part of a collected document (max 8000 chars per call). Reading is for
        understanding; cite with [E:n] evidence markers, not with document ids."""
        return tools.read_document(document_id, start, length)

    @server.tool()
    def get_evidence(evidence_ids: list[int]) -> list[dict]:
        """Citation details for [E:n] markers: verbatim quote, translation, source URL,
        post/capture time, SHA-256, source reliability grade, surrounding context."""
        return tools.get_evidence(evidence_ids)

    @server.tool()
    def timeline(investigation: int | str | None = None, start: str | None = None,
                 end: str | None = None, limit: int = 100) -> list[dict]:
        """Events in chronological order with participants, location and evidence."""
        return tools.timeline(investigation, start, end, limit)

    @server.tool()
    def list_findings(investigation: int | str | None = None) -> list[dict]:
        """Findings recorded so far ([F:n] markers) with their evidence."""
        return tools.list_findings(investigation)

    @server.tool()
    def shared_entities(investigation: int | str | None = None) -> list[dict]:
        """Entities of this investigation that also appear in other investigations
        (exact identifier/name matches): starting points for cross-case links."""
        return tools.shared_entities(investigation)

    @server.tool()
    def cross_links(investigation: int | str | None = None,
                    status: str | None = None) -> list[dict]:
        """Links between this investigation and others. status: candidate | confirmed |
        rejected. tier: hard (same entity) | soft (similar events, possibly same entity) |
        analytic (confirmed by an analyst)."""
        return tools.cross_links(investigation, status)

    @server.tool()
    def key_players(investigation: int | str | None = None, top: int = 15) -> dict:
        """Network analysis: most central entities (high betweenness = brokers linking
        otherwise separate groups) and communities. investigation="all" for everything."""
        return tools.key_players(investigation, top)

    @server.tool()
    def shortest_path(entity_a: int, entity_b: int, max_hops: int = 6) -> dict:
        """Shortest chain of relations/shared events connecting two entities, across
        all investigations."""
        return tools.shortest_path(entity_a, entity_b, max_hops)

    @server.tool()
    def graph_query(cypher: str, params: dict | None = None) -> list[dict]:
        """Read-only Cypher. Model: (:Entity {pg_id,name,type})-[:REL {type,pg_id,sources}]->
        (:Entity); (:Entity)-[:PARTICIPATED {role}]->(:Event {pg_id,type,time,description});
        (:Entity)-[:IN]->(:Investigation {pg_id,name}); (:Investigation)-[:LINKED]->(...)."""
        return tools.graph_query(cypher, params)

    @server.tool()
    def contradictions(investigation: int | str | None = None) -> list[dict]:
        """Same incident reported with conflicting facts (e.g. dates). Address these in
        findings and reports; don't silently pick one side."""
        return tools.contradictions(investigation)

    if toolset != "full":
        return server

    # ---------------------------------------------------------------- write
    @server.tool()
    def add_finding(text: str, kind: str, confidence: float, epistemic_status: str,
                    evidence_ids: list[int] | None = None, premises: list[dict] | None = None,
                    method: str | None = None) -> dict:
        """Record a finding. kind: fact|pattern|assessment|hypothesis|gap.
        epistemic_status: observed (directly visible in evidence) | reported (a source says
        it) | inferred (derived from other facts) | assessed (analytic judgement).
        observed/reported need evidence_ids. inferred/assessed need premises
        ([{"type": "evidence|relation|event|claim|finding", "id": n}]) and `method`
        (how the premises lead to the conclusion). Returns the [F:n] marker."""
        return tools.add_finding(text, kind, confidence, epistemic_status, evidence_ids,
                                 premises, method)

    @server.tool()
    def request_collection(plugin: str, params: dict[str, Any], reason: str,
                           priority: int = 100) -> dict:
        """Queue collection by the local agents (runs on the next `osint run`).
        plugins: searxng {"queries": [...], "language": "ar", "time_range": "month",
        "max_results": 10}; web {"urls": [...]}; rss {"feeds": [...]}."""
        return tools.request_collection(plugin, params, reason, priority)

    @server.tool()
    def confirm_cross_link(link_id: int, explanation: str, evidence_ids: list[int],
                           premises: list[dict] | None = None, confidence: float = 0.7) -> dict:
        """Confirm a candidate link between investigations. Needs evidence_ids (ideally
        from both investigations) and an explanation of what actually connects them."""
        return tools.confirm_cross_link(link_id, explanation, evidence_ids, premises,
                                        confidence)

    @server.tool()
    def reject_cross_link(link_id: int, reason: str) -> dict:
        """Reject a candidate link, e.g. a generic place or a common name with no real
        connection."""
        return tools.reject_cross_link(link_id, reason)

    @server.tool()
    async def write_report(title: str, markdown: str, supersedes_id: int | None = None) -> dict:
        """Save a report (Markdown) and run the citation gate. Every factual sentence
        needs [E:n] or [F:n] markers that support it. Methodology/Limitations/Sources
        sections are exempt. If `ok` is false, fix the listed sentences and resubmit with
        supersedes_id."""
        return await tools.write_report(title, markdown, supersedes_id)

    @server.tool()
    async def verify_report(report_id: int) -> dict:
        """Re-run the citation gate on a stored report."""
        return await tools.verify_report(report_id)

    return server


def main() -> None:
    logging.basicConfig(level=logging.WARNING)
    inv = int(os.environ["OSINT_INVESTIGATION_ID"])
    job = os.environ.get("OSINT_JOB", "analyst")
    toolset = os.environ.get("OSINT_TOOLSET", "full")
    app = App()
    judge = None
    if toolset == "full":
        from osint.llm.local import LocalLLM
        from osint.reports.verify import llm_judge

        llm = LocalLLM(get_models_config().local, slots=app.settings.concurrency.llm_slots)
        judge = llm_judge(llm)
    tools = AnalystTools(
        session_factory=app.session_factory, ontology=app.ontology, registry=app.registry,
        raw_store=app.raw_store, investigation_id=inv, actor=f"claude:{job}",
        max_collection_requests=int(os.environ.get("OSINT_MAX_REQUESTS", "30")), judge=judge,
        neo4j=app.settings.neo4j,
    )
    build_server(tools, toolset).run("stdio")
