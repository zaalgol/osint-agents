"""PluginContext: the only door plugins have to storage, models, network and config.

Plugins never open their own DB connections or HTTP clients, so policy (rate limits,
proxies, provenance logging) is enforced in one place. Async services (HTTP fetcher,
browser, local LLM) are opened by ``App.services()`` and closed together.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from functools import cached_property
from typing import TYPE_CHECKING

from sqlalchemy.orm import Session, sessionmaker

from osint.core.config import ModelsConfig, Settings, get_models_config, get_settings
from osint.core.ontology import Ontology
from osint.core.plugins import PluginRegistry, build_registry
from osint.storage.raw_store import RawStore

if TYPE_CHECKING:
    from osint.evidence.browser import BrowserCapturer
    from osint.llm.local import LocalLLM
    from osint.net.http import Fetcher


@dataclass
class PluginContext:
    settings: Settings
    models: ModelsConfig
    ontology: Ontology
    registry: PluginRegistry
    raw_store: RawStore
    session_factory: sessionmaker[Session] | None = None
    investigation_id: int | None = None
    http: Fetcher | None = None
    browser: BrowserCapturer | None = None
    llm: LocalLLM | None = None
    log: logging.Logger = field(default_factory=lambda: logging.getLogger("osint.plugin"))

    def session(self) -> Session:
        if self.session_factory is None:
            raise RuntimeError("no database configured for this context")
        return self.session_factory()


class App:
    """Lazily assembled application services (shared by the CLI, orchestrator and MCP server)."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    @cached_property
    def registry(self) -> PluginRegistry:
        return build_registry(self.settings.resolve(d) for d in self.settings.plugin_dirs)

    @cached_property
    def ontology(self) -> Ontology:
        files = [self.settings.resolve(f) for f in self.settings.ontology_files]
        return Ontology.load(files + self.registry.ontology_fragments())

    @cached_property
    def raw_store(self) -> RawStore:
        return RawStore(self.settings.data_path)

    @cached_property
    def session_factory(self) -> sessionmaker[Session]:
        from osint.storage.session import make_session_factory

        return make_session_factory(self.settings)

    def context(self, investigation_id: int | None = None, with_db: bool = True,
                **services) -> PluginContext:
        return PluginContext(
            settings=self.settings,
            models=get_models_config(),
            ontology=self.ontology,
            registry=self.registry,
            raw_store=self.raw_store,
            session_factory=self.session_factory if with_db else None,
            investigation_id=investigation_id,
            **services,
        )

    @asynccontextmanager
    async def services(self, *, http_transport=None, llm_transport=None, browser: bool = True,
                       vpn_transport=None):
        """Open the async services for a run and close them all afterwards."""
        from osint.evidence.browser import BrowserCapturer
        from osint.llm.local import LocalLLM
        from osint.net.http import Fetcher

        s = self.settings
        fetcher = Fetcher(s.network, transport=http_transport, vpn_transport=vpn_transport)
        capturer = (
            BrowserCapturer(s.network.user_agent, s.network.proxy, s.evidence.screenshot_timeout_s,
                            max_pages=s.concurrency.browser_pages)
            if browser and s.evidence.screenshots else None
        )
        llm = LocalLLM(get_models_config().local, slots=s.concurrency.llm_slots,
                       transport=llm_transport)
        try:
            yield {"http": fetcher, "browser": capturer, "llm": llm}
        finally:
            await fetcher.aclose()
            if capturer is not None:
                await capturer.aclose()
            await llm.aclose()
