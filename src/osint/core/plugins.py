"""Plugin base classes and registry.

Plugins are found in two ways:
  * Python entry points in the ``osint.plugins`` group (installed packages, built-ins), and
  * ``*.py`` files in the configured plugin_dirs (drop-in, no packaging needed).

Every plugin is a subclass of one of the kind base classes below, with a unique ``name``
within its kind.
"""

from __future__ import annotations

import importlib.util
import inspect
import logging
import sys
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator, Iterable
from importlib.metadata import entry_points
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from pydantic import BaseModel

if TYPE_CHECKING:
    from osint.core.context import PluginContext
    from osint.core.models import CapturedItem, DocumentView, ExtractionResult, FollowUp

log = logging.getLogger(__name__)

ENTRY_POINT_GROUP = "osint.plugins"


class NoParams(BaseModel):
    pass


class Plugin(ABC):
    kind: ClassVar[str] = ""                 # set by each kind base class
    name: ClassVar[str] = ""                 # set by concrete plugins
    version: ClassVar[str] = "0.1.0"
    description: ClassVar[str] = ""
    params_schema: ClassVar[type[BaseModel]] = NoParams
    ontology_fragment: ClassVar[Path | None] = None   # optional YAML adding ontology types

    @property
    def ident(self) -> str:
        """Stable identifier recorded in provenance (custody log, run log)."""
        return f"{self.kind}:{self.name}@{self.version}"

    def parse_params(self, params: dict[str, Any]) -> BaseModel:
        return self.params_schema.model_validate(params)


class Collector(Plugin):
    """Fetches artifacts from a source.

    ``collect`` yields CapturedItem (evidence to store) or FollowUp (more work to schedule).
    Resumability: the orchestrator persists ``checkpoint()`` after each item it has
    stored and calls ``restore()`` with it on resume. Advance your cursor only after the
    consumer comes back for the next item (at-least-once; ingest dedups by hash).
    """

    kind = "collector"
    refreshable: ClassVar[bool] = False   # re-run by `osint refresh` / schedules
    requires_account: ClassVar[bool] = False  # needs the user's account/API identity

    @abstractmethod
    def collect(
        self, params: BaseModel, ctx: PluginContext
    ) -> AsyncIterator[CapturedItem | FollowUp]: ...

    def checkpoint(self) -> dict[str, Any]:
        return {}

    def restore(self, checkpoint: dict[str, Any]) -> None:
        """Restore state saved by checkpoint() (no-op for stateless collectors)."""

    def on_refresh(self, checkpoint: dict[str, Any]) -> dict[str, Any]:
        """Checkpoint to start a refresh from. Default: start over. Override to keep
        state that prevents re-fetching (e.g. seen feed entries)."""
        return {}


class Extractor(Plugin):
    """Turns a document into entities/relations/events, each with a verbatim quote.

    Extractors never write to the DB. The extraction writer verifies every quote against
    the document text, then resolves entities and writes everything with citations.
    """

    kind = "extractor"
    handles: ClassVar[set[str]] = set()      # mime types / languages / doc kinds

    @abstractmethod
    async def extract(self, document: DocumentView, ctx: PluginContext) -> ExtractionResult: ...


class Enricher(Plugin):
    """Looks an entity up in an outside source. Returns an EnrichmentResult
    (osint.enrichment.base): captured responses, a derived facts text, and relations
    quoting that text. Persistence and citation checks are done by the core."""

    kind = "enricher"
    entity_types: ClassVar[set[str]] = set()

    @abstractmethod
    async def enrich(self, entity: Any, ctx: PluginContext) -> Any: ...


class Analyzer(Plugin):
    kind = "analyzer"

    @abstractmethod
    async def analyze(self, scope: Any, ctx: PluginContext) -> list[Any]: ...


class Exporter(Plugin):
    kind = "exporter"
    formats: ClassVar[set[str]] = set()

    @abstractmethod
    async def export(self, scope: Any, out: Path, ctx: PluginContext) -> Path: ...


class StorageBackend(Plugin):
    kind = "storage"


class LLMProvider(Plugin):
    kind = "llm"


class CaptureHandler(Plugin):
    """Platform-specific proof capture (screenshots, native IDs, media originals)."""

    kind = "capture"
    platforms: ClassVar[set[str]] = set()


class Timestamper(Plugin):
    """Trusted timestamping of hash manifests (RFC 3161, OpenTimestamps, ...)."""

    kind = "timestamper"

    @abstractmethod
    async def stamp(self, digest: bytes, ctx: PluginContext) -> bytes: ...

    @abstractmethod
    async def verify(self, digest: bytes, proof: bytes, ctx: PluginContext) -> bool: ...


KINDS: tuple[type[Plugin], ...] = (
    Collector, Extractor, Enricher, Analyzer, Exporter,
    StorageBackend, LLMProvider, CaptureHandler, Timestamper,
)


class PluginError(RuntimeError):
    pass


def check_collector_allowed(cls: type[Plugin], settings) -> None:
    """Refuse collectors that need the user's own account/ID unless explicitly enabled."""
    if getattr(cls, "requires_account", False) and not settings.collection.allow_account_sources:
        raise PluginError(
            f"collector {cls.name!r} needs your account/ID; it's disabled "
            "(settings: collection.allow_account_sources)")


class PluginRegistry:
    def __init__(self) -> None:
        self._plugins: dict[tuple[str, str], type[Plugin]] = {}
        self._origins: dict[tuple[str, str], str] = {}

    # ------------------------------------------------------------------ registration

    def register(self, cls: type[Plugin], origin: str = "<direct>") -> type[Plugin]:
        if not (inspect.isclass(cls) and issubclass(cls, Plugin)):
            raise PluginError(f"{cls!r} is not a Plugin subclass")
        if inspect.isabstract(cls):
            raise PluginError(f"{cls.__name__} is abstract (missing methods?)")
        if not cls.kind or not cls.name:
            raise PluginError(f"{cls.__name__} must define kind and name")
        key = (cls.kind, cls.name)
        existing = self._plugins.get(key)
        if existing is not None and existing is not cls:
            raise PluginError(
                f"duplicate {cls.kind} plugin {cls.name!r}: {self._origins[key]} and {origin}"
            )
        self._plugins[key] = cls
        self._origins[key] = origin
        return cls

    def discover_entry_points(self) -> None:
        for ep in entry_points(group=ENTRY_POINT_GROUP):
            try:
                self.register(ep.load(), origin=f"entry_point:{ep.value}")
            except Exception as e:  # noqa: BLE001 - a broken plugin must not take the system down
                log.error("failed to load plugin entry point %s: %s", ep.value, e)

    def discover_dirs(self, dirs: Iterable[Path]) -> None:
        for d in dirs:
            if not d.is_dir():
                continue
            for path in sorted(d.glob("*.py")):
                if path.name.startswith("_"):
                    continue
                try:
                    module = _import_file(path)
                except Exception as e:  # noqa: BLE001 - same: isolate broken drop-ins
                    log.error("failed to import plugin file %s: %s", path, e)
                    continue
                for _, obj in inspect.getmembers(module, inspect.isclass):
                    if (
                        issubclass(obj, Plugin)
                        and obj.__module__ == module.__name__
                        and obj.name
                        and not inspect.isabstract(obj)
                    ):
                        try:
                            self.register(obj, origin=str(path))
                        except PluginError as e:
                            log.error("%s", e)

    # ------------------------------------------------------------------ lookup

    def get(self, kind: str, name: str) -> type[Plugin]:
        try:
            return self._plugins[(kind, name)]
        except KeyError:
            raise PluginError(f"no {kind} plugin named {name!r}") from None

    def create(self, kind: str, name: str, **kwargs: Any) -> Plugin:
        return self.get(kind, name)(**kwargs)

    def list(self, kind: str | None = None) -> list[tuple[type[Plugin], str]]:
        return [
            (cls, self._origins[key])
            for key, cls in sorted(self._plugins.items())
            if kind is None or key[0] == kind
        ]

    def ontology_fragments(self) -> list[Path]:
        return [cls.ontology_fragment for cls in self._plugins.values() if cls.ontology_fragment]


def _import_file(path: Path):
    mod_name = f"osint_local_plugins.{path.stem}"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = module
    spec.loader.exec_module(module)
    return module


def build_registry(plugin_dirs: Iterable[Path] = ()) -> PluginRegistry:
    reg = PluginRegistry()
    reg.discover_entry_points()
    reg.discover_dirs(plugin_dirs)
    return reg
