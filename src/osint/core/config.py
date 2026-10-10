"""Settings loading.

Precedence (highest first): init kwargs > OSINT_* env vars > .env > config/settings.local.yaml
> config/settings.yaml. Relative paths are resolved against the project home
(OSINT_HOME env var, else the current directory).
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)


def project_home() -> Path:
    return Path(os.environ.get("OSINT_HOME", Path.cwd())).resolve()


class PostgresSettings(BaseModel):
    host: str = "127.0.0.1"
    port: int = 5432
    user: str = "osint"
    password: str = "osint"
    database: str = "osint"

    @property
    def url(self) -> str:
        return (
            f"postgresql+psycopg://{self.user}:{self.password}"
            f"@{self.host}:{self.port}/{self.database}"
        )


class Neo4jSettings(BaseModel):
    uri: str = "bolt://127.0.0.1:7687"
    user: str = "neo4j"
    password: str = "osint-neo4j-pw"


class SearxngSettings(BaseModel):
    url: str = "http://127.0.0.1:8888"


class ConcurrencySettings(BaseModel):
    llm_slots: int = 2
    network_tasks: int = 16
    browser_pages: int = 2            # concurrent Chromium pages (each costs ~200-500 MB)
    min_free_ram_gb: float = 3.0      # workers pause claiming new tasks below this
    # Ollama's runner process grows in RAM over long runs; unload (and transparently reload)
    # the local models when available RAM falls below this
    recycle_llm_below_gb: float = 6.0


class EvidenceSettings(BaseModel):
    hash_algorithms: list[str] = Field(default_factory=lambda: ["sha256", "sha512"])
    archive_org: bool = False
    screenshots: bool = True          # full-page PNG + PDF + rendered DOM via Playwright
    screenshot_timeout_s: float = 45
    # trusted timestamps for sealed manifests (only a hash is sent); [] disables
    timestamp_methods: list[str] = Field(default_factory=lambda: ["rfc3161", "opentimestamps"])
    tsa_url: str = "https://freetsa.org/tsr"
    seal_after_run: bool = True


class NetworkSettings(BaseModel):
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/141.0 Safari/537.36"
    )
    proxy: str | None = None          # global proxy for ALL traffic; None = direct
    vpn_proxy: str | None = None      # VPN route, used only when the direct route is blocked
    vpn_fallback: bool = True
    # On the VPN route, resolve names with DNS-over-HTTPS (sent through the VPN), so
    # DNS-level blocks and ISP DNS logging don't apply. TLS is still verified per hostname.
    vpn_doh: bool = True
    doh_url: str = "https://cloudflare-dns.com/dns-query"
    timeout_s: float = 30
    per_host_interval_s: float = 2.0  # politeness / anti-blocking delay between hits per host
    max_bytes: int = 50 * 1024 * 1024


class AnalysisSettings(BaseModel):
    # Claude's confidence *downgrades* apply at once (safe direction); upgrades and
    # withdrawals always wait for a human in the review queue.
    auto_apply_downgrades: bool = True


class MediaSettings(BaseModel):
    transcribe_missing_captions: bool = True   # needs: uv sync --extra media
    whisper_model: str = "small"               # tiny | base | small | medium | large-v3
    whisper_device: str = "auto"               # auto (GPU if CUDA libs load) | cuda | cpu
    max_transcribe_minutes: int = 20


class CollectionSettings(BaseModel):
    # Sources that need your own account/ID (Telegram API, Reddit API, ACLED, ...) are off
    # unless you enable them here explicitly.
    allow_account_sources: bool = False


class ExtractionSettings(BaseModel):
    extractors: list[str] = Field(default_factory=lambda: ["llm"])
    # models.yaml role for the LLM extractor: agent (fast) | agent_heavy (accurate, slower).
    # `osint eval history` shows the measured trade-off on this machine.
    llm_role: str = "agent"
    chunk_chars: int = 7000
    chunk_overlap: int = 400
    max_chunks_per_document: int = 8
    min_text_chars: int = 200         # shorter documents are not worth an LLM call


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="OSINT_",
        env_nested_delimiter="__",
        env_file=str(project_home() / ".env"),  # MCP subprocesses run with other cwds
        extra="ignore",
    )

    data_dir: Path = Path("data")
    postgres: PostgresSettings = Field(default_factory=PostgresSettings)
    neo4j: Neo4jSettings = Field(default_factory=Neo4jSettings)
    searxng: SearxngSettings = Field(default_factory=SearxngSettings)
    concurrency: ConcurrencySettings = Field(default_factory=ConcurrencySettings)
    evidence: EvidenceSettings = Field(default_factory=EvidenceSettings)
    network: NetworkSettings = Field(default_factory=NetworkSettings)
    collection: CollectionSettings = Field(default_factory=CollectionSettings)
    media: MediaSettings = Field(default_factory=MediaSettings)
    analysis: AnalysisSettings = Field(default_factory=AnalysisSettings)
    extraction: ExtractionSettings = Field(default_factory=ExtractionSettings)
    plugin_dirs: list[Path] = Field(default_factory=lambda: [Path("plugins_local")])
    ontology_files: list[Path] = Field(default_factory=lambda: [Path("config/ontology.yaml")])

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        home = project_home()
        yaml_files = [home / "config/settings.local.yaml", home / "config/settings.yaml"]
        yaml_files = [f for f in yaml_files if f.is_file()]
        sources: list[PydanticBaseSettingsSource] = [init_settings, env_settings, dotenv_settings]
        # First file in the list wins, so the local override comes first.
        sources += [YamlConfigSettingsSource(settings_cls, yaml_file=f) for f in yaml_files]
        return tuple(sources)

    def resolve(self, path: Path) -> Path:
        return path if path.is_absolute() else project_home() / path

    @property
    def data_path(self) -> Path:
        return self.resolve(self.data_dir)

    @property
    def raw_path(self) -> Path:
        return self.data_path / "raw"


class LocalRole(BaseModel):
    model: str
    context: int | None = None
    temperature: float | None = None
    dimensions: int | None = None
    keep_alive: str | None = None     # Ollama: how long the model stays loaded ("1m", "0")
    max_output_tokens: int | None = None  # cap per call (bounds runaway generations)


class LocalModels(BaseModel):
    backend: str = "ollama"
    base_url: str = "http://127.0.0.1:11434/v1"
    api_key: str = "ollama"
    roles: dict[str, LocalRole] = Field(default_factory=dict)


class ClaudeModels(BaseModel):
    binary: str = "claude"
    default_model: str = "sonnet"
    use_api_key: bool = False          # False: strip ANTHROPIC_API_KEY so jobs bill to Max
    jobs: dict[str, str] = Field(default_factory=dict)
    max_turns: dict[str, int] = Field(default_factory=dict)


class ModelsConfig(BaseModel):
    local: LocalModels = Field(default_factory=LocalModels)
    claude: ClaudeModels = Field(default_factory=ClaudeModels)


@lru_cache
def get_settings() -> Settings:
    return Settings()


@lru_cache
def get_models_config() -> ModelsConfig:
    path = project_home() / "config/models.yaml"
    if not path.is_file():
        return ModelsConfig()
    return ModelsConfig.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")) or {})
