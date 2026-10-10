// API client for the local OSINT backend (osint ui). Writes carry the per-server CSRF token.

const csrf = document.querySelector<HTMLMetaElement>('meta[name="csrf"]')?.content ?? "";

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

async function handle<T>(r: Response): Promise<T> {
  const text = await r.text();
  let data: unknown = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }
  if (!r.ok) {
    const msg = (data && typeof data === "object" && "error" in data)
      ? String((data as { error: unknown }).error)
      : `${r.status} ${r.statusText}`;
    throw new ApiError(msg, r.status);
  }
  return data as T;
}

export async function get<T>(path: string): Promise<T> {
  return handle<T>(await fetch(path, { headers: { Accept: "application/json" } }));
}

export async function post<T>(path: string, body: unknown = {}): Promise<T> {
  return handle<T>(await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
    body: JSON.stringify(body),
  }));
}

export async function upload<T>(path: string, form: FormData): Promise<T> {
  return handle<T>(await fetch(path, { method: "POST", headers: { "X-CSRF-Token": csrf }, body: form }));
}

// ---------------------------------------------------------------- types

export type Counts = Record<string, number>;

export interface InvestigationSummary {
  id: number;
  name: string;
  focus: string | null;
  created: string;
  counts: Counts;
  open_tasks: number;
  failed_tasks: number;
  review_open: number;
  profile: "standard" | "anonymous";
  status: string;
}

export interface Schedule {
  every_minutes: number;
  time_range: string | null;
  analyze: boolean;
  extract_role: string | null;
  enabled: boolean;
  last_run_at: string | null;
  next_run_at: string | null;
  last_result: Record<string, unknown> | null;
}

export interface InvestigationStatus {
  id: number;
  name: string;
  status: string;
  seed: { focus?: string; queries?: string[]; urls?: string[]; feeds?: string[]; lang?: string; time_range?: string };
  config: Record<string, unknown>;
  created: string;
  profile: "standard" | "anonymous";
  tasks: Record<string, Record<string, number>>;
  knowledge: Counts;
  failed: { id: number; type: string; plugin: string; error: string; attempts: number }[];
  schedule: Schedule | null;
}

export interface Job {
  id: number;
  action: string;
  label: string;
  args: string[];
  investigation_id: number | null;
  queue_worker: boolean;
  status: "running" | "done" | "failed" | "cancelled" | "lost";
  pid: number | null;
  exit_code: number | null;
  started_at: string;
  finished_at: string | null;
  log?: string;
}

export interface Plugin {
  kind: string;
  name: string;
  version: string;
  description: string;
  origin: string;
  schema?: JsonSchema;
  requires_account?: boolean;
  entity_types?: string[];
}

export interface JsonSchema {
  type?: string | string[];
  title?: string;
  description?: string;
  default?: unknown;
  enum?: unknown[];
  items?: JsonSchema;
  properties?: Record<string, JsonSchema>;
  required?: string[];
  anyOf?: JsonSchema[];
  minimum?: number;
  maximum?: number;
  minItems?: number;
  $ref?: string;
  $defs?: Record<string, JsonSchema>;
}

export interface EvidenceItem {
  marker: string;
  quote?: string;
  quote_translated?: string | null;
  verified?: boolean;
  url?: string;
  title?: string | null;
  posted_at?: string | null;
  captured_at?: string;
  sha256?: string;
  source_reliability?: string;
  information_credibility?: string;
  admiralty?: string;
  machine_read?: boolean;
  context?: string | null;
  document_id?: number | null;
  collected_in?: { id: number; name: string }[];
  error?: string;
}

export interface Support {
  independent_sources: number;
  documents: number;
}

export interface EntityDetail {
  entity_id: number;
  name: string;
  type: string;
  strong_key: string | null;
  attributes: Record<string, unknown>;
  aliases: string[];
  alias_count: number;
  investigations: { id: number; name: string }[];
  relations: {
    relation_id: number;
    direction: "in" | "out";
    type: string;
    other: { entity_id: number; name: string; type: string };
    confidence: number;
    evidence: string[];
    support?: Support;
  }[];
  events: {
    event_id: number;
    type: string;
    role: string;
    time: string | null;
    description: string;
    evidence: string[];
    support?: Support;
  }[];
  claims_not_facts?: unknown[];
  evidence_detail: Record<string, EvidenceItem>;
}

export interface TimelineEvent {
  event_id: number;
  reports: number;
  type: string;
  time: string | null;
  precision: string | null;
  description: string;
  location: string | null;
  participants: { entity_id: number; name: string; role: string }[];
  evidence: string[];
  support?: Support;
}

export interface Finding {
  marker: string;
  kind: string;
  text: string;
  confidence: number;
  epistemic_status: string;
  status: string;
  created_by: string;
  evidence: string[];
  revisions?: unknown[];
}

export interface CrossLink {
  link_id: number;
  other_investigation: { id: number; name: string };
  tier: string;
  score: number;
  status: string;
  via: { type: string; id: number; name?: string; entity_type?: string; description?: string };
  explanation: string | null;
  decided_by: string | null;
  evidence: string[];
}

export interface ReviewItem {
  id: number;
  kind: string;
  reason: string;
  investigation_id: number | null;
  investigation?: string | null;
  created?: string | null;
  payload: Record<string, unknown>;
}

export interface Artifact {
  id: number;
  url: string;
  mime: string | null;
  platform: string | null;
  platform_id: string | null;
  captured: string;
  posted: string | null;
  status: number | null;
  sha256: string;
  size: number;
  document: number | null;
  route: string | null;
  blocked: string | null;
  source: { id: number; locator: string; kind: string; grade: string } | null;
  captures: { id: number; kind: string }[];
}

export interface Source {
  id: number;
  kind: string;
  locator: string;
  grade: string;
  note: string | null;
  artifacts: number;
  first_seen: string | null;
}

export interface ProofNode {
  type: string;
  id: number;
  text?: string;
  kind?: string;
  status?: string;
  epistemic_status?: string;
  confidence?: number;
  method?: string;
  by?: string;
  quote?: string;
  translation?: string | null;
  url?: string;
  captured?: string;
  sha256?: string;
  missing?: boolean;
  children?: ProofNode[];
}

export const markerId = (m: string) => Number(m.replace(/\D/g, ""));
