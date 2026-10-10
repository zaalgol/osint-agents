// A form generated from a plugin's JSON Schema (pydantic params_schema), so every
// collector, including ones added later, gets a UI without extra code.
import { useMemo, useState } from "react";
import type { JsonSchema } from "../api";
import { ListInput } from "./ui";

type Values = Record<string, unknown>;

function resolve(s: JsonSchema, root: JsonSchema): JsonSchema {
  if (s.$ref) {
    const name = s.$ref.split("/").pop()!;
    return root.$defs?.[name] ?? s;
  }
  if (s.anyOf) {
    const real = s.anyOf.filter((x) => x.type !== "null");
    if (real.length === 1) return { ...resolve(real[0], root), description: s.description, default: s.default, title: s.title };
  }
  return s;
}

function typeOf(s: JsonSchema): string {
  const t = Array.isArray(s.type) ? s.type.find((x) => x !== "null") : s.type;
  if (s.enum) return "enum";
  return t ?? "string";
}

export function defaults(schema: JsonSchema): Values {
  const out: Values = {};
  for (const [k, raw] of Object.entries(schema.properties ?? {})) {
    const s = resolve(raw, schema);
    if (s.default !== undefined && s.default !== null) out[k] = s.default;
    else if (typeOf(s) === "array") out[k] = [];
  }
  return out;
}

export function SchemaForm({ schema, value, onChange }: {
  schema: JsonSchema; value: Values; onChange: (v: Values) => void;
}) {
  const props = schema.properties ?? {};
  const required = new Set(schema.required ?? []);
  const [showJson, setShowJson] = useState(false);
  const [jsonText, setJsonText] = useState("");
  const [jsonErr, setJsonErr] = useState<string | null>(null);
  const keys = useMemo(() => Object.keys(props), [props]);
  const set = (k: string, v: unknown) => {
    const next = { ...value };
    if (v === "" || v === undefined || (Array.isArray(v) && v.length === 0 && !required.has(k))) delete next[k];
    else next[k] = v;
    onChange(next);
  };

  return (
    <div className="stack">
      {keys.map((k) => {
        const s = resolve(props[k], schema);
        const t = typeOf(s);
        const label = (
          <>
            <span>{s.title ?? k}{required.has(k) && " *"}</span>
            {s.description && <span className="hint">{s.description}</span>}
          </>
        );
        if (t === "boolean") {
          return (
            <label key={k} className="check">
              <input type="checkbox" checked={Boolean(value[k] ?? s.default)} onChange={(e) => set(k, e.target.checked)} />
              <span>{s.title ?? k}{s.description && <span className="muted small"> · {s.description}</span>}</span>
            </label>
          );
        }
        if (t === "array" && typeOf(resolve(s.items ?? {}, schema)) === "string") {
          return (
            <label key={k} className="field">{label}
              <ListInput value={(value[k] as string[]) ?? []} onChange={(v) => set(k, v)} placeholder="Type and press Enter (or paste several lines)" />
            </label>
          );
        }
        if (t === "enum") {
          return (
            <label key={k} className="field">{label}
              <select value={String(value[k] ?? "")} onChange={(e) => set(k, e.target.value || undefined)}>
                <option value="">—</option>
                {s.enum!.map((o) => <option key={String(o)} value={String(o)}>{String(o)}</option>)}
              </select>
            </label>
          );
        }
        if (t === "integer" || t === "number") {
          return (
            <label key={k} className="field">{label}
              <input type="number" value={value[k] === undefined ? "" : String(value[k])}
                min={s.minimum} max={s.maximum} step={t === "integer" ? 1 : "any"}
                onChange={(e) => set(k, e.target.value === "" ? undefined : Number(e.target.value))} />
            </label>
          );
        }
        if (t === "string") {
          return (
            <label key={k} className="field">{label}
              <input value={String(value[k] ?? "")} onChange={(e) => set(k, e.target.value)} />
            </label>
          );
        }
        return (
          <label key={k} className="field">{label}
            <span className="hint">Complex field: edit it in the JSON view below.</span>
          </label>
        );
      })}
      <div>
        <button type="button" className="ghost small" onClick={() => { setJsonText(JSON.stringify(value, null, 2)); setShowJson(!showJson); setJsonErr(null); }}>
          {showJson ? "Hide" : "Edit as"} JSON
        </button>
        {showJson && (
          <div className="stack" style={{ marginTop: 6 }}>
            <textarea className="mono" rows={8} value={jsonText} onChange={(e) => setJsonText(e.target.value)} />
            <div className="row">
              <button type="button" className="small" onClick={() => {
                try { onChange(JSON.parse(jsonText)); setJsonErr(null); } catch (e) { setJsonErr(String(e)); }
              }}>Apply JSON</button>
              {jsonErr && <span className="error small">{jsonErr}</span>}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
