import { useCallback, useEffect, useRef, useState } from 'react';
import type { components } from '../api/schema';

// The server always sends fields that have defaults; OpenAPI marks them optional, so make responses exact.
type Out<T> = T extends (infer U)[] ? Out<U>[] : T extends object ? { [K in keyof T]-?: Out<Exclude<T[K], undefined>> } : T;
type S = { [K in keyof components['schemas']]: Out<components['schemas'][K]> };
export type Agent = S['Agent'];
export type Alert = S['Alert'];
export type Approval = S['Approval'];
export type Decision = S['Decision'];
export type ArenaRun = S['ArenaRun'];
export type Signature = S['Signature'];
export type ScenarioInfo = S['ScenarioInfo'];
export type RedTeamResult = S['RedTeamResult'];
export type Analysis = S['Analysis'];
export type UrlFinding = S['UrlFinding'];
export type AgentRisk = S['AgentRisk'];
export type RoleDetail = S['RoleDetail'];
export type ContentItem = S['ContentItem'];
export type Factor = S['Factor'];

// Shapes of the endpoints that return plain dicts.
export interface ActionEvent {
  id: string;
  ts: string;
  agent_id: string;
  role: string;
  session_id: string;
  action: { tool: string; resource?: string | null; destination?: string | null; sensitivity: string; bytes_out: number };
  provenance: { tainted_by: string[] };
  scores: Record<string, number>;
  risk: number | null;
  decision: string | null;
  shadow: boolean;
  reason: string | null;
  alert_id: string | null;
}

export interface Health {
  status: string;
  env: string;
  agents: number;
  embedder: string;
  pending_approvals: number;
  exfil_bytes_reached_sink: number;
  llm: { provider: string; model: string; ready: boolean; cooldown_s: number; last_error: string | null }[];
}

export interface Trend {
  minutes: number;
  agents: Record<string, { minute: string; drift: number | null; max_risk: number | null; count: number }[]>;
  fleet: { minute: string; score: number; agents: number }[];
  now: { fleet_score: number; drift: Record<string, number> };
}

export interface Replay {
  session_id: string;
  agents: string[];
  steps: ActionEvent[];
  content: ContentItem[];
  alerts: Alert[];
  decisions: Decision[];
}

export interface ScenarioRun {
  scenario_id: string;
  name: string;
  passed: boolean;
  checks: string[];
  exfil_bytes: number;
  primary_agent: string | null;
  alert: Alert | null;
  steps: { label: string; kind: string; detail: string; decision: string | null; risk: number | null; status_after: string | null }[];
}

export const API = (import.meta.env.VITE_API_URL ?? 'http://localhost:8000').replace(/\/$/, '');
export const WS_URL = import.meta.env.VITE_WS_URL ?? `${API.replace(/^http/, 'ws')}/v1/stream`;

const KEY = 'tl.token';
export const auth = {
  get token() {
    try {
      return sessionStorage.getItem(KEY);
    } catch {
      return null;
    }
  },
  set(token: string | null) {
    try {
      if (token) sessionStorage.setItem(KEY, token);
      else sessionStorage.removeItem(KEY);
    } catch {
      /* private mode: stays signed in for this tab only */
    }
    window.dispatchEvent(new Event('tl-auth'));
  },
};

export class ApiError extends Error {
  constructor(public status: number, public detail: unknown) {
    super(typeof detail === 'string' ? detail : status === 0 ? 'The API is unreachable.' : `Request failed (${status})`);
  }
}

export async function api<T>(path: string, init: RequestInit & { json?: unknown } = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (auth.token) headers.set('Authorization', `Bearer ${auth.token}`);
  if (init.json !== undefined) headers.set('Content-Type', 'application/json');
  let res: Response;
  try {
    res = await fetch(API + path, { ...init, headers, body: init.json !== undefined ? JSON.stringify(init.json) : init.body });
  } catch {
    throw new ApiError(0, 'The API is unreachable. On the free tier it may be waking up, which takes about 30 seconds.');
  }
  if (res.status === 401 && auth.token) auth.set(null);
  const type = res.headers.get('content-type') ?? '';
  const body = type.includes('json') ? await res.json() : await res.text();
  if (!res.ok) throw new ApiError(res.status, (body as { detail?: unknown })?.detail ?? body);
  return body as T;
}

/** GET with optional polling. `reload` refetches now. */
export function useApi<T>(path: string | null, pollMs = 0) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const seq = useRef(0);
  const reload = useCallback(async () => {
    if (!path) return;
    const n = ++seq.current;
    try {
      const d = await api<T>(path);
      if (n === seq.current) {
        setData(d);
        setError(null);
      }
    } catch (e) {
      if (n === seq.current) setError(e as ApiError);
    }
  }, [path]);
  useEffect(() => {
    setData(null);
    reload();
    if (!pollMs) return;
    const t = setInterval(() => !document.hidden && reload(), pollMs);
    return () => clearInterval(t);
  }, [reload, pollMs]);
  return { data, error, reload, setData };
}

export const pct = (v: number) => `${Math.round(v * 100)}%`;
export const ago = (ts: string) => {
  const s = Math.max(0, (Date.now() - new Date(ts).getTime()) / 1000);
  return s < 60 ? `${Math.round(s)} s ago` : s < 3600 ? `${Math.round(s / 60)} min ago` : `${Math.round(s / 3600)} h ago`;
};
export const statusLabel: Record<string, string> = {
  active: 'Active', restricted: 'Restricted', step_up: 'Step-up', quarantined: 'Isolated',
};
export const decisionLabel: Record<string, string> = {
  allow: 'Allowed', allow_logged: 'Allowed, logged', deny: 'Blocked', require_approval: 'Held for approval', quarantine: 'Isolated',
};
