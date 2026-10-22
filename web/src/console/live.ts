// The live stream (/v1/stream) as a tiny external store: the first message authenticates, then events flow.
import { useSyncExternalStore } from 'react';
import { type ActionEvent, type Alert, auth, type Decision, WS_URL } from './api';

export interface LiveState {
  connected: boolean;
  events: ActionEvent[]; // newest first
  alerts: Alert[]; // newest first, one per id
  decisions: Decision[];
  arena: unknown[];
  tick: number; // bumps on every message: pages refetch on it
}

let state: LiveState = { connected: false, events: [], alerts: [], decisions: [], arena: [], tick: 0 };
const subs = new Set<() => void>();
const set = (patch: Partial<LiveState>) => {
  state = { ...state, ...patch, tick: state.tick + 1 };
  subs.forEach((f) => f());
};

let ws: WebSocket | null = null;
let retry = 0;
let timer = 0;

function connect() {
  const token = auth.token;
  if (!token || ws) return;
  ws = new WebSocket(WS_URL);
  ws.onopen = () => ws?.send(JSON.stringify({ token }));
  ws.onmessage = (m) => {
    const { topic, data } = JSON.parse(m.data);
    if (topic === 'hello') {
      retry = 0;
      set({ connected: true });
    } else if (topic === 'action.scored') set({ events: [data, ...state.events].slice(0, 300) });
    else if (topic === 'alert.raised' || topic === 'alert.updated') set({ alerts: [data, ...state.alerts.filter((a) => a.id !== data.id)].slice(0, 100) });
    else if (topic === 'containment.changed') set({ decisions: [data, ...state.decisions].slice(0, 100) });
    else if (topic === 'arena.progress') set({ arena: [data, ...state.arena].slice(0, 100) });
    else set({});
  };
  ws.onclose = (e) => {
    ws = null;
    set({ connected: false });
    if (e.code === 4401) return auth.set(null);
    if (auth.token) timer = window.setTimeout(connect, Math.min(15000, 1000 * 2 ** retry++));
  };
}

export function startLive() {
  connect();
}

export function stopLive() {
  clearTimeout(timer);
  ws?.close();
  ws = null;
}

export function useLive(): LiveState {
  return useSyncExternalStore(
    (f) => (subs.add(f), () => subs.delete(f)),
    () => state,
  );
}
