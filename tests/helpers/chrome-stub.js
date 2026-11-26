// Enough of the extension APIs to exercise the service worker in Node.
// storage.session is deliberately a separate map: it models the in-memory,
// never-persisted area where the unlocked key lives.

export function installChromeStub() {
  const local = new Map();
  const session = new Map();
  const listeners = { message: [], alarm: [], installed: [] };
  const alarms = new Map();

  const area = (map) => ({
    async get(keys) {
      if (keys === null || keys === undefined) return Object.fromEntries(map);
      const list = Array.isArray(keys) ? keys : [keys];
      const out = {};
      for (const key of list) if (map.has(key)) out[key] = structuredClone(map.get(key));
      return out;
    },
    async set(items) {
      for (const [key, value] of Object.entries(items)) map.set(key, structuredClone(value));
    },
    async remove(keys) {
      for (const key of Array.isArray(keys) ? keys : [keys]) map.delete(key);
    },
    async clear() {
      map.clear();
    },
  });

  const chrome = {
    storage: { local: area(local), session: area(session) },
    alarms: {
      create: (name, info) => alarms.set(name, info),
      clear: async (name) => alarms.delete(name),
      onAlarm: { addListener: (fn) => listeners.alarm.push(fn) },
    },
    runtime: {
      onMessage: { addListener: (fn) => listeners.message.push(fn) },
      onInstalled: { addListener: (fn) => listeners.installed.push(fn) },
      getManifest: () => ({ version: '1.0.0' }),
      getURL: (path) => `chrome-extension://test/${path}`,
    },
    tabs: {
      query: async () => [{ id: 1, windowId: 1, title: 'test tab', url: tabState.url }],
      create: async () => ({ id: 2 }),
      captureVisibleTab: async () => 'data:image/png;base64,iVBORw0KGgo=',
    },
  };

  // Pretend page for chrome.scripting: each frame answers the injected function
  // with whatever `frames` says, and every call is recorded.
  const tabState = { url: 'https://github.com/sessions/two-factor' };
  const scripting = {
    calls: [],
    frames: [{ frameId: 0, probe: { score: 100, filled: false } }],
    blocked: false,
  };
  chrome.scripting = {
    async executeScript({ target, func, args }) {
      scripting.calls.push({ target, args, func });
      if (scripting.blocked) throw new Error('Cannot access a chrome:// URL');
      const frames = target.frameIds
        ? scripting.frames.filter((f) => target.frameIds.includes(f.frameId))
        : target.allFrames ? scripting.frames : scripting.frames.filter((f) => f.frameId === 0);
      return frames.map((f) => ({
        frameId: f.frameId,
        result: args[1] === 'fill' ? { score: f.probe.score, filled: f.probe.score >= 45 } : f.probe,
      }));
    },
  };

  globalThis.chrome = chrome;

  /** Call the service worker the way the popup does, and unwrap the reply. */
  async function send(cmd, payload = {}) {
    const result = await new Promise((resolve) => {
      listeners.message[0]({ cmd, ...payload }, {}, resolve);
    });
    if (!result.ok) throw new Error(result.error);
    return result.data;
  }

  return { chrome, send, local, session, alarms, listeners, scripting, tabState };
}
