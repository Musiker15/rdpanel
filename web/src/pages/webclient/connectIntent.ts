// A one-time "connect now" intent, so that only the panel itself starts a
// session on arrival: a link to /connect?id=… from anywhere else (a chat, a
// page) only fills in the ID and waits for a click. The intent is written by
// the device drawer right before it opens the web client and is good for one
// minute; localStorage because the client opens in a new tab.

const KEY = "rdpanel.connect.intent";
const TTL_MS = 60_000;

type Intent = { id: string; exp: number };

/** Records that the panel is about to open the web client for id. */
export function markConnectIntent(id: string, now = Date.now()): void {
  try {
    localStorage.setItem(KEY, JSON.stringify({ id, exp: now + TTL_MS } satisfies Intent));
  } catch {
    /* storage unavailable: the page waits for a click */
  }
}

/** Takes (and clears) a fresh intent for id; false for any other id or none. */
export function takeConnectIntent(id: string, now = Date.now()): boolean {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return false;
    localStorage.removeItem(KEY);
    const v = JSON.parse(raw) as Partial<Intent>;
    return v.id === id && typeof v.exp === "number" && v.exp > now;
  } catch {
    return false;
  }
}
