// AI Relay — personal keys, plus shared keys with fair-use limits.
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const zlib = require("zlib");

// Accounts and chats are saved in Upstash Redis when its two env vars are set (survives redeploys).
// Otherwise they go to local files, which Render's free plan erases on every restart.
const UP_URL = process.env.UPSTASH_REDIS_REST_URL;
const UP_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;
const USE_REDIS = !!(UP_URL && UP_TOKEN);

const DIR = process.env.DATA_DIR || path.join(__dirname, "data");
fs.mkdirSync(DIR, { recursive: true });
if (!USE_REDIS) console.log("Note: no Upstash set, so accounts and chats are not kept between deploys on Render's free plan.");

// Fair-use limits. On shared keys these apply to EACH AI separately. Your own keys aren't capped.
const PER_USER_HOURLY = 20; // messages per person per AI per hour
const PER_USER_DAILY = 70;  // messages per person per AI per day
const MAX_CHATS = 50;       // saved chats per person
const MAX_MESSAGES = 200;   // messages kept per chat
const MAX_KEYS_PER_NETWORK_PER_DAY = 5; // personal keys one network can create per day (resets at midnight UTC)

// Only the latest messages are sent to the AI, so providers don't hit their per-minute token limits.
const CONTEXT_MESSAGES = 10; // how many recent messages the AI sees
const CONTEXT_CHARS = 3000;  // long messages are shortened for the AI to this many characters

// `model` = first model name to try. If it isn't available, the app tries the names in `known`, then, if `lookup`
// is true, the text models the provider lists for your key. `daily` = messages per day on the SHARED key
// (set in Render as NAME_API_KEY). Override in Render with NAME_DAILY_LIMIT, e.g. MISTRAL_DAILY_LIMIT = 0.
// `paid` = needs billing. Shared use of a paid AI costs you money, so keep its daily number low.
const PROVIDERS = {
  Groq: { url: "https://api.groq.com/openai/v1/chat/completions", listUrl: "https://api.groq.com/openai/v1/models", model: "llama-3.3-70b-versatile", known: ["llama-3.1-8b-instant", "openai/gpt-oss-20b"], lookup: false, keyUrl: "https://console.groq.com/keys", daily: 900, paid: false },
  Cerebras: { url: "https://api.cerebras.ai/v1/chat/completions", listUrl: "https://api.cerebras.ai/v1/models", model: "gpt-oss-120b", known: ["llama3.1-8b", "qwen-3-32b"], lookup: false, keyUrl: "https://cloud.cerebras.ai", daily: 500, paid: false },
  NVIDIA: { url: "https://integrate.api.nvidia.com/v1/chat/completions", listUrl: "https://integrate.api.nvidia.com/v1/models", model: "nvidia/nemotron-3.5-super-vl-120b-a12b", known: [], lookup: false, keyUrl: "https://build.nvidia.com", daily: 500, paid: false },
  Mistral: { url: "https://api.mistral.ai/v1/chat/completions", listUrl: "https://api.mistral.ai/v1/models", model: "mistral-small-latest", known: ["mistral-medium-latest", "open-mistral-nemo"], lookup: false, keyUrl: "https://console.mistral.ai", daily: 200, paid: false },
  OpenRouter: { url: "https://openrouter.ai/api/v1/chat/completions", listUrl: "https://openrouter.ai/api/v1/models", model: "mistralai/mistral-large-4-0", known: ["google/gemma-3-27b-it:free"], lookup: false, keyUrl: "https://openrouter.ai/keys", daily: 45, paid: false },
  Cloudflare: { url: `https://api.cloudflare.com/client/v4/accounts/${process.env.CLOUDFLARE_ACCOUNT_ID || "missing-account-id"}/ai/v1/chat/completions`, listUrl: `https://api.cloudflare.com/client/v4/accounts/${process.env.CLOUDFLARE_ACCOUNT_ID || "missing-account-id"}/ai/models/search?per_page=100`, model: "@cf/openai/gpt-oss-120b", known: ["@cf/deepseek-ai/deepseek-v4-pro-0813"], lookup: true, keyUrl: "https://dash.cloudflare.com/profile/api-tokens", daily: 100, paid: false },
};

// AIs that can read photos. Photos are only sent to these.
const VISION = ["Mistral"];

// Keys come from Render's environment, e.g. GROQ_API_KEY, MISTRAL_API_KEY, CLOUDFLARE_API_KEY
const envKey = (name) => process.env[name.toUpperCase() + "_API_KEY"];
const dailyCap = (name) => Number(process.env[name.toUpperCase() + "_DAILY_LIMIT"] || PROVIDERS[name].daily);

// Shared daily counters, per provider (reset at midnight UTC)
let shared = { day: "", n: {} };
const today = () => new Date().toISOString().slice(0, 10);
function resetIfNewDay() { if (shared.day !== today()) shared = { day: today(), n: {} }; }
function sharedLeft(name) {
  resetIfNewDay();
  return dailyCap(name) - (shared.n[name] || 0);
}
// True if at least one shared AI still has messages left today
const sharedUsable = () => Object.keys(PROVIDERS).some((n) => envKey(n) && sharedLeft(n) > 0);

// --- app icon and manifest, so the app can sit on the Home Screen like a real app ---
const manifest = {
  name: "AI Relay",
  short_name: "AI Relay",
  start_url: "/",
  display: "standalone",
  background_color: "#000000",
  theme_color: "#000000",
  icons: [
    { src: "/icon-192.png", sizes: "192x192", type: "image/png" },
    { src: "/icon-512.png", sizes: "512x512", type: "image/png" },
  ],
};
const crcTable = (() => {
  const t = [];
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();
function crc32(buf) {
  let c = 0xffffffff;
  for (const b of buf) c = crcTable[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
function pngChunk(type, data) {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type), data]);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(td));
  return Buffer.concat([len, td, crc]);
}
// Draws a blue tile with two white arrows (one pointing right, one pointing left).
function makeIcon(size) {
  const stride = size * 3 + 1;
  const raw = Buffer.alloc(stride * size);
  const ly1 = size * 0.38, ly2 = size * 0.62, th = size * 0.07;
  const x0 = size * 0.24, x1 = size * 0.76, hw = size * 0.12;
  for (let y = 0; y < size; y++) {
    raw[y * stride] = 0;
    for (let x = 0; x < size; x++) {
      const t = (x + y) / (2 * size);
      let r = 37 + (56 - 37) * t, g = 99 + (189 - 99) * t, b = 235 + (248 - 235) * t;
      let white = false;
      if (x >= x0 && x <= x1 && Math.abs(y - ly1) <= th / 2) white = true;
      if (x >= x1 - hw && x <= x1 && Math.abs(y - ly1) <= (x1 - x)) white = true;
      if (x >= x0 && x <= x1 && Math.abs(y - ly2) <= th / 2) white = true;
      if (x >= x0 && x <= x0 + hw && Math.abs(y - ly2) <= (x - x0)) white = true;
      const i = y * stride + 1 + x * 3;
      raw[i] = white ? 255 : r;
      raw[i + 1] = white ? 255 : g;
      raw[i + 2] = white ? 255 : b;
    }
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0); ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; ihdr[9] = 2; ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;
  return Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    pngChunk("IHDR", ihdr),
    pngChunk("IDAT", zlib.deflateSync(raw)),
    pngChunk("IEND", Buffer.alloc(0)),
  ]);
}
const iconCache = {};
const iconFor = (size) => (iconCache[size] ||= makeIcon(size));

// --- text helpers: a message is either plain text or [text part, image part] ---
const textOf = (c) => Array.isArray(c) ? ((c.find((p) => p && p.type === "text") || {}).text || "") : String(c ?? "");
const hasPhoto = (c) => Array.isArray(c) && c.some((p) => p && p.type === "image_url");
// Text version used when saving chats (photos aren't stored, so we keep a marker)
const plain = (c) => hasPhoto(c) ? (textOf(c) + " [photo]").trim() : textOf(c);

// --- storage: Upstash Redis when configured, otherwise one encrypted local file per access key ---
const sha = (s) => crypto.createHash("sha256").update(s).digest();
const idOf = (t) => sha("id:" + t).toString("hex");
const fileOf = (t) => path.join(DIR, idOf(t) + ".bin");

// Talks to Upstash over its REST API. Each command is a JSON array, e.g. ["GET", "key"].
async function redis(cmd) {
  const r = await fetch(UP_URL, {
    method: "POST",
    headers: { Authorization: `Bearer ${UP_TOKEN}`, "Content-Type": "application/json" },
    body: JSON.stringify(cmd),
    signal: AbortSignal.timeout(10000),
  });
  const j = await r.json();
  if (j.error) throw new Error("storage: " + j.error);
  return j.result;
}

async function readBlob(t) {
  if (USE_REDIS) {
    const v = await redis(["GET", "relay:" + idOf(t)]);
    return v ? Buffer.from(v, "base64") : null;
  }
  try { return fs.readFileSync(fileOf(t)); } catch { return null; }
}
async function writeBlob(t, buf) {
  if (USE_REDIS) return redis(["SET", "relay:" + idOf(t), buf.toString("base64")]);
  fs.writeFileSync(fileOf(t), buf);
}

// Counts how many personal keys a network has created today. The counter expires at midnight UTC.
const memCounts = {};
async function bumpNetworkCountToday(ip) {
  const day = today();
  const id = sha("net:" + day + ":" + ip).toString("hex");
  if (USE_REDIS) {
    const key = "netcount:" + id;
    const count = Number(await redis(["INCR", key]));
    if (count === 1) await redis(["EXPIRE", key, String(secondsUntilMidnightUTC())]);
    return count;
  }
  memCounts[id] = (memCounts[id] || 0) + 1;
  return memCounts[id];
}
function secondsUntilMidnightUTC() {
  const now = new Date();
  const next = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1);
  return Math.max(1, Math.ceil((next - now.getTime()) / 1000));
}
// Friendly reset time, e.g. "tomorrow at 00:00 UTC (in 7 hours)".
function resetMessage() {
  const secs = secondsUntilMidnightUTC();
  const hours = Math.floor(secs / 3600), mins = Math.ceil((secs % 3600) / 60);
  const when = hours > 0 ? `${hours} hour${hours === 1 ? "" : "s"}${mins ? " " + mins + " min" : ""}` : `${mins} min`;
  return `You've reached the limit of ${MAX_KEYS_PER_NETWORK_PER_DAY} personal keys from this network today. You can create more tomorrow at 00:00 UTC, in about ${when}.`;
}

const newUser = () => ({ keys: {}, usage: {}, until: {}, reason: {}, selected: "auto", current: null, lim: {}, chats: {} });

async function loadUser(t) {
  try {
    const b = await readBlob(t);
    if (!b) return null;
    const d = crypto.createDecipheriv("aes-256-gcm", sha("enc:" + t), b.subarray(0, 12));
    d.setAuthTag(b.subarray(12, 28));
    return JSON.parse(Buffer.concat([d.update(b.subarray(28)), d.final()]).toString());
  } catch { return null; }
}
async function saveUser(t, u) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", sha("enc:" + t), iv);
  const enc = Buffer.concat([c.update(JSON.stringify(u)), c.final()]);
  await writeBlob(t, Buffer.concat([iv, c.getAuthTag(), enc]));
}

// --- per-AI limits for one person: each AI has its own hourly and daily count ---
function limitOf(u, name) {
  u.lim ||= {};
  const L = (u.lim[name] ||= { hs: 0, hn: 0, day: "", dn: 0 });
  if (Date.now() - L.hs > 3600000) { L.hs = Date.now(); L.hn = 0; }
  if (L.day !== today()) { L.day = today(); L.dn = 0; }
  return L;
}

// --- saved chats ---
function putChat(u, id, messages) {
  if (!id || !Array.isArray(messages)) return;
  const key = String(id).slice(0, 40);
  u.chats ||= {};
  if (!messages.length) { delete u.chats[key]; return; }
  const clean = messages.slice(-MAX_MESSAGES).map((m) => ({
    role: m.role === "assistant" ? "assistant" : "user",
    content: plain(m.content).slice(0, 20000),
    meta: String(m.meta || "").slice(0, 200),
  }));
  const first = clean.find((m) => m.role === "user");
  const title = (first ? first.content : "New chat").replace(/\s+/g, " ").trim().slice(0, 48) || "New chat";
  u.chats[key] = { id: key, title, updated: Date.now(), messages: clean };
  const sorted = Object.values(u.chats).sort((a, b) => b.updated - a.updated);
  for (const old of sorted.slice(MAX_CHATS)) delete u.chats[old.id];
}
const listChats = (u) => Object.values(u.chats || {}).sort((a, b) => b.updated - a.updated).map(({ id, title, updated }) => ({ id, title, updated }));

// --- model names: remember the one that worked for each AI ---
const models = {}; // AI name -> model name that last worked
const modelFor = (name) => models[name] || PROVIDERS[name].model;

function errText(text) {
  try {
    const j = JSON.parse(text);
    const m = j.error?.message || j.message || (Array.isArray(j) ? j[0]?.error?.message : "") || "";
    return String(m).replace(/\s+/g, " ").slice(0, 120);
  } catch { return String(text).replace(/\s+/g, " ").slice(0, 120); }
}

const headersFor = (key) => ({ "Content-Type": "application/json", Authorization: `Bearer ${key}` });

// Is this error about the model name (so trying another name may help)?
const isModelError = (status, text) =>
  status === 404 || status === 410 || (status === 400 && /model|not found|does not exist|unsupported|slug|isn't available|not available|decommissioned/i.test(text));

// Names that are never chat models.
const NOT_CHAT = /embed|whisper|tts|guard|vision|image|rerank|moderation|audio|dall|diffusion|clip|safety|speech|transcri|robotics|ocr|\br1\b|distill|reward|prompt|code|vl\b|-vl|asr|stt|clef|clairic|moondream|flux|stable|bge|whisper|resnet|aura|melotts|sqlcoder|uform/i;

// Ask the provider which models this key can use. Returns the list of names (may be empty), or null if unreadable.
async function listModels(name, key) {
  const p = PROVIDERS[name];
  try {
    const res = await fetch(p.listUrl, { headers: headersFor(key), signal: AbortSignal.timeout(15000) });
    if (!res.ok) return null;
    const j = await res.json();
    const raw = j.data || j.models || j.result || [];
    const out = [];
    for (const m of raw) {
      const id = String(m.id || m.name || m.model || "").replace(/^models\//, "");
      if (!id) continue;
      const task = typeof m.task === "string" ? m.task : m.task?.name;
      if (task && !/text generation/i.test(task)) continue;
      if (NOT_CHAT.test(id)) continue;
      out.push(id);
    }
    return out;
  } catch { return null; }
}

// Choose the next model name to try.
// 1. Known names that the provider lists for this key.
// 2. For AIs with lookup on, any text model the provider lists for this key.
// 3. The next known name, even if it isn't listed.
async function findNextModel(name, key, skip) {
  const p = PROVIDERS[name];
  const available = await listModels(name, key);
  if (available) {
    const set = new Set(available);
    const listedKnown = (p.known || []).find((id) => set.has(id) && !skip.has(id));
    if (listedKnown) return listedKnown;
    if (p.lookup) {
      const listedAny = available.find((id) => !skip.has(id));
      if (listedAny) return listedAny;
    }
  }
  return (p.known || []).find((id) => !skip.has(id)) || null;
}

// --- failover logic, per user ---
const usage = (u, n) => (u.usage[n] ||= { ok: 0, fail: 0, tokens: 0, left: null });
const resting = (u, n) => (u.until[n] || 0) > Date.now();
function ordered(u) {
  const have = Object.keys(PROVIDERS).filter((n) => u.keys[n] || envKey(n));
  return have.includes(u.selected) ? [u.selected, ...have.filter((n) => n !== u.selected)] : have;
}
// If the person pinned an AI, use ONLY that AI. Auto-switch uses them all in order.
function planFor(u) {
  const all = ordered(u);
  return u.selected !== "auto" && all.includes(u.selected) ? [u.selected] : all;
}
function cooldownFor(res, text) {
  const ra = parseInt(res.headers.get("retry-after"), 10);
  if (!isNaN(ra)) return ra * 1000;
  return /day|daily|quota|credit|billing|balance/i.test(text) ? 3600000 : 60000;
}

// Keep only the latest messages (starting with a user message) and shorten very long text.
function trimContext(messages, n) {
  let out = messages.slice(-n);
  while (out.length && out[0].role !== "user") out = out.slice(1);
  return out.map((m) => {
    if (hasPhoto(m.content)) return m;
    const t = textOf(m.content);
    return { role: m.role, content: t.length > CONTEXT_CHARS ? t.slice(-CONTEXT_CHARS) : t };
  });
}

// Shape the messages for one AI. Text-only AIs get text; only the newest photo is sent to photo-capable AIs.
function prepare(name, messages) {
  const last = messages.length - 1;
  return messages.map((m, i) => {
    if (!hasPhoto(m.content)) return { role: m.role, content: textOf(m.content) };
    if (!VISION.includes(name) || i !== last) return { role: m.role, content: plain(m.content) };
    if (name === "Mistral") {
      return { role: m.role, content: m.content.map((p) => p.type === "image_url" ? { type: "image_url", image_url: p.image_url.url } : p) };
    }
    return { role: m.role, content: m.content };
  });
}

// Call one AI with one model name. Returns { ok, reply, tokens } or { ok:false, reason, cooldown, modelError }.
async function callModel(name, key, model, messages) {
  const p = PROVIDERS[name];
  for (let attempt = 0; attempt < 2; attempt++) {
    // First try the recent context; if the provider's per-minute token limit is hit, retry with only the last 2 messages.
    const ctx = trimContext(messages, attempt === 0 ? CONTEXT_MESSAGES : 2);
    try {
      const res = await fetch(p.url, {
        method: "POST",
        headers: headersFor(key),
        body: JSON.stringify({ model, messages: prepare(name, ctx), max_tokens: 1024 }),
        signal: AbortSignal.timeout(45000),
      });
      const text = await res.text();
      if (res.ok) {
        const data = JSON.parse(text), reply = data.choices?.[0]?.message?.content;
        if (reply) return { ok: true, reply, tokens: data.usage?.total_tokens || 0 };
        return { ok: false, reason: "empty reply", cooldown: 30000 };
      }
      if (attempt === 0 && res.status === 429 && /token/i.test(text)) continue;
      const detail = errText(text);
      if (isModelError(res.status, text)) {
        return { ok: false, modelError: true, reason: `${model} isn't available for this key${detail ? " (" + detail + ")" : ""}`, cooldown: 60000 };
      }
      if (res.status === 401) {
        return { ok: false, reason: "key rejected. Copy the key again from the provider and paste it into this AI's card, then Save.", cooldown: 300000 };
      }
      const cooldown = [402, 403, 429].includes(res.status) || res.status >= 500 ? cooldownFor(res, text) : 30000;
      return { ok: false, reason: `HTTP ${res.status}${detail ? ": " + detail : ""}`, cooldown };
    } catch (e) {
      return { ok: false, reason: e.message, cooldown: 30000 };
    }
  }
  return { ok: false, reason: "request failed", cooldown: 30000 };
}

// only = ask just this AI (used by the Test button). test = don't count it against limits.
async function ask(u, messages, only, test) {
  const tried = [];
  const photo = hasPhoto(messages[messages.length - 1]?.content);
  let list = only ? [only] : planFor(u);
  if (photo) {
    const ok = list.filter((n) => VISION.includes(n));
    if (!ok.length) {
      const pinned = !only && u.selected !== "auto" && !VISION.includes(u.selected) ? u.selected : null;
      const err = new Error(pinned
        ? `${pinned} can't read photos. Pick Mistral in AI providers, or choose Auto-switch.`
        : "Photos only work with Mistral right now. Add a free Mistral key in AI providers.");
      err.tried = []; throw err;
    }
    list = ok;
  }
  let limited = 0;
  for (const name of list) {
    if (resting(u, name)) { tried.push(`${name}: resting`); continue; }
    const usingShared = !u.keys[name];
    if (usingShared && !test) {
      if (dailyCap(name) <= 0) { tried.push(`${name}: shared use is off. Add your own key for this AI.`); continue; }
      if (sharedLeft(name) <= 0) { tried.push(`${name}: shared daily limit reached`); continue; }
      const L = limitOf(u, name);
      if (L.hn >= PER_USER_HOURLY) { limited++; tried.push(`${name}: your ${PER_USER_HOURLY} messages this hour are used`); continue; }
      if (L.dn >= PER_USER_DAILY) { limited++; tried.push(`${name}: your ${PER_USER_DAILY} messages today are used`); continue; }
    }
    const s = usage(u, name);
    const key = u.keys[name] || envKey(name);

    // Try the saved or default model. If it isn't available, move to the next name.
    const skip = new Set();
    let answered = null, last = null;
    let model = modelFor(name);
    for (let step = 0; step < 8 && !answered; step++) {
      if (!model) {
        model = await findNextModel(name, key, skip);
        if (!model) break;
      }
      skip.add(model);
      last = await callModel(name, key, model, messages);
      if (last.ok) { answered = { reply: last.reply, tokens: last.tokens, model }; break; }
      if (!last.modelError) break;
      model = null;
    }

    if (answered) {
      if (usingShared && !test) {
        shared.n[name] = (shared.n[name] || 0) + 1;
        const L = limitOf(u, name); L.hn++; L.dn++;
      }
      models[name] = answered.model;
      s.ok++; s.tokens += answered.tokens; u.current = name; u.reason[name] = "";
      return { reply: answered.reply, provider: name, model: answered.model, fellBack: u.selected !== "auto" && u.selected !== name, shared: usingShared };
    }

    const reason = last ? last.reason : "none of this AI's models worked for this key";
    s.fail++; u.reason[name] = reason;
    u.until[name] = Date.now() + (last ? last.cooldown : 60000);
    tried.push(`${name}: ${reason}`);
  }
  let msg;
  if (limited > 0 && limited === list.length) msg = `You've used your limit on this AI (${PER_USER_HOURLY} an hour, ${PER_USER_DAILY} a day). Each AI has its own limit, so pick a different AI in AI providers.`;
  else if (u.selected !== "auto" && !only && list.length === 1) msg = `${list[0]} didn't answer. Reason: ${tried[0] ? tried[0].replace(/^[^:]*:\s*/, "") : "unknown"}. Use Test on its card for details, or pick another AI.`;
  else if (list.length) msg = "All providers are resting right now.";
  else msg = "Add at least one key first (AI providers).";
  const err = new Error(msg);
  err.tried = tried; throw err;
}

function status(u) {
  const next = planFor(u).find((n) => !resting(u, n));
  return {
    selected: u.selected, current: u.current, nextUp: next || null,
    limits: { perHour: PER_USER_HOURLY, perDay: PER_USER_DAILY },
    providers: Object.entries(PROVIDERS).map(([name, p]) => {
      const s = usage(u, name), own = !!u.keys[name];
      const L = own ? null : limitOf(u, name);
      return { name, model: modelFor(name) || "checking your key…", keyUrl: p.keyUrl, paid: !!p.paid, hasKey: !!(u.keys[name] || envKey(name)), own, coolingDown: resting(u, name),
        resumesInSec: Math.max(0, Math.ceil(((u.until[name] || 0) - Date.now()) / 1000)), reason: u.reason[name] || "",
        requests: s.ok, errors: s.fail, tokens: s.tokens, left: s.left,
        usedThisHour: L ? L.hn : null, usedToday: L ? L.dn : null,
        sharedLeftToday: envKey(name) ? Math.max(0, sharedLeft(name)) : null }; // provider keys are never sent back
    }),
  };
}

const send = (res, code, obj) => { res.writeHead(code, { "Content-Type": "application/json" }); res.end(JSON.stringify(obj)); };

async function route(req, res) {
  // Home Screen icon and app settings
  if (req.method === "GET" && req.url === "/manifest.json") {
    res.writeHead(200, { "Content-Type": "application/manifest+json", "Cache-Control": "public, max-age=3600" });
    return res.end(JSON.stringify(manifest));
  }
  if (req.method === "GET" && (req.url === "/icon-192.png" || req.url === "/icon-512.png" || req.url === "/apple-touch-icon.png")) {
    const size = req.url.includes("512") ? 512 : req.url.includes("192") ? 192 : 180;
    res.writeHead(200, { "Content-Type": "image/png", "Cache-Control": "public, max-age=86400" });
    return res.end(iconFor(size));
  }

  if (!req.url.startsWith("/api/")) {
    return fs.readFile(path.join(__dirname, "index.html"), (err, data) => {
      if (err) { res.writeHead(404); return res.end("Not found"); }
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" }); res.end(data);
    });
  }
  let raw = "";
  for await (const c of req) { raw += c; if (raw.length > 6e6) return send(res, 413, { error: "too large" }); }
  let body = {}; try { body = raw ? JSON.parse(raw) : {}; } catch { return send(res, 400, { error: "bad request" }); }

  if (req.url === "/api/signup" && req.method === "POST") {
    const ip = String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();
    const count = await bumpNetworkCountToday(ip);
    if (count > MAX_KEYS_PER_NETWORK_PER_DAY) {
      return send(res, 429, { error: resetMessage() });
    }
    const token = "fa-" + crypto.randomBytes(18).toString("base64url");
    await saveUser(token, newUser());
    return send(res, 200, { token });
  }
  const token = req.headers["x-access-key"] || "";
  const u = token ? await loadUser(token) : null;
  if (!u) return send(res, 401, { error: "Key not recognized" });

  if (req.url === "/api/status") return send(res, 200, status(u));

  if (req.url === "/api/chats") return send(res, 200, listChats(u));
  if (req.url === "/api/chats/open") {
    const c = u.chats?.[String(body.id || "").slice(0, 40)];
    return c ? send(res, 200, c) : send(res, 404, { error: "Chat not found" });
  }
  if (req.url === "/api/chats/delete") {
    if (u.chats) delete u.chats[String(body.id || "").slice(0, 40)];
    await saveUser(token, u);
    return send(res, 200, listChats(u));
  }
  if (req.url === "/api/chats/sync") {
    putChat(u, body.id, body.messages);
    await saveUser(token, u);
    return send(res, 200, listChats(u));
  }

  if (req.url === "/api/key" && PROVIDERS[body.provider]) {
    if (body.key) { u.keys[body.provider] = String(body.key).trim(); delete u.until[body.provider]; u.reason[body.provider] = ""; }
    else { delete u.keys[body.provider]; if (u.selected === body.provider) u.selected = "auto"; }
    await saveUser(token, u); return send(res, 200, status(u));
  }
  if (req.url === "/api/select") {
    if (body.provider === "auto" || u.keys[body.provider] || envKey(body.provider)) u.selected = body.provider;
    await saveUser(token, u); return send(res, 200, status(u));
  }
  if (req.url === "/api/test" && PROVIDERS[body.provider]) {
    const name = body.provider;
    if (!u.keys[name] && !envKey(name)) return send(res, 200, { ok: false, error: "No key added for this AI yet." });
    if (!u.keys[name] && dailyCap(name) <= 0) return send(res, 200, { ok: false, error: "Shared use is off for this AI. Add your own key to test it." });
    try {
      const out = await ask(u, [{ role: "user", content: "Reply with just the word OK." }], name, true);
      await saveUser(token, u);
      return send(res, 200, { ok: true, reply: String(out.reply).slice(0, 60), model: out.model });
    } catch (e) {
      await saveUser(token, u);
      return send(res, 200, { ok: false, error: (e.tried && e.tried[0]) || e.message });
    }
  }
  if (req.url === "/api/chat" && Array.isArray(body.messages)) {
    const hasOwn = Object.values(u.keys).some(Boolean);
    if (!ordered(u).length) return send(res, 503, { error: "Add at least one key first. Tap the AI providers button at the top." });
    if (!hasOwn && !sharedUsable()) return send(res, 503, { error: "Today's shared limit is used up on every AI. It resets at midnight UTC. You can also add your own key." });
    try {
      const out = await ask(u, body.messages);
      putChat(u, body.chatId, [...body.messages, { role: "assistant", content: out.reply, meta: out.provider + " · " + out.model }]);
      await saveUser(token, u);
      return send(res, 200, out);
    } catch (e) { await saveUser(token, u); return send(res, 503, { error: e.message, tried: e.tried || [] }); }
  }
  send(res, 404, { error: "not found" });
}

http.createServer((req, res) => {
  route(req, res).catch((e) => {
    console.error(e);
    if (!res.headersSent) send(res, 500, { error: "Something went wrong on the server. Try again." });
  });
}).listen(process.env.PORT || 3000, () => console.log(`AI Relay on http://localhost:${process.env.PORT || 3000}`));
