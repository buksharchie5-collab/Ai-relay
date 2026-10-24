// AI Relay — personal keys, plus shared keys with fair-use limits.
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

// Accounts and chats are saved as local files in this folder.
const DIR = process.env.DATA_DIR || path.join(__dirname, "data");
fs.mkdirSync(DIR, { recursive: true });

// Fair-use limits. On shared keys these apply to EACH AI separately. Your own keys aren't capped.
const PER_USER_HOURLY = 20; // messages per person per AI per hour
const PER_USER_DAILY = 70;  // messages per person per AI per day
const MAX_CHATS = 50;       // saved chats per person
const MAX_MESSAGES = 200;   // messages kept per chat

// Only the latest messages are sent to the AI, so providers don't hit their per-minute token limits.
const CONTEXT_MESSAGES = 10; // how many recent messages the AI sees
const CONTEXT_CHARS = 3000;  // long messages are shortened for the AI to this many characters

// `model` = first model name to try. If it isn't available for your key, the app asks the provider
// for the models your key CAN use (`listUrl`) and picks a chat model from that list.
// `daily` = messages per day allowed on the SHARED key (set in Render as NAME_API_KEY).
//           Override in Render with NAME_DAILY_LIMIT, e.g. MISTRAL_DAILY_LIMIT = 0 turns sharing off.
// `paid` = needs billing. Shared use of a paid AI costs you money, so keep its daily number low.
const PROVIDERS = {
  Groq: { url: "https://api.groq.com/openai/v1/chat/completions", listUrl: "https://api.groq.com/openai/v1/models", model: "llama-3.3-70b-versatile", keyUrl: "https://console.groq.com/keys", daily: 900, paid: false },
  Cerebras: { url: "https://api.cerebras.ai/v1/chat/completions", listUrl: "https://api.cerebras.ai/v1/models", model: "gpt-oss-120b", keyUrl: "https://cloud.cerebras.ai", daily: 500, paid: false },
  NVIDIA: { url: "https://integrate.api.nvidia.com/v1/chat/completions", listUrl: "https://integrate.api.nvidia.com/v1/models", model: null, keyUrl: "https://build.nvidia.com", daily: 500, paid: false },
  Mistral: { url: "https://api.mistral.ai/v1/chat/completions", listUrl: "https://api.mistral.ai/v1/models", model: "mistral-small-latest", keyUrl: "https://console.mistral.ai", daily: 200, paid: false },
  OpenRouter: { url: "https://openrouter.ai/api/v1/chat/completions", listUrl: "https://openrouter.ai/api/v1/models", model: "google/gemma-3-27b-it:free", keyUrl: "https://openrouter.ai/keys", daily: 45, paid: false },
  Cloudflare: { url: `https://api.cloudflare.com/client/v4/accounts/${process.env.CLOUDFLARE_ACCOUNT_ID || "missing-account-id"}/ai/v1/chat/completions`, listUrl: `https://api.cloudflare.com/client/v4/accounts/${process.env.CLOUDFLARE_ACCOUNT_ID || "missing-account-id"}/ai/models/search`, model: null, keyUrl: "https://dash.cloudflare.com/profile/api-tokens", daily: 100, paid: false },
};

// Which model names are chat models, per AI. Used when picking from a provider's model list.
const CHAT_PICK = {
  Groq: /llama|gpt-oss|gemma|qwen|mixtral/i,
  Cerebras: /llama|gpt-oss|qwen/i,
  NVIDIA: /llama|gemma|mistral|mixtral/i,
  Mistral: /mistral|ministral/i,
  OpenRouter: /gemma|llama|mistral|qwen/i,
  Cloudflare: /llama|gemma|mistral|qwen/i,
};
// Never pick these kinds of models for chat.
const NOT_CHAT = /embed|whisper|tts|guard|vision|image|rerank|moderation|audio|dall|diffusion|clip|safety|speech|transcri|robotics|ocr|\br1\b|distill|reward|prompt|code|vl\b|-vl|asr|tts|stt|reasoning|thinking/i;

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

// --- text helpers: a message is either plain text or [text part, image part] ---
const textOf = (c) => Array.isArray(c) ? ((c.find((p) => p && p.type === "text") || {}).text || "") : String(c ?? "");
const hasPhoto = (c) => Array.isArray(c) && c.some((p) => p && p.type === "image_url");
// Text version used when saving chats (photos aren't stored, so we keep a marker)
const plain = (c) => hasPhoto(c) ? (textOf(c) + " [photo]").trim() : textOf(c);

// --- storage: one encrypted file per access key (the key itself is never stored) ---
const sha = (s) => crypto.createHash("sha256").update(s).digest();
const fileOf = (t) => path.join(DIR, sha("id:" + t).toString("hex") + ".bin");

async function readBlob(t) {
  try { return fs.readFileSync(fileOf(t)); } catch { return null; }
}
async function writeBlob(t, buf) {
  fs.writeFileSync(fileOf(t), buf);
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

// Is this error about the model name (so asking for a working model may help)?
const isModelError = (status, text) =>
  status === 404 || status === 410 || (status === 400 && /model|not found|does not exist|unsupported|slug|isn't available|not available/i.test(text));

// Ask the provider which models this key can use, and pick a chat model from that list.
async function findWorkingModel(name, key) {
  const p = PROVIDERS[name];
  try {
    const res = await fetch(p.listUrl, { headers: headersFor(key), signal: AbortSignal.timeout(15000) });
    if (!res.ok) return null;
    const j = await res.json();
    const raw = j.data || j.models || j.result || [];
    const ids = raw.map((m) => String(m.id || m.name || m.model || "").replace(/^models\//, "")).filter(Boolean);
    const pick = CHAT_PICK[name];
    return ids.find((id) => pick && pick.test(id) && !NOT_CHAT.test(id)) || null;
  } catch { return null; }
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

    // Try the saved or default model. If it isn't available, ask the provider for a model this key can use, then try that.
    let answered = null, last = null;
    let model = modelFor(name);
    let triedLookup = false;
    for (let step = 0; step < 3 && !answered; step++) {
      if (!model) {
        triedLookup = true;
        model = await findWorkingModel(name, key);
        if (!model) break;
      }
      last = await callModel(name, key, model, messages);
      if (last.ok) { answered = { reply: last.reply, tokens: last.tokens, model }; break; }
      if (!last.modelError || triedLookup) break;
      model = await findWorkingModel(name, key);
      triedLookup = true;
      if (!model) break;
    }

    if (answered) {
      if (usingShared && !test) {
        shared.n[name] = (shared.n[name] || 0) + 1;
        const L = limitOf(u,
