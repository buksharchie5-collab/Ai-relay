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
// The full chat is still saved and shown on screen.
const CONTEXT_MESSAGES = 10; // how many recent messages the AI sees
const CONTEXT_CHARS = 3000;  // long messages are shortened for the AI to this many characters

// Free-tier models change often: edit `model` here if a provider retires one.
// `daily` = messages per day allowed on the SHARED key (set in Render as NAME_API_KEY).
//           Override in Render with NAME_DAILY_LIMIT, e.g. CHATGPT_DAILY_LIMIT = 0 turns sharing off.
// `paid` = needs billing. Shared use of a paid AI costs you money, so keep its daily number low.
// `discover` = allowed to swap to a replacement model if this one is retired.
const PROVIDERS = {
  Groq: { url: "https://api.groq.com/openai/v1/chat/completions", model: "llama-3.3-70b-versatile", keyUrl: "https://console.groq.com/keys", daily: 900, discover: true, paid: false },
  Cerebras: { url: "https://api.cerebras.ai/v1/chat/completions", model: "llama-3.3-70b", keyUrl: "https://cloud.cerebras.ai", daily: 500, discover: true, paid: false },
  NVIDIA: { url: "https://integrate.api.nvidia.com/v1/chat/completions", model: "meta/llama-3.3-70b-instruct", keyUrl: "https://build.nvidia.com", daily: 500, discover: true, paid: false },
  ChatGPT: { url: "https://api.openai.com/v1/chat/completions", model: "gpt-4o-mini", keyUrl: "https://platform.openai.com/api-keys", daily: 50, discover: false, paid: true },
  Grok: { url: "https://api.x.ai/v1/chat/completions", model: "grok-3-mini", keyUrl: "https://console.x.ai", daily: 50, discover: false, paid: true },
};

// Replacement models are only chosen from the same family as the original.
const FAMILY = {
  Groq: /llama.*70b/i, Cerebras: /llama.*70b/i, NVIDIA: /llama.*70b/i,
};
// Never pick these kinds of models for chat.
const NOT_CHAT = /code|embed|whisper|tts|guard|vision|image|rerank|moderation|audio|dall|diffusion|clip|safety|speech|transcri|robotics|learnlm|ocr|\br1\b|distill|reward|prompt/i;

// AIs that can read photos. Photos are only sent to these.
const VISION = ["ChatGPT"];

// Keys come from Render's environment, e.g. GROQ_API_KEY, CHATGPT_API_KEY, GROK_API_KEY
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

// --- model auto-repair: only for free AIs that allow it, and only within the same model family ---
const models = {}; // AI name -> replacement model found automatically
const modelOf = (name) => models[name] || PROVIDERS[name].model;

function errText(text) {
  try {
    const j = JSON.parse(text);
    const m = j.error?.message || j.message || (Array.isArray(j) ? j[0]?.error?.message : "") || "";
    return String(m).replace(/\s+/g, " ").slice(0, 120);
  } catch { return String(text).replace(/\s+/g, " ").slice(0, 120); }
}

const headersFor = (key) => ({ "Content-Type": "application/json", Authorization: `Bearer ${key}` });

async function discover(name, key) {
  if (!PROVIDERS[name].discover || !FAMILY[name]) return null;
  try {
    const res = await fetch(PROVIDERS[name].url.replace("/chat/completions", "/models"), { headers: headersFor(key), signal: AbortSignal.timeout(15000) });
    if (!res.ok) return null;
    const j = await res.json();
    const ids = (j.data || j.models || []).map((m) => String(m.id || m.name || "").replace(/^models\//, "")).filter(Boolean);
    const hit = ids.find((id) => FAMILY[name].test(id) && !NOT_CHAT.test(id));
    return hit || null;
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
    return { role: m.role, content: m.content };
  });
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
        ? `${pinned} can't read photos. Pick ChatGPT in AI providers, or choose Auto-switch.`
        : "Photos only work with ChatGPT right now. Add your own key for ChatGPT in AI providers.");
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
    const p = PROVIDERS[name], s = usage(u, name);
    const key = u.keys[name] || envKey(name);
    let reason = "";
    for (let attempt = 0; attempt < 2; attempt++) {
      // First try the recent context; if the provider's per-minute token limit is hit, retry with only the last 2 messages.
      const ctx = trimContext(messages, attempt === 0 ? CONTEXT_MESSAGES : 2);
      try {
        const res = await fetch(p.url, {
          method: "POST",
          headers: headersFor(key),
          body: JSON.stringify({ model: modelOf(name), messages: prepare(name, ctx), max_tokens: 1024 }),
          signal: AbortSignal.timeout(45000),
        });
        const text = await res.text();
        if (res.ok) {
          const data = JSON.parse(text), reply = data.choices?.[0]?.message?.content;
          if (reply) {
            if (usingShared && !test) {
              shared.n[name] = (shared.n[name] || 0) + 1;
              const L = limitOf(u, name); L.hn++; L.dn++;
            }
            s.ok++; s.tokens += data.usage?.total_tokens || 0; u.current = name; u.reason[name] = "";
            const rl = res.headers.get("x-ratelimit-remaining-requests");
            if (rl !== null) s.left = Number(rl);
            return { reply, provider: name, model: modelOf(name), fellBack: u.selected !== "auto" && u.selected !== name, shared: usingShared };
          }
          reason = "empty reply"; u.until[name] = Date.now() + 30000; break;
        }
        // Too many tokens this minute? Retry once with a much shorter context.
        if (attempt === 0 && res.status === 429 && /token/i.test(text)) continue;
        // Model retired or renamed? Look for a replacement from the same family and try once more.
        if (attempt === 0 && (res.status === 404 || res.status === 410 || (res.status === 400 && /model/i.test(text)))) {
          const m = await discover(name, key);
          if (m && m !== modelOf(name)) { models[name] = m; continue; }
        }
        const detail = errText(text);
        if (res.status === 401) {
          reason = "key rejected. Copy the key again from the provider and paste it into this AI's card, then Save.";
          u.until[name] = Date.now() + 300000;
        } else {
          reason = `HTTP ${res.status}${detail ? ": " + detail : ""}`;
          if (res.status === 404 || res.status === 410) u.until[name] = Date.now() + 300000;
          else if ([402, 403, 429].includes(res.status) || res.status >= 500) u.until[name] = Date.now() + cooldownFor(res, text);
          else u.until[name] = Date.now() + 30000;
        }
        break;
      } catch (e) { reason = e.message; u.until[name] = Date.now() + 30000; break; }
    }
    s.fail++; u.reason[name] = reason; tried.push(`${name}: ${reason}`);
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
      return { name, model: modelOf(name), keyUrl: p.keyUrl, paid: !!p.paid, hasKey: !!(u.keys[name] || envKey(name)), own, coolingDown: resting(u, name),
        resumesInSec: Math.max(0, Math.ceil(((u.until[name] || 0) - Date.now()) / 1000)), reason: u.reason[name] || "",
        requests: s.ok, errors: s.fail, tokens: s.tokens, left: s.left,
        usedThisHour: L ? L.hn : null, usedToday: L ? L.dn : null,
        sharedLeftToday: envKey(name) ? Math.max(0, sharedLeft(name)) : null }; // provider keys are never sent back
    }),
  };
}

const signups = {}; // simple per-network limit on new keys
const send = (res, code, obj) => { res.writeHead(code, { "Content-Type": "application/json" }); res.end(JSON.stringify(obj)); };

async function route(req, res) {
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
    const hits = (signups[ip] || []).filter((t) => Date.now() - t < 3600000);
    if (hits.length >= 10) return send(res, 429, { error: "Too many new keys from your network. Try again in an hour." });
    signups[ip] = [...hits, Date.now()];
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
