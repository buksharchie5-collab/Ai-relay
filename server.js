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

// `model` = first model name to try. `candidates` = other names to try if one isn't available for your key.
// If a provider says "use this slug instead", the app tries that name automatically.
// `daily` = messages per day allowed on the SHARED key (set in Render as NAME_API_KEY).
//           Override in Render with NAME_DAILY_LIMIT, e.g. MISTRAL_DAILY_LIMIT = 0 turns sharing off.
// `paid` = needs billing. Shared use of a paid AI costs you money, so keep its daily number low.
const PROVIDERS = {
  Groq: { url: "https://api.groq.com/openai/v1/chat/completions", model: "llama-3.3-70b-versatile", candidates: ["llama-3.1-8b-instant", "openai/gpt-oss-20b", "gemma2-9b-it"], keyUrl: "https://console.groq.com/keys", daily: 900, paid: false },
  Cerebras: { url: "https://api.cerebras.ai/v1/chat/completions", model: "gpt-oss-120b", candidates: ["llama3.1-8b", "qwen-3-32b", "llama-3.3-70b"], keyUrl: "https://cloud.cerebras.ai", daily: 500, paid: false },
  NVIDIA: { url: "https://integrate.api.nvidia.com/v1/chat/completions", model: "meta/llama-3.1-8b-instruct", candidates: ["google/gemma-2-9b-it", "mistralai/mistral-7b-instruct-v0.3"], keyUrl: "https://build.nvidia.com", daily: 500, paid: false },
  Mistral: { url: "https://api.mistral.ai/v1/chat/completions", model: "mistral-small-latest", candidates: ["mistral-medium-latest", "open-mistral-nemo"], keyUrl: "https://console.mistral.ai", daily: 200, paid: false },
  OpenRouter: { url: "https://openrouter.ai/api/v1/chat/completions", model: "google/gemma-3-27b-it:free", candidates: ["mistralai/mistral-small-3", "meta-llama/llama-3.3-70b-instruct:free"], keyUrl: "https://openrouter.ai/keys", daily: 45, paid: false },
  Cloudflare: { url: `https://api.cloudflare.com/client/v4/accounts/${process.env.CLOUDFLARE_ACCOUNT_ID || "missing-account-id"}/ai/v1/chat/completions`, model: "@cf/meta/llama-3.3-70b-instruct-fp8-fast", candidates: ["@cf/meta/llama-3.1-8b-instruct-fast", "@cf/google/gemma-3-12b-it"], keyUrl: "https://dash.cloudflare.com/profile/api-tokens", daily: 100, paid: false },
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
const modelsFor = (name) => [...new Set([models[name], PROVIDERS[name].model, ...(PROVIDERS[name].candidates || [])].filter(Boolean))].slice(0, 6);

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
  status === 404 || status === 410 || (status === 400 && /model|not found|does not exist|unsupported|slug/i.test(text));

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

// Call one AI with one model name. Returns { ok, reply, tokens } or { ok:false, reason, cooldown, modelError, suggested }.
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
        // Some providers name the right model in their error, e.g. "use this slug instead: x/y".
        const m = /(?:slug instead|instead)\s*:?\s*([A-Za-z0-9@._\/:-]+)/i.exec(text);
        return { ok: false, modelError: true, suggested: m ? m[1].replace(/[)"'.,]+$/, "") : null,
          reason: `${model} isn't available for this key${detail ? " (" + detail + ")" : ""}`, cooldown: 60000 };
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

    // Try each model name in turn, following any name the provider suggests, until one works.
    const queue = modelsFor(name);
    const seen = new Set();
    let answered = null, last = null;
    while (queue.length && !answered) {
      const model = queue.shift();
      if (seen.has(model)) continue;
      seen.add(model);
      last = await callModel(name, key, model, messages);
      if (last.ok) { answered = { reply: last.reply, tokens: last.tokens, model }; break; }
      if (!last.modelError) break; // not a model-name problem, so other names won't help
      if (last.suggested && !seen.has(last.suggested)) queue.unshift(last.suggested);
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

    const reason = last ? last.reason : "no model available";
    s.fail++; u.reason[name] = reason;
    u.until[name] = Date.now() + (last ? last.cooldown : 30000);
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
      return { name, model: modelsFor(name)[0], keyUrl: p.keyUrl, paid: !!p.paid, hasKey: !!(u.keys[name] || envKey(name)), own, coolingDown: resting(u, name),
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
