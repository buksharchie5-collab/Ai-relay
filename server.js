// AI Relay — personal keys, plus shared free keys with fair-use limits.
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const DIR = process.env.DATA_DIR || path.join(__dirname, "data");
fs.mkdirSync(DIR, { recursive: true });

// Fair-use limits for people using the shared keys (people with their own keys aren't capped).
const PER_USER_HOURLY = 20; // messages per person per hour
const PER_USER_DAILY = 70;  // messages per person per day

// Free-tier models change often: edit `model` here if a provider retires one.
// (If one is retired, the app also tries to find a working model by itself.)
// `daily` = messages per day allowed on YOUR shared key.
const PROVIDERS = {
  Groq: { url: "https://api.groq.com/openai/v1/chat/completions", model: "llama-3.3-70b-versatile", keyUrl: "https://console.groq.com/keys", daily: 900 },
  Cerebras: { url: "https://api.cerebras.ai/v1/chat/completions", model: "llama-3.3-70b", keyUrl: "https://cloud.cerebras.ai", daily: 500 },
  Gemini: { url: "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions", model: "gemini-2.5-flash", keyUrl: "https://aistudio.google.com/apikey", daily: 200 },
  OpenRouter: { url: "https://openrouter.ai/api/v1/chat/completions", model: "meta-llama/llama-3.3-70b-instruct:free", keyUrl: "https://openrouter.ai/keys", daily: 45 },
  Mistral: { url: "https://api.mistral.ai/v1/chat/completions", model: "mistral-small-latest", keyUrl: "https://console.mistral.ai", daily: 200 },
  NVIDIA: { url: "https://integrate.api.nvidia.com/v1/chat/completions", model: "meta/llama-3.3-70b-instruct", keyUrl: "https://build.nvidia.com", daily: 500 },
  SambaNova: { url: "https://api.sambanova.ai/v1/chat/completions", model: "Meta-Llama-3.3-70B-Instruct", keyUrl: "https://cloud.sambanova.ai", daily: 20 },
};

// Shared keys come from Render's environment, e.g. GROQ_API_KEY, NVIDIA_API_KEY, SAMBANOVA_API_KEY
const envKey = (name) => process.env[name.toUpperCase() + "_API_KEY"];
// Optional override, e.g. SAMBANOVA_DAILY_LIMIT
const dailyCap = (name) => Number(process.env[name.toUpperCase() + "_DAILY_LIMIT"] || PROVIDERS[name].daily);

// Shared daily counters, per provider (reset at midnight UTC)
let shared = { day: "", n: {} };
const today = () => new Date().toISOString().slice(0, 10);
function resetIfNewDay() { if (shared.day !== today()) shared = { day: today(), n: {} }; }
function sharedLeft(name) {
  resetIfNewDay();
  return dailyCap(name) - (shared.n[name] || 0);
}
// True if at least one shared provider still has messages left today
const sharedUsable = () => Object.keys(PROVIDERS).some((n) => envKey(n) && sharedLeft(n) > 0);

// --- per-user storage: one encrypted file per access key (the key itself is never stored) ---
const sha = (s) => crypto.createHash("sha256").update(s).digest();
const fileOf = (t) => path.join(DIR, sha("id:" + t).toString("hex") + ".bin");
const newUser = () => ({ keys: {}, usage: {}, until: {}, reason: {}, selected: "auto", current: null, hour: { start: 0, n: 0 }, day: { day: "", n: 0 } });

function loadUser(t) {
  try {
    const b = fs.readFileSync(fileOf(t));
    const d = crypto.createDecipheriv("aes-256-gcm", sha("enc:" + t), b.subarray(0, 12));
    d.setAuthTag(b.subarray(12, 28));
    return JSON.parse(Buffer.concat([d.update(b.subarray(28)), d.final()]).toString());
  } catch { return null; }
}
function saveUser(t, u) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", sha("enc:" + t), iv);
  const enc = Buffer.concat([c.update(JSON.stringify(u)), c.final()]);
  fs.writeFileSync(fileOf(t), Buffer.concat([iv, c.getAuthTag(), enc]));
}

// --- model auto-repair: if a provider retires a model, find a working one from its live list ---
const models = {}; // provider -> model found automatically
const modelOf = (name) => models[name] || PROVIDERS[name].model;

function errText(text) {
  try {
    const j = JSON.parse(text);
    const m = j.error?.message || j.message || (Array.isArray(j) ? j[0]?.error?.message : "") || "";
    return String(m).replace(/\s+/g, " ").slice(0, 120);
  } catch { return String(text).replace(/\s+/g, " ").slice(0, 120); }
}

async function discover(name, key) {
  try {
    const res = await fetch(PROVIDERS[name].url.replace("/chat/completions", "/models"), { headers: { Authorization: `Bearer ${key}` }, signal: AbortSignal.timeout(15000) });
    if (!res.ok) return null;
    const j = await res.json();
    let ids = (j.data || j.models || []).map((m) => String(m.id || m.name || "").replace(/^models\//, "")).filter(Boolean);
    ids = ids.filter((id) => !/embed|whisper|tts|guard|vision|image|imagen|rerank|moderation|audio|dall|diffusion|clip|safety|speech|transcri|live|robotics|learnlm|ocr/i.test(id));
    if (name === "OpenRouter") ids = ids.filter((id) => id.endsWith(":free"));
    if (name === "Gemini") ids = ids.filter((id) => id.startsWith("gemini-"));
    const prefer = [/llama.*70b/i, /70b/i, /120b/i, /flash/i, /large|medium/i, /llama|qwen|gemma|mistral|gpt-oss|deepseek|nemotron/i];
    for (const re of prefer) { const hit = ids.find((id) => re.test(id)); if (hit) return hit; }
    return ids[0] || null;
  } catch { return null; }
}

// --- failover logic, per user ---
const usage = (u, n) => (u.usage[n] ||= { ok: 0, fail: 0, tokens: 0, left: null });
const resting = (u, n) => (u.until[n] || 0) > Date.now();
function ordered(u) {
  const have = Object.keys(PROVIDERS).filter((n) => u.keys[n] || envKey(n));
  return have.includes(u.selected) ? [u.selected, ...have.filter((n) => n !== u.selected)] : have;
}
function cooldownFor(res, text) {
  const ra = parseInt(res.headers.get("retry-after"), 10);
  if (!isNaN(ra)) return ra * 1000;
  return /day|daily|quota/i.test(text) ? 3600000 : 60000;
}

async function ask(u, messages) {
  const tried = [];
  for (const name of ordered(u)) {
    if (resting(u, name)) { tried.push(`${name}: resting`); continue; }
    const usingShared = !u.keys[name];
    if (usingShared && sharedLeft(name) <= 0) { tried.push(`${name}: shared daily limit reached`); continue; }
    const p = PROVIDERS[name], s = usage(u, name);
    const key = u.keys[name] || envKey(name);
    let reason = "";
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const res = await fetch(p.url, {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${key}` },
          body: JSON.stringify({ model: modelOf(name), messages }),
          signal: AbortSignal.timeout(45000),
        });
        const text = await res.text();
        if (res.ok) {
          const data = JSON.parse(text), reply = data.choices?.[0]?.message?.content;
          if (reply) {
            if (usingShared) shared.n[name] = (shared.n[name] || 0) + 1;
            s.ok++; s.tokens += data.usage?.total_tokens || 0; u.current = name; u.reason[name] = "";
            const rl = res.headers.get("x-ratelimit-remaining-requests");
            if (rl !== null) s.left = Number(rl);
            return { reply, provider: name, model: modelOf(name), fellBack: u.selected !== "auto" && u.selected !== name, shared: usingShared };
          }
          reason = "empty reply"; u.until[name] = Date.now() + 30000; break;
        }
        // Model retired or renamed? Look up a working one and try once more.
        if (attempt === 0 && (res.status === 404 || res.status === 410 || (res.status === 400 && /model/i.test(text)))) {
          const m = await discover(name, key);
          if (m && m !== modelOf(name)) { models[name] = m; continue; }
        }
        const detail = errText(text);
        reason = `HTTP ${res.status}${detail ? ": " + detail : ""}`;
        if (res.status === 401) u.until[name] = Date.now() + 300000;
        else if (res.status === 404 || res.status === 410) u.until[name] = Date.now() + 300000;
        else if ([402, 403, 429].includes(res.status) || res.status >= 500) u.until[name] = Date.now() + cooldownFor(res, text);
        else u.until[name] = Date.now() + 30000;
        if (res.status === 401) reason = "key rejected. " + detail;
        break;
      } catch (e) { reason = e.message; u.until[name] = Date.now() + 30000; break; }
    }
    s.fail++; u.reason[name] = reason; tried.push(`${name}: ${reason}`);
  }
  const err = new Error(ordered(u).length ? "All providers are resting right now." : "Add at least one free key first.");
  err.tried = tried; throw err;
}

function status(u) {
  const next = ordered(u).find((n) => !resting(u, n));
  const h = u.hour || { start: 0, n: 0 };
  const d = u.day || { day: "", n: 0 };
  const hourUsed = Date.now() - h.start > 3600000 ? 0 : h.n;
  const dayUsed = d.day === today() ? d.n : 0;
  return {
    selected: u.selected, current: u.current, nextUp: next || null,
    limits: { perHour: PER_USER_HOURLY, usedThisHour: hourUsed, perDay: PER_USER_DAILY, usedToday: dayUsed },
    providers: Object.entries(PROVIDERS).map(([name, p]) => {
      const s = usage(u, name);
      return { name, model: modelOf(name), keyUrl: p.keyUrl, hasKey: !!(u.keys[name] || envKey(name)), own: !!u.keys[name], coolingDown: resting(u, name),
        resumesInSec: Math.max(0, Math.ceil(((u.until[name] || 0) - Date.now()) / 1000)), reason: u.reason[name] || "",
        requests: s.ok, errors: s.fail, tokens: s.tokens, left: s.left,
        sharedLeftToday: envKey(name) ? Math.max(0, sharedLeft(name)) : null }; // provider keys are never sent back
    }),
  };
}

const signups = {}; // simple per-network limit on new keys
const send = (res, code, obj) => { res.writeHead(code, { "Content-Type": "application/json" }); res.end(JSON.stringify(obj)); };

http.createServer(async (req, res) => {
  if (!req.url.startsWith("/api/")) {
    return fs.readFile(path.join(__dirname, "index.html"), (err, data) => {
      if (err) { res.writeHead(404); return res.end("Not found"); }
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" }); res.end(data);
    });
  }
  let raw = "";
  for await (const c of req) { raw += c; if (raw.length > 1e6) return send(res, 413, { error: "too large" }); }
  let body = {}; try { body = raw ? JSON.parse(raw) : {}; } catch { return send(res, 400, { error: "bad request" }); }

  if (req.url === "/api/signup" && req.method === "POST") {
    const ip = String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();
    const hits = (signups[ip] || []).filter((t) => Date.now() - t < 3600000);
    if (hits.length >= 10) return send(res, 429, { error: "Too many new keys from your network. Try again in an hour." });
    signups[ip] = [...hits, Date.now()];
    const token = "fa-" + crypto.randomBytes(18).toString("base64url");
    saveUser(token, newUser());
    return send(res, 200, { token });
  }
  const token = req.headers["x-access-key"] || "";
  const u = token ? loadUser(token) : null;
  if (!u) return send(res, 401, { error: "Key not recognized" });

  if (req.url === "/api/status") return send(res, 200, status(u));
  if (req.url === "/api/key" && PROVIDERS[body.provider]) {
    if (body.key) { u.keys[body.provider] = String(body.key).trim(); delete u.until[body.provider]; u.reason[body.provider] = ""; }
    else { delete u.keys[body.provider]; if (u.selected === body.provider) u.selected = "auto"; }
    saveUser(token, u); return send(res, 200, status(u));
  }
  if (req.url === "/api/select") {
    if (body.provider === "auto" || u.keys[body.provider] || envKey(body.provider)) u.selected = body.provider;
    saveUser(token, u); return send(res, 200, status(u));
  }
  if (req.url === "/api/chat" && Array.isArray(body.messages)) {
    const hasOwn = Object.values(u.keys).some(Boolean);
    if (!hasOwn && !sharedUsable()) return send(res, 503, { error: "Today's shared free limit is used up on every provider. It resets at midnight UTC. You can also add your own free key." });

    const h = (u.hour ||= { start: 0, n: 0 });
    if (Date.now() - h.start > 3600000) { h.start = Date.now(); h.n = 0; }
    if (!hasOwn && h.n >= PER_USER_HOURLY) {
      const mins = Math.ceil((h.start + 3600000 - Date.now()) / 60000);
      return send(res, 429, { error: `You've used your ${PER_USER_HOURLY} messages for this hour. Try again in ${mins} min, or add your own free key.` });
    }

    const d = (u.day ||= { day: today(), n: 0 });
    if (d.day !== today()) { d.day = today(); d.n = 0; }
    if (!hasOwn && d.n >= PER_USER_DAILY) {
      return send(res, 429, { error: `You've used your ${PER_USER_DAILY} free messages for today. They reset at midnight UTC, or add your own free key.` });
    }

    h.n++;
    try {
      const out = await ask(u, body.messages);
      if (!hasOwn) d.n++;
      saveUser(token, u);
      return send(res, 200, out);
    } catch (e) { saveUser(token, u); return send(res, 503, { error: e.message, tried: e.tried || [] }); }
  }
  send(res, 404, { error: "not found" });
}).listen(process.env.PORT || 3000, () => console.log(`AI Relay on http://localhost:${process.env.PORT || 3000}`));
