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

// `model` = first model name to try. If the provider says it isn't available, the app tries the names in `known`
// one at a time, then gives up. `daily` = messages per day on the SHARED key (set in Render as NAME_API_KEY).
// Override in Render with NAME_DAILY_LIMIT, e.g. MISTRAL_DAILY_LIMIT = 0 turns sharing off.
// `paid` = needs billing. Shared use of a paid AI costs you money, so keep its daily number low.
const PROVIDERS = {
  Groq: { url: "https://api.groq.com/openai/v1/chat/completions", listUrl: "https://api.groq.com/openai/v1/models", model: "llama-3.3-70b-versatile", known: ["llama-3.1-8b-instant", "openai/gpt-oss-20b"], keyUrl: "https://console.groq.com/keys", daily: 900, paid: false },
  Cerebras: { url: "https://api.cerebras.ai/v1/chat/completions", listUrl: "https://api.cerebras.ai/v1/models", model: "gpt-oss-120b", known: ["llama3.1-8b", "qwen-3-32b"], keyUrl: "https://cloud.cerebras.ai", daily: 500, paid: false },
  NVIDIA: { url: "https://integrate.api.nvidia.com/v1/chat/completions", listUrl: "https://integrate.api.nvidia.com/v1/models", model: "nvidia/nemotron-3.5-super-vl-120b-a12b", known: [], keyUrl: "https://build.nvidia.com", daily: 500, paid: false },
  Mistral: { url: "https://api.mistral.ai/v1/chat/completions", listUrl: "https://api.mistral.ai/v1/models", model: "mistral-small-latest", known: ["mistral-medium-latest", "open-mistral-nemo"], keyUrl: "https://console.mistral.ai", daily: 200, paid: false },
  OpenRouter: { url: "https://openrouter.ai/api/v1/chat/completions", listUrl: "https://openrouter.ai/api/v1/models", model: "mistralai/mistral-large-4-0", known: ["google/gemma-3-27b-it:free"], keyUrl: "https://openrouter.ai/keys", daily: 45, paid: false },
  Cloudflare: { url: `https://api.cloudflare.com/client/v4/accounts/${process.env.CLOUDFLARE_ACCOUNT_ID || "missing-account-id"}/ai/v1/chat/completions`, listUrl: `https://api.cloudflare.com/client/v4/accounts/${process.env.CLOUDFLARE_ACCOUNT_ID || "missing-account-id"}/ai/models/search`, model: "@cf/openai/gpt-oss-120b", known: ["@cf/deepseek-ai/deepseek-v4-pro-0813", "@cf/openai/gpt-oss-20b"], keyUrl: "https://dash.cloudflare.com/profile/api-tokens", daily: 100, paid: false },
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
const modelFor = (name) => models[name] || PROVIDERS[name
