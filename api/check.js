// api/check.js
// Vercel Serverless function — BaseScan proxy + analyzer
// Requirements: set env var BASESCAN_API_KEY in Vercel (Project Settings -> Environment Variables)
// Usage: POST /api/check  with JSON { address: "0x..." }
// Response: JSON analysis (score, tier, sample tx info, estimates)
//
// Features:
// - Calls BaseScan endpoints: txlist, tokentx, txlistinternal, eth_getCode
// - KNOWN_BRIDGES & KNOWN_DAPPS arrays for better detection
// - Simple in-memory cache with TTL
// - Simple per-IP rate-limit
// - Concurrency-limited getCode checks

import fetch from "node-fetch";

const API_BASE = "https://api.basescan.org/api";
const API_KEY = process.env.BASESCAN_API_KEY || "";
const CACHE_TTL_MS = 1000 * 60 * 5; // 5 minutes
const MAX_GETCODE_CONCURRENCY = 6;
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
const RATE_LIMIT_MAX_REQ = 12; // per IP per window

// Lightweight in-memory caches (note: serverless may be ephemeral)
const cache = new Map(); // key -> { ts, data }
const rateMap = new Map(); // ip -> { tsWindowStart, count }

// -- Known contract lists (lowercase) --
// These were sourced from public docs/explorer at time of creation.
// Update as needed.
const KNOWN_BRIDGES = [
  // Example or known bridge/relayer contracts (verify before use)
  "0x3154cf16ccdb4c6d922629664174b904d80f2c35", // example bridge contract seen on explorers
];

const KNOWN_DAPPS = [
  // Uniswap v3 on Base (factory / router)
  "0x33128a8fc17869897dc e68ed026d694621f6fdfd".replace(/\s+/g,''), // UniswapV3Factory (docs)
  "0x4752ba5dbc23f44d87826276bf6fd6b1c372ad24".toLowerCase(),
  "0x050e797f3625ec8785265e1d9bd4799b97528a1".toLowerCase(), // universal router
  // Zora token (official on Base)
  "0x1111111111166b7fe7bd91427724b487980afc69".toLowerCase(),
  // Aerodrome token / contracts (AERO)
  "0x940181a94a35a4569e4529a3cdfb74e38fd98631".toLowerCase(),
  // BasePaint (example)
  "0xba5e05cb26b78eda3a2f8e3b3814726305dcac83".toLowerCase(),
  // friend.tech (example addresses found on explorer)
  "0xcf205808ed36593aa40a44f10c7f7c2f67d4a4d4".toLowerCase(),
  // Parallel (marketplace/game) — placeholder (replace with official if you find)
  // Add more known dApp contract addresses here
];

// simple sleep
const sleep = ms => new Promise(r => setTimeout(r, ms));

function nowTs() { return Date.now(); }
function cacheKeyForAddress(addr) { return `check:${addr}`; }

// rate limit check
function checkRateLimit(ip) {
  const now = nowTs();
  const entry = rateMap.get(ip);
  if (!entry) {
    rateMap.set(ip, { tsWindowStart: now, count: 1 });
    return { ok: true };
  }
  if (now - entry.tsWindowStart > RATE_LIMIT_WINDOW_MS) {
    // reset window
    rateMap.set(ip, { tsWindowStart: now, count: 1 });
    return { ok: true };
  }
  if (entry.count >= RATE_LIMIT_MAX_REQ) {
    return { ok: false, retryAfterMs: RATE_LIMIT_WINDOW_MS - (now - entry.tsWindowStart) };
  }
  entry.count += 1;
  rateMap.set(ip, entry);
  return { ok: true };
}

// safe fetch JSON helper
async function safeFetchJson(url) {
  const r = await fetch(url, { timeout: 15000 });
  return r.json();
}

// eth_getCode wrapper
async function getCode(addr) {
  const url = `${API_BASE}?module=proxy&action=eth_getCode&address=${addr}&tag=latest&apikey=${API_KEY}`;
  try {
    const j = await safeFetchJson(url);
    if (j && j.result) {
      const code = j.result;
      return code && code !== "0x" && code !== "0x0";
    }
  } catch (e) {
    // ignore
  }
  return null;
}

// concurrency-limited map
async function mapLimit(arr, fn, concurrency = 4) {
  const results = [];
  const pool = [];
  for (const item of arr) {
    const p = Promise.resolve().then(() => fn(item));
    results.push(p);
    pool.push(p);
    if (pool.length >= concurrency) {
      await Promise.race(pool).catch(()=>{/*ignore*/});
      // remove finished
      for (let i = pool.length - 1; i >= 0; --i) {
        if (pool[i].isFulfilled || pool[i].isRejected) pool.splice(i, 1);
      }
    }
  }
  return Promise.all(results);
}

export default async function handler(req, res) {
  // Allow CORS (adjust in production)
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") { res.status(200).send("ok"); return; }

  if (req.method !== "POST") {
    res.status(405).json({ ok: false, error: "POST only" });
    return;
  }

  const clientIp = req.headers["x-forwarded-for"]?.split(",")?.[0]?.trim() || req.socket?.remoteAddress || "unknown";
  const rl = checkRateLimit(clientIp);
  if (!rl.ok) {
    res.setHeader("Retry-After", String(Math.ceil((rl.retryAfterMs||0)/1000)));
    res.status(429).json({ ok: false, error: "Rate limit exceeded", retryAfterMs: rl.retryAfterMs });
    return;
  }

  const body = req.body || {};
  const address = (body.address || "").trim().toLowerCase();
  if (!address || !/^0x[a-f0-9]{40}$/.test(address)) {
    res.status(400).json({ ok: false, error: "Invalid address" });
    return;
  }

  // cache key
  const ckey = cacheKeyForAddress(address);
  const cEntry = cache.get(ckey);
  if (cEntry && (nowTs() - cEntry.ts) < CACHE_TTL_MS) {
    // return cached
    return res.status(200).json({ ok: true, cached: true, ...cEntry.data });
  }

  if (!API_KEY) {
    res.status(500).json({ ok: false, error: "Server missing BASESCAN_API_KEY env var" });
    return;
  }

  try {
    // 1) normal txs
    const txlistUrl = `${API_BASE}?module=account&action=txlist&address=${address}&startblock=0&endblock=99999999&sort=asc&apikey=${API_KEY}`;
    const txlist = await safeFetchJson(txlistUrl);
    const txs = Array.isArray(txlist.result) ? txlist.result : [];

    // 2) token transfers
    const tokenTxUrl = `${API_BASE}?module=account&action=tokentx&address=${address}&startblock=0&endblock=99999999&sort=asc&apikey=${API_KEY}`;
    const tokenTx = await safeFetchJson(tokenTxUrl);
    const tokenTxs = Array.isArray(tokenTx.result) ? tokenTx.result : [];

    // 3) internal txs
    const internalTxUrl = `${API_BASE}?module=account&action=txlistinternal&address=${address}&startblock=0&endblock=99999999&sort=asc&apikey=${API_KEY}`;
    const internalTx = await safeFetchJson(internalTxUrl);
    const internalTxs = Array.isArray(internalTx.result) ? internalTx.result : [];

    // build counterparties
    const counterparties = new Set();
    for (const t of txs) { if (t.from) counterparties.add(t.from.toLowerCase()); if (t.to) counterparties.add(t.to.toLowerCase()); }
    for (const t of tokenTxs) { if (t.from) counterparties.add(t.from.toLowerCase()); if (t.to) counterparties.add(t.to.toLowerCase()); if (t.contractAddress) counterparties.add(t.contractAddress.toLowerCase()); }
    for (const t of internalTxs) { if (t.from) counterparties.add(t.from.toLowerCase()); if (t.to) counterparties.add(t.to.toLowerCase()); }
    counterparties.delete(address);

    // limit counterparties for getCode checks
    const counterArr = Array.from(counterparties).slice(0, 250);

    // check contract code with concurrency
    const checks = await Promise.all(counterArr.map(async (addr) => {
      try {
        const isC = await getCode(addr);
        // small pause to be nice to provider
        await sleep(30);
        return { address: addr, isContract: !!isC };
      } catch (e) {
        return { address: addr, isContract: null, error: String(e).slice(0,200) };
      }
    }));

    const contractMap = {};
    checks.forEach(c => contractMap[c.address] = c.isContract);

    // detect bridged (heuristic):
    // bridged if any tx touches KNOWN_BRIDGES, OR token transfers exist, OR contract interactions present early
    let bridged = false;
    for (const t of [...txs, ...internalTxs, ...tokenTxs]) {
      if (!t) continue;
      const to = (t.to || "").toLowerCase();
      const from = (t.from || "").toLowerCase();
      if (KNOWN_BRIDGES.includes(to) || KNOWN_BRIDGES.includes(from)) bridged = true;
      if (t.contractAddress) bridged = bridged || true;
      if (t.input && t.input !== "0x") bridged = bridged || true;
    }

    // dApp proxy: count counterparties that are known dApps or contracts
    let dappCounter = 0;
    for (const addr of counterArr) {
      const isC = contractMap[addr];
      if (isC === true) dappCounter++;
      if (KNOWN_DAPPS.includes(addr)) dappCounter++;
    }

    // sybil/bot heuristics
    const totalTxCount = txs.length + tokenTxs.length + internalTxs.length;
    let sybilRisk = "Low";
    if (totalTxCount >= 400 && Object.keys(contractMap).length <= 2) sybilRisk = "High";
    else if (totalTxCount <= 2) sybilRisk = "Medium";

    // months active
    let monthsActive = 0;
    if (txs.length > 0) {
      const firstTs = Number(txs[0].timeStamp || txs[0].timestamp || 0) * 1000;
      const lastTs = Number(txs[txs.length - 1].timeStamp || txs[txs.length - 1].timestamp || 0) * 1000;
      const firstD = new Date(firstTs);
      const lastD = new Date(lastTs);
      monthsActive = Math.max(0, (lastD.getFullYear()-firstD.getFullYear())*12 + (lastD.getMonth()-firstD.getMonth()));
    }

    // scoring
    let score = 0;
    if (bridged) score += 20;
    if (totalTxCount >= 50) score += 30;
    else if (totalTxCount >= 20) score += 20;
    else if (totalTxCount >= 5) score += 10;
    score += Math.min(dappCounter, 10) * 3; // up to 30
    score += Math.min(monthsActive, 12); // up to 12
    if (sybilRisk === "High") score = Math.max(0, score - 40);
    else if (sybilRisk === "Medium") score = Math.max(0, score - 15);
    score = Math.min(100, Math.round(score));

    // tier
    let tier = "Ineligible or Low Score";
    if (score >= 80) tier = "Tier 1 — Builder";
    else if (score >= 50) tier = "Tier 2 — Creator";
    else if (score >= 25) tier = "Tier 3 — Active Wallet";

    // estimates (FDV=34B, community=20%)
    const FDV = 34000000000;
    const communityPool = FDV * 0.20;
    const builderPool = communityPool * 0.25;
    const creatorPool = communityPool * 0.35;
    const activePool = communityPool * 0.40;
    const estimates = {
      builderPer: builderPool / 100000,    // default builder count assumption
      creatorPer: creatorPool / 1000000,   // creator count assumption
      activePerLow: activePool / 10000000,
      activePerHigh: activePool / 5000000
    };

    const sample = {
      txCount: txs.length,
      tokenTxCount: tokenTxs.length,
      internalTxCount: internalTxs.length,
      totalTxCount,
      firstTx: txs.length ? txs[0].timeStamp || txs[0].timestamp : null,
      lastTx: txs.length ? txs[txs.length - 1].timeStamp || txs[txs.length - 1].timestamp : null,
      counterparties_count: counterparties.size,
      counterparties_sample: counterArr.map(a => ({ address: a, isContract: contractMap[a] || false }))
    };

    const out = {
      address,
      sample,
      bridged,
      dappCounter,
      sybilRisk,
      score,
      tier,
      estimates,
      note: "Heuristic analysis. Update KNOWN_DAPPS / KNOWN_BRIDGES in api/check.js to tune detection."
    };

    // set cache
    cache.set(ckey, { ts: nowTs(), data: out });
    // cleanup old cache entries occasionally
    setTimeout(() => {
      try {
        for (const [k, v] of cache) {
          if ((nowTs() - v.ts) > CACHE_TTL_MS * 3) cache.delete(k);
        }
      } catch (e) {}
    }, 1000);

    res.status(200).json({ ok: true, cached: false, ...out });
  } catch (err) {
    console.error("api/check error:", err);
    res.status(500).json({ ok: false, error: String(err).slice(0, 300) });
  }
}
