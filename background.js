// background.js

const CACHE_PREFIX = 'vtcache:';
const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24h cache for resolved verdicts
const ERROR_CACHE_TTL_MS = 5 * 60 * 1000; // 5min cache for transient errors (rate limits, timeouts)
const POLL_INTERVAL_MS = 1500; // poll VT analysis
const MAX_POLL_ATTEMPTS = 10;
const PRUNE_PROBABILITY = 0.05; // opportunistically prune expired cache entries on ~5% of writes

// Dedup concurrent checks for the same URL within this service worker's lifetime.
const inFlight = new Map();

function cacheKey(url) {
  return CACHE_PREFIX + url;
}

async function getCache(url) {
  return new Promise((res) => {
    chrome.storage.local.get([cacheKey(url)], (items) => {
      const entry = items[cacheKey(url)];
      if (!entry) return res(null);
      if (Date.now() - entry.ts > entry.ttl) return res(null);
      res(entry.result);
    });
  });
}

async function setCache(url, result, ttl) {
  return new Promise((res) => {
    chrome.storage.local.set({[cacheKey(url)]: {ts: Date.now(), ttl, result}}, () => res());
  });
}

async function pruneExpiredCache() {
  return new Promise((res) => {
    chrome.storage.local.get(null, (items) => {
      const now = Date.now();
      const toRemove = Object.entries(items)
        .filter(([key, entry]) => key.startsWith(CACHE_PREFIX) &&
          (!entry || typeof entry.ts !== 'number' || now - entry.ts > (entry.ttl || CACHE_TTL_MS)))
        .map(([key]) => key);
      if (toRemove.length === 0) return res();
      chrome.storage.local.remove(toRemove, () => res());
    });
  });
}

async function maybePruneCache() {
  if (Math.random() < PRUNE_PROBABILITY) {
    await pruneExpiredCache();
  }
}

chrome.runtime.onInstalled.addListener(() => pruneExpiredCache());
chrome.runtime.onStartup.addListener(() => pruneExpiredCache());

// --- Settings: API key + allow/deny domain lists ---

async function getSettings() {
  return new Promise((res) => {
    chrome.storage.sync.get(['vtApiKey', 'allowList', 'denyList'], (items) => {
      res({
        apiKey: items.vtApiKey || null,
        allowList: Array.isArray(items.allowList) ? items.allowList : [],
        denyList: Array.isArray(items.denyList) ? items.denyList : []
      });
    });
  });
}

function hostMatchesList(hostname, list) {
  if (!hostname) return false;
  return list.some((entry) => hostname === entry || hostname.endsWith('.' + entry));
}

// --- Redirect unwrapping (Gmail/Google click-tracking wrappers etc.) ---

const REDIRECT_PARAM_NAMES = ['url', 'u', 'q', 'redirect', 'redirect_uri', 'target', 'dest', 'r'];

function tryDecode(value) {
  try {
    return decodeURIComponent(value);
  } catch (e) {
    return value;
  }
}

const MAX_REDIRECT_HOPS = 3;

// Redirect endpoints that are trusted not to be harmful themselves, so only
// their destination needs checking. Any other URL that carries a URL in a
// query parameter is checked *as well as* its destination: the click navigates
// to the wrapper first, and an attacker can put a harmless-looking destination
// in the parameter of a malicious host (evil.example/?u=https://google.com).
function isTrustedRedirector(parsed) {
  const host = parsed.hostname.replace(/^www\./, '');
  return host === 'google.com' && parsed.pathname === '/url';
}

function innerUrl(parsed) {
  const names = isTrustedRedirector(parsed) ? ['q', 'url'] : REDIRECT_PARAM_NAMES;
  for (const name of names) {
    const value = parsed.searchParams.get(name);
    if (!value) continue;
    const decoded = tryDecode(value);
    if (/^https?:\/\//i.test(decoded)) return decoded;
  }
  return null;
}

// Every URL from the clicked link to its final destination, as
// [{url, trusted}]. `truncated` means the chain went deeper than
// MAX_REDIRECT_HOPS, so the final destination is unknown.
function redirectChain(rawUrl) {
  const chain = [];
  let current = rawUrl;
  for (let hop = 0; ; hop++) {
    let parsed;
    try {
      parsed = new URL(current);
    } catch (e) {
      chain.push({url: current, trusted: false});
      return {chain, truncated: false};
    }

    const inner = innerUrl(parsed);
    const redirects = Boolean(inner) && inner !== current;
    if (redirects && hop === MAX_REDIRECT_HOPS) {
      chain.push({url: current, trusted: false});
      return {chain, truncated: true};
    }
    chain.push({url: current, trusted: redirects && isTrustedRedirector(parsed)});
    if (!redirects) return {chain, truncated: false};
    current = inner;
  }
}

function hostOf(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch (e) {
    return null; // malformed URL; let VirusTotal reject it if we get that far
  }
}

// --- Base64url helper for VirusTotal URL identifiers ---

// VirusTotal's URL id is the unpadded base64url of the URL's UTF-8 bytes.
// btoa() alone throws on characters outside Latin-1.
function toBase64Url(str) {
  let binary = '';
  for (const byte of new TextEncoder().encode(str)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// --- VirusTotal query ---

async function fetchFromVirusTotal(url, apiKey) {
  try {
    const form = new URLSearchParams();
    form.append('url', url);

    const postResp = await fetch('https://www.virustotal.com/api/v3/urls', {
      method: 'POST',
      headers: {'x-apikey': apiKey},
      body: form
    });

    if (!postResp.ok) {
      const retryable = postResp.status === 429 || postResp.status >= 500;
      return {ok: false, error: 'post_failed', status: postResp.status, retryable};
    }

    const postJson = await postResp.json();
    const analysisId = postJson.data && postJson.data.id;
    if (!analysisId) return {ok: false, error: 'no_analysis_id', retryable: false};

    for (let attempts = 0; attempts < MAX_POLL_ATTEMPTS; attempts++) {
      await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));

      const analysisResp = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
        headers: {'x-apikey': apiKey}
      });
      if (!analysisResp.ok) continue;
      const analysisJson = await analysisResp.json();

      const status = analysisJson.data && analysisJson.data.attributes && analysisJson.data.attributes.status;
      if (status === 'completed') {
        const stats = analysisJson.data.attributes.stats || {};
        return {
          ok: true,
          malicious: (stats.malicious || 0) > 0,
          suspicious: (stats.suspicious || 0) > 0,
          maliciousCount: stats.malicious || 0,
          suspiciousCount: stats.suspicious || 0
        };
      }
    }

    // Polling timed out; fall back to the URL object's last known stats.
    const urlId = toBase64Url(url);
    const encodedIdResp = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      headers: {'x-apikey': apiKey}
    });
    if (encodedIdResp.ok) {
      const info = await encodedIdResp.json();
      const stats = (info.data && info.data.attributes && info.data.attributes.last_analysis_stats) || {};
      return {
        ok: true,
        malicious: (stats.malicious || 0) > 0,
        suspicious: (stats.suspicious || 0) > 0,
        maliciousCount: stats.malicious || 0,
        suspiciousCount: stats.suspicious || 0
      };
    }

    return {ok: false, error: 'timeout', retryable: true};
  } catch (e) {
    return {ok: false, error: String(e), retryable: true};
  }
}

// Look up one URL: cache, then in-flight de-dupe, then VirusTotal.
async function scanUrl(url, apiKey) {
  const cached = await getCache(url);
  if (cached) return cached;

  if (inFlight.has(url)) return inFlight.get(url);

  const promise = (async () => {
    const result = await fetchFromVirusTotal(url, apiKey);
    if (result.ok) {
      await setCache(url, result, CACHE_TTL_MS);
    } else if (result.retryable) {
      await setCache(url, result, ERROR_CACHE_TTL_MS);
    }
    await maybePruneCache();
    return result;
  })();

  inFlight.set(url, promise);
  try {
    return await promise;
  } finally {
    inFlight.delete(url);
  }
}

// The verdict for a link is the worst verdict of every URL it passes through
// (except trusted redirectors such as google.com/url). Any lookup error fails
// the whole check, so an unverifiable hop never lets the link count as clean.
async function queryVirusTotal(rawUrl) {
  const {apiKey, allowList, denyList} = await getSettings();

  const {chain, truncated} = redirectChain(rawUrl);
  const resolvedUrl = chain[chain.length - 1].url;
  const hops = chain.filter((hop) => !hop.trusted).map((hop) => ({url: hop.url, host: hostOf(hop.url)}));

  const denied = hops.find((hop) => hostMatchesList(hop.host, denyList));
  if (denied) {
    return {ok: true, malicious: true, suspicious: false, maliciousCount: 0, suspiciousCount: 0,
      listed: 'deny', resolvedUrl, flaggedUrl: denied.url};
  }

  if (truncated) return {ok: false, error: 'too_many_redirects', resolvedUrl};

  const toScan = hops.filter((hop) => !hostMatchesList(hop.host, allowList));
  if (toScan.length === 0) {
    return {ok: true, malicious: false, suspicious: false, maliciousCount: 0, suspiciousCount: 0, listed: 'allow', resolvedUrl};
  }

  if (!apiKey) return {ok: false, error: 'no_api_key', resolvedUrl};

  // Sequential, not parallel: the content script already runs 4 checks at a
  // time, and the free tier allows only 4 requests per minute.
  let worst = null;
  for (const hop of toScan) {
    const result = await scanUrl(hop.url, apiKey);
    if (!result.ok) return {...result, resolvedUrl};
    const rank = result.malicious ? 2 : result.suspicious ? 1 : 0;
    const worstRank = worst ? (worst.malicious ? 2 : worst.suspicious ? 1 : 0) : -1;
    if (rank > worstRank) worst = {...result, flaggedUrl: rank > 0 ? hop.url : undefined};
    if (rank === 2) break; // already as bad as it gets; save the quota
  }
  return {...worst, resolvedUrl};
}

// Listener for messages from content script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message && message.type === 'checkUrl') {
    const url = message.url;
    (async () => {
      const res = await queryVirusTotal(url);
      sendResponse(res);
    })();
    // inform chrome we will send response asynchronously
    return true;
  }
});
