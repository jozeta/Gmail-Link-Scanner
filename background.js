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

function unwrapRedirect(rawUrl, maxHops = 3) {
  let current = rawUrl;
  for (let i = 0; i < maxHops; i++) {
    let parsed;
    try {
      parsed = new URL(current);
    } catch (e) {
      break;
    }

    const host = parsed.hostname.replace(/^www\./, '');
    let inner = null;

    if (host === 'google.com' && parsed.pathname === '/url') {
      inner = parsed.searchParams.get('q') || parsed.searchParams.get('url');
    } else {
      for (const name of REDIRECT_PARAM_NAMES) {
        const value = parsed.searchParams.get(name);
        if (!value) continue;
        const decoded = tryDecode(value);
        if (/^https?:\/\//i.test(decoded)) {
          inner = decoded;
          break;
        }
      }
    }

    if (!inner || inner === current) break;
    current = inner;
  }
  return current;
}

// --- Base64url helper for VirusTotal URL identifiers ---

function toBase64Url(str) {
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
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

async function queryVirusTotal(rawUrl) {
  const {apiKey, allowList, denyList} = await getSettings();

  const resolvedUrl = unwrapRedirect(rawUrl);
  let hostname = null;
  try {
    hostname = new URL(resolvedUrl).hostname.toLowerCase();
  } catch (e) {
    // malformed URL; let VirusTotal reject it below if we get that far
  }

  if (hostMatchesList(hostname, denyList)) {
    return {ok: true, malicious: true, suspicious: false, maliciousCount: 0, suspiciousCount: 0, listed: 'deny', resolvedUrl};
  }
  if (hostMatchesList(hostname, allowList)) {
    return {ok: true, malicious: false, suspicious: false, maliciousCount: 0, suspiciousCount: 0, listed: 'allow', resolvedUrl};
  }

  if (!apiKey) return {ok: false, error: 'no_api_key', resolvedUrl};

  const cached = await getCache(resolvedUrl);
  if (cached) return {...cached, resolvedUrl};

  if (inFlight.has(resolvedUrl)) {
    const result = await inFlight.get(resolvedUrl);
    return {...result, resolvedUrl};
  }

  const promise = (async () => {
    const result = await fetchFromVirusTotal(resolvedUrl, apiKey);
    if (result.ok) {
      await setCache(resolvedUrl, result, CACHE_TTL_MS);
    } else if (result.retryable) {
      await setCache(resolvedUrl, result, ERROR_CACHE_TTL_MS);
    }
    await maybePruneCache();
    return result;
  })();

  inFlight.set(resolvedUrl, promise);
  try {
    const result = await promise;
    return {...result, resolvedUrl};
  } finally {
    inFlight.delete(resolvedUrl);
  }
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
