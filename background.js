// background.js

const CACHE_PREFIX = 'vtcache:';
const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24h cache for resolved verdicts
const ERROR_CACHE_TTL_MS = 5 * 60 * 1000; // 5min cache for transient errors (rate limits, timeouts)
const PRUNE_PROBABILITY = 0.05; // opportunistically prune expired cache entries on ~5% of writes

const VT_API = 'https://www.virustotal.com/api/v3';

// An existing VirusTotal report is reused instead of submitting a new scan when
// it is recent enough. A report that already flags the URL is reused at any age.
const REPORT_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;
// Wait before each poll of a freshly submitted analysis. Every poll costs a
// request, so poll a few times with growing gaps instead of every 1.5 s.
const POLL_DELAYS_MS = [5000, 10000, 15000, 20000];

// Request budget. Defaults match the VirusTotal free tier; premium keys can
// raise them on the options page.
const DEFAULT_REQUESTS_PER_MINUTE = 4;
const DEFAULT_REQUESTS_PER_DAY = 500;
const RATE_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_BACKOFF_MS = 60 * 1000; // pause everything after an unexpected 429
const KEEPALIVE_INTERVAL_MS = 20 * 1000;

// Lower runs first: a click is waiting for the answer, a scan is not.
const PRIORITY = {click: 0, scan: 1};

const QUOTA_KEY = 'vtquota'; // chrome.storage.local: {day, count}
const WINDOW_KEY = 'vtwindow'; // chrome.storage.session: request timestamps of the last minute
const RECENT_KEY = 'vtrecent'; // chrome.storage.session: recent checks, shown in the popup
const RECENT_MAX = 20;

// Tracking parameters removed before a URL is scanned or cached. They don't
// change where a link goes, they split the cache, and some identify the
// recipient, which VirusTotal doesn't need to know.
const TRACKING_PARAMS = /^(utm_.*|fbclid|gclid|dclid|gbraid|wbraid|msclkid|yclid|igshid|mc_cid|mc_eid|_hsenc|_hsmi|mkt_tok)$/i;

// Dedup concurrent checks for the same URL within this service worker's lifetime.
// url -> {job, promise}
const inFlight = new Map();

// --- Cache ---

function cacheKey(url) {
  return CACHE_PREFIX + url;
}

async function getCache(url) {
  const items = await chrome.storage.local.get(cacheKey(url));
  const entry = items[cacheKey(url)];
  if (!entry || Date.now() - entry.ts > entry.ttl) return null;
  return entry.result;
}

async function setCache(url, result, ttl) {
  await chrome.storage.local.set({[cacheKey(url)]: {ts: Date.now(), ttl, result}});
}

async function pruneExpiredCache() {
  const items = await chrome.storage.local.get(null);
  const now = Date.now();
  const toRemove = Object.entries(items)
    .filter(([key, entry]) => key.startsWith(CACHE_PREFIX) &&
      (!entry || typeof entry.ts !== 'number' || now - entry.ts > (entry.ttl || CACHE_TTL_MS)))
    .map(([key]) => key);
  if (toRemove.length) await chrome.storage.local.remove(toRemove);
}

async function clearCache() {
  const items = await chrome.storage.local.get(null);
  const keys = Object.keys(items).filter((key) => key.startsWith(CACHE_PREFIX));
  if (keys.length) await chrome.storage.local.remove(keys);
  await chrome.storage.session.remove(RECENT_KEY);
  return keys.length;
}

async function maybePruneCache() {
  if (Math.random() < PRUNE_PROBABILITY) await pruneExpiredCache();
}

chrome.runtime.onInstalled.addListener(() => { pruneExpiredCache(); });
chrome.runtime.onStartup.addListener(() => { pruneExpiredCache(); });

// --- Settings: API key, allow/deny domain lists, request budget ---

function clampInt(value, min, max, fallback) {
  const n = Number(value);
  return Number.isInteger(n) && n >= min && n <= max ? n : fallback;
}

async function getSettings() {
  const items = await chrome.storage.sync.get(['vtApiKey', 'allowList', 'denyList', 'requestsPerMinute', 'requestsPerDay']);
  const settings = {
    apiKey: items.vtApiKey || null,
    allowList: Array.isArray(items.allowList) ? items.allowList : [],
    denyList: Array.isArray(items.denyList) ? items.denyList : [],
    requestsPerMinute: clampInt(items.requestsPerMinute, 1, 1000, DEFAULT_REQUESTS_PER_MINUTE),
    requestsPerDay: clampInt(items.requestsPerDay, 1, 10000000, DEFAULT_REQUESTS_PER_DAY)
  };
  limits.perMinute = settings.requestsPerMinute;
  limits.perDay = settings.requestsPerDay;
  return settings;
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

// Drop the #fragment and tracking parameters. Other parameters are left
// exactly as they were (no re-encoding) unless something was removed.
function normalizeForScan(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch (e) {
    return url;
  }
  parsed.hash = '';
  const tracking = [...new Set(parsed.searchParams.keys())].filter((name) => TRACKING_PARAMS.test(name));
  for (const name of tracking) parsed.searchParams.delete(name);
  return parsed.href;
}

// --- Base64url helper for VirusTotal URL identifiers ---

// VirusTotal's URL id is the unpadded base64url of the URL's UTF-8 bytes.
// btoa() alone throws on characters outside Latin-1.
function toBase64Url(str) {
  let binary = '';
  for (const byte of new TextEncoder().encode(str)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// --- Rate limiter: one queue for every VirusTotal request ---

const limits = {perMinute: DEFAULT_REQUESTS_PER_MINUTE, perDay: DEFAULT_REQUESTS_PER_DAY};
let windowStamps = []; // request times within the last minute
let quota = {day: '', count: 0}; // requests sent today (UTC, like VirusTotal's daily reset)
let limiterLoad = null;
let pausedUntil = 0;
const waiters = []; // {job, resolve, seq}
let waiterSeq = 0;
let scheduleTimer = null;
let keepAliveTimer = null;

class QuotaExhaustedError extends Error {}

function utcDay(time) {
  return new Date(time).toISOString().slice(0, 10);
}

// The service worker can be stopped and restarted at any time, so the
// limiter's state is persisted: the last minute in session storage, the daily
// count in local storage.
function loadLimiterState() {
  if (!limiterLoad) {
    limiterLoad = Promise.all([
      chrome.storage.session.get(WINDOW_KEY).catch(() => ({})),
      chrome.storage.local.get(QUOTA_KEY).catch(() => ({}))
    ]).then(([session, local]) => {
      if (Array.isArray(session[WINDOW_KEY])) windowStamps = session[WINDOW_KEY].filter((t) => typeof t === 'number');
      const saved = local[QUOTA_KEY];
      if (saved && typeof saved.day === 'string' && typeof saved.count === 'number') quota = saved;
    });
  }
  return limiterLoad;
}

function persistLimiterState() {
  chrome.storage.session.set({[WINDOW_KEY]: windowStamps}).catch(() => {});
  chrome.storage.local.set({[QUOTA_KEY]: quota}).catch(() => {});
}

// Chrome stops an idle service worker after ~30 s. A queued request can wait
// longer than that, so keep the worker alive while there is work.
function updateKeepAlive() {
  const busy = waiters.length > 0 || inFlight.size > 0;
  if (busy && !keepAliveTimer) {
    keepAliveTimer = setInterval(() => chrome.runtime.getPlatformInfo(() => {}), KEEPALIVE_INTERVAL_MS);
  } else if (!busy && keepAliveTimer) {
    clearInterval(keepAliveTimer);
    keepAliveTimer = null;
  }
}

function pickNextWaiter() {
  let best = 0;
  for (let i = 1; i < waiters.length; i++) {
    const a = waiters[i];
    const b = waiters[best];
    if (a.job.priority < b.job.priority || (a.job.priority === b.job.priority && a.seq < b.seq)) best = i;
  }
  return waiters.splice(best, 1)[0];
}

function schedule() {
  clearTimeout(scheduleTimer);
  scheduleTimer = null;
  const now = Date.now();
  windowStamps = windowStamps.filter((t) => now - t < RATE_WINDOW_MS);
  if (quota.day !== utcDay(now)) quota = {day: utcDay(now), count: 0};

  let granted = false;
  while (waiters.length) {
    if (quota.count >= limits.perDay) {
      for (const waiter of waiters.splice(0)) waiter.resolve(false);
      break;
    }
    if (now < pausedUntil || windowStamps.length >= limits.perMinute) break;
    const waiter = pickNextWaiter();
    windowStamps.push(now);
    quota.count++;
    granted = true;
    waiter.resolve(true);
  }
  if (granted) persistLimiterState();
  updateKeepAlive();

  if (waiters.length) {
    const nextSlot = windowStamps.length >= limits.perMinute ? windowStamps[0] + RATE_WINDOW_MS : now;
    scheduleTimer = setTimeout(schedule, Math.max(Math.max(nextSlot, pausedUntil) - now, 50));
  }
}

// Resolves once this request may be sent. Jobs with a lower priority value
// go first, and a job's priority can be raised while it waits (a click on a
// link that is queued for a scan).
async function acquireSlot(job) {
  await loadLimiterState();
  const allowed = await new Promise((resolve) => {
    waiters.push({job, resolve, seq: waiterSeq++});
    schedule();
  });
  if (!allowed) throw new QuotaExhaustedError();
}

async function vtRequest(job, path, init = {}) {
  await acquireSlot(job);
  const resp = await fetch(VT_API + path, {...init, headers: {'x-apikey': job.apiKey}});
  if (resp.status === 429) {
    // Someone else is using the key, or the limits are set too high: back off.
    pausedUntil = Date.now() + RATE_LIMIT_BACKOFF_MS;
    schedule();
  }
  return resp;
}

// --- VirusTotal query ---

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function httpError(error, status) {
  if (status === 401 || status === 403) return {ok: false, error: 'invalid_api_key', status, retryable: false};
  return {ok: false, error, status, retryable: status === 429 || status >= 500};
}

function verdictFromStats(stats, finalUrl) {
  stats = stats || {};
  const result = {
    ok: true,
    malicious: (stats.malicious || 0) > 0,
    suspicious: (stats.suspicious || 0) > 0,
    maliciousCount: stats.malicious || 0,
    suspiciousCount: stats.suspicious || 0
  };
  if (typeof finalUrl === 'string' && /^https?:\/\//i.test(finalUrl)) result.finalUrl = finalUrl;
  return result;
}

function verdictFromReport(report) {
  return verdictFromStats(report.last_analysis_stats, report.last_final_url);
}

function isUsableReport(report) {
  const stats = report.last_analysis_stats;
  if (!stats) return false;
  if ((stats.malicious || 0) > 0 || (stats.suspicious || 0) > 0) return true;
  const analysedAt = (report.last_analysis_date || 0) * 1000;
  return Date.now() - analysedAt <= REPORT_MAX_AGE_MS;
}

// 1. GET the existing report (one request, enough for most URLs).
// 2. Only if VirusTotal has never seen the URL, or its clean report is stale:
//    submit it and poll the analysis.
async function fetchFromVirusTotal(url, job) {
  try {
    const urlId = toBase64Url(url);
    let report = null;
    const reportResp = await vtRequest(job, `/urls/${urlId}`);
    if (reportResp.ok) {
      const json = await reportResp.json();
      report = (json.data && json.data.attributes) || null;
    } else if (reportResp.status !== 404) {
      return httpError('report_failed', reportResp.status);
    }
    if (report && isUsableReport(report)) return verdictFromReport(report);

    const form = new URLSearchParams();
    form.append('url', url);
    const postResp = await vtRequest(job, '/urls', {method: 'POST', body: form});
    if (!postResp.ok) return httpError('post_failed', postResp.status);
    const postJson = await postResp.json();
    const analysisId = postJson.data && postJson.data.id;
    if (!analysisId) return {ok: false, error: 'no_analysis_id', retryable: false};

    for (const delay of POLL_DELAYS_MS) {
      await sleep(delay);
      const analysisResp = await vtRequest(job, `/analyses/${encodeURIComponent(analysisId)}`);
      if (!analysisResp.ok) continue;
      const attributes = (await analysisResp.json()).data?.attributes;
      if (attributes && attributes.status === 'completed') {
        return verdictFromStats(attributes.stats, report && report.last_final_url);
      }
    }

    // The analysis is still running. Use the older report if there was one,
    // otherwise try once more for a report that may have appeared meanwhile.
    if (report && report.last_analysis_stats) return verdictFromReport(report);
    const lateResp = await vtRequest(job, `/urls/${urlId}`);
    if (lateResp.ok) {
      const late = (await lateResp.json()).data?.attributes;
      if (late && late.last_analysis_stats) return verdictFromReport(late);
    }
    return {ok: false, error: 'timeout', retryable: true};
  } catch (e) {
    if (e instanceof QuotaExhaustedError) return {ok: false, error: 'daily_limit', retryable: true};
    return {ok: false, error: String(e), retryable: true};
  }
}

// Look up one URL: cache, then in-flight de-dupe, then VirusTotal.
async function scanUrl(rawUrl, apiKey, priority) {
  const url = normalizeForScan(rawUrl);
  const cached = await getCache(url);
  if (cached) return cached;

  const existing = inFlight.get(url);
  if (existing) {
    existing.job.priority = Math.min(existing.job.priority, priority);
    return existing.promise;
  }

  const job = {priority, apiKey};
  const promise = (async () => {
    const result = await fetchFromVirusTotal(url, job);
    if (result.ok) {
      await setCache(url, result, CACHE_TTL_MS);
    } else if (result.retryable) {
      await setCache(url, result, ERROR_CACHE_TTL_MS);
    }
    await maybePruneCache();
    return result;
  })();

  inFlight.set(url, {job, promise});
  updateKeepAlive();
  try {
    return await promise;
  } finally {
    inFlight.delete(url);
    updateKeepAlive();
  }
}

function rank(result) {
  return result.malicious ? 2 : result.suspicious ? 1 : 0;
}

// The verdict for a link is the worst verdict of every URL it passes through
// (except trusted redirectors such as google.com/url). Any lookup error fails
// the whole check, so an unverifiable hop never lets the link count as clean.
async function queryVirusTotal(rawUrl, priority = PRIORITY.scan) {
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

  // One hop after another: the rate limiter already runs different links in
  // parallel, and this way a malicious first hop saves the rest of the quota.
  let worst = null;
  let finalUrl;
  for (const hop of toScan) {
    const result = await scanUrl(hop.url, apiKey, priority);
    if (!result.ok) return {...result, resolvedUrl};
    if (hop.url === resolvedUrl) finalUrl = result.finalUrl;
    if (!worst || rank(result) > rank(worst)) worst = {...result, flaggedUrl: rank(result) > 0 ? hop.url : undefined};
    if (rank(result) === 2) break; // already as bad as it gets
  }
  const combined = {...worst, resolvedUrl};
  if (finalUrl && finalUrl !== resolvedUrl) combined.finalUrl = finalUrl;
  else delete combined.finalUrl;
  return combined;
}

// --- Recent checks (popup) ---

let recentWrite = Promise.resolve();

function verdictLabel(result) {
  if (!result.ok) return 'error';
  if (result.listed === 'deny') return 'blocked';
  if (result.malicious) return 'malicious';
  if (result.suspicious) return 'suspicious';
  if (result.listed === 'allow') return 'allowed';
  return 'clean';
}

function recordRecent(url, result) {
  recentWrite = recentWrite.then(async () => {
    const items = await chrome.storage.session.get(RECENT_KEY);
    const list = Array.isArray(items[RECENT_KEY]) ? items[RECENT_KEY] : [];
    const entry = {url, verdict: verdictLabel(result), error: result.ok ? undefined : result.error, ts: Date.now()};
    const next = [entry, ...list.filter((item) => item.url !== url)].slice(0, RECENT_MAX);
    await chrome.storage.session.set({[RECENT_KEY]: next});
  }).catch(() => {});
  return recentWrite;
}

async function getStatus() {
  await Promise.all([loadLimiterState(), getSettings()]);
  const now = Date.now();
  const items = await chrome.storage.session.get(RECENT_KEY);
  return {
    usedToday: quota.day === utcDay(now) ? quota.count : 0,
    requestsPerDay: limits.perDay,
    lastMinute: windowStamps.filter((t) => now - t < RATE_WINDOW_MS).length,
    requestsPerMinute: limits.perMinute,
    queued: waiters.length,
    checking: inFlight.size,
    pausedForMs: Math.max(0, pausedUntil - now),
    recent: Array.isArray(items[RECENT_KEY]) ? items[RECENT_KEY] : []
  };
}

// Options page "Test key": any authenticated GET will do. 404 still means the
// key was accepted.
async function testApiKey(apiKey) {
  if (typeof apiKey !== 'string' || !/^[A-Za-z0-9]{16,128}$/.test(apiKey)) {
    return {ok: false, message: 'That does not look like a VirusTotal API key.'};
  }
  try {
    const resp = await vtRequest({priority: PRIORITY.click, apiKey}, `/urls/${toBase64Url('https://www.virustotal.com/')}`);
    if (resp.ok || resp.status === 404) return {ok: true, message: 'The key works.'};
    if (resp.status === 401 || resp.status === 403) return {ok: false, message: 'VirusTotal rejected this key.'};
    if (resp.status === 429) return {ok: true, message: 'The key works, but its rate limit is used up right now.'};
    return {ok: false, message: `VirusTotal answered with HTTP ${resp.status}.`};
  } catch (e) {
    if (e instanceof QuotaExhaustedError) return {ok: false, message: 'The daily request limit set on this page is used up.'};
    return {ok: false, message: `Could not reach VirusTotal (${String(e)}).`};
  }
}

// --- Messages ---

// The popup and the options page. The options page opens in a tab, so
// `sender.tab` alone can't tell it apart from a content script; the sender URL
// can (content scripts report the Gmail page's URL).
function isExtensionPage(sender) {
  return typeof sender.url === 'string' && sender.url.startsWith(chrome.runtime.getURL(''));
}

function isCheckableUrl(url) {
  return typeof url === 'string' && url.length <= 8192 && /^https?:\/\//i.test(url);
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message.type !== 'string' || sender.id !== chrome.runtime.id) return;

  if (message.type === 'checkUrl') {
    if (!isCheckableUrl(message.url)) {
      sendResponse({ok: false, error: 'invalid_url'});
      return;
    }
    const priority = message.priority === 'click' ? PRIORITY.click : PRIORITY.scan;
    (async () => {
      const result = await queryVirusTotal(message.url, priority);
      recordRecent(result.resolvedUrl || message.url, result);
      sendResponse(result);
    })();
    return true; // respond asynchronously
  }

  if (message.type === 'flagCount' && sender.tab) {
    const count = clampInt(message.count, 0, 9999, 0);
    chrome.action.setBadgeBackgroundColor({tabId: sender.tab.id, color: '#d9534f'});
    chrome.action.setBadgeText({tabId: sender.tab.id, text: count ? String(count) : ''});
    return;
  }

  if (message.type === 'openOptions') {
    chrome.runtime.openOptionsPage();
    return;
  }

  // Everything below is only for the popup and the options page.
  if (!isExtensionPage(sender)) return;

  if (message.type === 'getStatus') {
    getStatus().then(sendResponse);
    return true;
  }
  if (message.type === 'clearCache') {
    clearCache().then((removed) => sendResponse({removed}));
    return true;
  }
  if (message.type === 'testKey') {
    testApiKey(message.key).then(sendResponse);
    return true;
  }
});
