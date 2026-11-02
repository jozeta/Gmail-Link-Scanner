// Loads background.js into a VM context with a fake `chrome`, a fake clock
// and a fake VirusTotal, so its logic can be tested in plain Node.

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const SOURCE = fs.readFileSync(path.join(__dirname, '..', '..', 'background.js'), 'utf8');
const DAY_MS = 24 * 60 * 60 * 1000;

function fakeStorageArea() {
  const data = {};
  return {
    data,
    async get(keys) {
      if (keys === null || keys === undefined) return {...data};
      const list = Array.isArray(keys) ? keys : [keys];
      return Object.fromEntries(list.filter((k) => k in data).map((k) => [k, structuredClone(data[k])]));
    },
    async set(items) { Object.assign(data, structuredClone(items)); },
    async remove(keys) { for (const k of [].concat(keys)) delete data[k]; }
  };
}

function loadBackground() {
  let clock = Date.UTC(2026, 10, 2, 12, 0, 0);
  let timerSeq = 0;
  const timers = new Map(); // id -> {at, fn, interval}

  class FakeDate extends Date {
    constructor(...args) { super(...(args.length ? args : [clock])); }
    static now() { return clock; }
  }

  const sync = fakeStorageArea();
  const local = fakeStorageArea();
  const session = fakeStorageArea();
  sync.data.vtApiKey = 'k'.repeat(64); // secret-scan:allow (fake test key)

  // VirusTotal fake: `vt.reports[url]` = {stats, date (ms), finalUrl} | 'error';
  // `vt.analysis[url]` = stats returned once the analysis completes;
  // `vt.pendingPolls[url]` = number of polls that still answer "queued".
  const vt = {reports: {}, analysis: {}, pendingPolls: {}, requests: [], status: null};
  const badge = {};

  function reportFor(id) {
    const url = Buffer.from(id, 'base64url').toString('utf8');
    return {url, report: vt.reports[url]};
  }

  async function fakeFetch(url, init = {}) {
    const method = init.method || 'GET';
    const apiPath = url.replace('https://www.virustotal.com/api/v3', '');
    vt.requests.push({method, path: apiPath, at: clock, key: init.headers && init.headers['x-apikey']});
    const json = (body, status = 200) => ({ok: status >= 200 && status < 300, status, json: async () => body});
    if (vt.status) return json({}, vt.status);

    if (method === 'POST' && apiPath === '/urls') {
      const submitted = init.body.get('url');
      if (vt.reports[submitted] === 'error') return json({}, 503);
      return json({data: {id: 'an-' + Buffer.from(submitted).toString('base64url')}});
    }
    if (apiPath.startsWith('/analyses/')) {
      const submitted = Buffer.from(decodeURIComponent(apiPath.slice('/analyses/an-'.length)), 'base64url').toString('utf8');
      if ((vt.pendingPolls[submitted] || 0) > 0) {
        vt.pendingPolls[submitted]--;
        return json({data: {attributes: {status: 'queued'}}});
      }
      return json({data: {attributes: {status: 'completed', stats: vt.analysis[submitted] || {malicious: 0, suspicious: 0}}}});
    }
    if (apiPath.startsWith('/urls/')) {
      const {report} = reportFor(apiPath.slice('/urls/'.length));
      if (report === 'error') return json({}, 503);
      if (!report) return json({error: {code: 'NotFoundError'}}, 404);
      return json({data: {attributes: {
        last_analysis_stats: report.stats,
        last_analysis_date: Math.floor((report.date ?? clock) / 1000),
        last_final_url: report.finalUrl
      }}});
    }
    return json({}, 400);
  }

  let messageListener = null;
  const ctx = {
    console, URL, URLSearchParams, TextEncoder, btoa, structuredClone, Promise, Math, Map, Set, Error,
    Date: FakeDate,
    setTimeout: (fn, ms = 0) => { const id = ++timerSeq; timers.set(id, {at: clock + ms, fn}); return id; },
    clearTimeout: (id) => { timers.delete(id); },
    setInterval: (fn, ms) => { const id = ++timerSeq; timers.set(id, {at: clock + ms, fn, interval: ms}); return id; },
    clearInterval: (id) => { timers.delete(id); },
    fetch: fakeFetch,
    chrome: {
      storage: {sync, local, session},
      runtime: {
        id: 'ext-id',
        getURL: (p) => 'chrome-extension://ext-id/' + p,
        getPlatformInfo: (cb) => cb && cb({}),
        openOptionsPage: () => { badge.optionsOpened = true; },
        onInstalled: {addListener() {}},
        onStartup: {addListener() {}},
        onMessage: {addListener(fn) { messageListener = fn; }}
      },
      action: {
        setBadgeText: ({tabId, text}) => { badge[tabId] = text; },
        setBadgeBackgroundColor: () => {}
      }
    }
  };
  vm.createContext(ctx);
  vm.runInContext(SOURCE, ctx, {filename: 'background.js'});

  // Let pending promise chains run.
  async function settle(rounds = 30) {
    for (let i = 0; i < rounds; i++) await new Promise((r) => setImmediate(r));
  }

  // Move the fake clock forward, firing timers in order.
  async function advance(ms) {
    const target = clock + ms;
    await settle();
    for (;;) {
      let next = null;
      for (const [id, t] of timers) if (t.at <= target && (!next || t.at < next[1].at)) next = [id, t];
      if (!next) break;
      const [id, t] = next;
      clock = Math.max(clock, t.at);
      if (t.interval) t.at = clock + t.interval; else timers.delete(id);
      t.fn();
      await settle();
    }
    clock = target;
    await settle();
  }

  // Runs `fn` while advancing the clock until its promise settles.
  async function run(promise, maxMs = 30 * 60 * 1000) {
    let done = false;
    let value;
    let error;
    promise.then((v) => { done = true; value = v; }, (e) => { done = true; error = e; });
    for (let waited = 0; !done && waited < maxMs; waited += 1000) await advance(1000);
    if (!done) throw new Error('timed out on the fake clock');
    if (error) throw error;
    return value;
  }

  function send(message, sender = {id: 'ext-id', tab: {id: 1}}) {
    return new Promise((resolve) => {
      const async = messageListener(message, sender, resolve);
      if (async !== true) resolve(undefined);
    });
  }

  return {
    ctx, vt, badge, sync, local, session, advance, settle, run, send, DAY_MS,
    now: () => clock,
    query: (url, priority) => ctx.queryVirusTotal(url, priority),
    call: (expr) => vm.runInContext(expr, ctx)
  };
}

module.exports = {loadBackground};
