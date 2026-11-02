#!/usr/bin/env node
// Loads the real, unpacked extension into a headless Edge/Chromium with a
// throwaway profile and checks that the service worker, options page and popup
// work with the real extension APIs. No API key is set, so nothing is sent to
// VirusTotal. Needs Node 22+ and a browser that still accepts --load-extension
// (Microsoft Edge and Chromium do; recent Google Chrome builds don't).
// Usage: node tests/run-extension-smoke.js   (BROWSER=/path/to/browser to override)

const {spawn} = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const EXTENSION = path.join(__dirname, '..');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const results = [];
const check = (name, cond, detail) => results.push({name, ok: Boolean(cond), detail});

function findBrowser() {
  if (process.env.BROWSER) return process.env.BROWSER;
  const candidates = [
    '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
    '/Applications/Chromium.app/Contents/MacOS/Chromium',
    'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe'
  ];
  const found = candidates.find((c) => fs.existsSync(c));
  if (!found) throw new Error('No Edge/Chromium found; set BROWSER=/path/to/browser');
  return found;
}

async function connect(wsUrl) {
  const ws = new WebSocket(wsUrl);
  await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = reject; });
  let seq = 0;
  const waiting = new Map();
  const events = [];
  ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.id) {
      const resolve = waiting.get(msg.id);
      waiting.delete(msg.id);
      if (resolve) resolve(msg);
    } else {
      events.push(msg);
    }
  };
  const send = (method, params = {}) => new Promise((resolve) => {
    const id = ++seq;
    waiting.set(id, resolve);
    ws.send(JSON.stringify({id, method, params}));
  });
  const evaluate = async (expression) => {
    const r = await send('Runtime.evaluate', {expression, awaitPromise: true, returnByValue: true});
    if (r.result.exceptionDetails) throw new Error(r.result.exceptionDetails.exception?.description || 'evaluate failed');
    return r.result.result.value;
  };
  const errors = () => events
    .filter((e) => e.method === 'Runtime.exceptionThrown' || (e.method === 'Runtime.consoleAPICalled' && e.params.type === 'error'))
    .map((e) => JSON.stringify(e.params).slice(0, 300));
  return {close: () => ws.close(), send, evaluate, errors};
}

async function main() {
  if (typeof WebSocket === 'undefined') throw new Error('Needs Node 22+ (global WebSocket)');
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'gls-smoke-'));
  const browser = spawn(findBrowser(), [
    '--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check', `--user-data-dir=${profile}`,
    `--load-extension=${EXTENSION}`, `--disable-extensions-except=${EXTENSION}`, '--remote-debugging-port=0', 'about:blank'
  ], {stdio: 'ignore'});

  try {
    const portFile = path.join(profile, 'DevToolsActivePort');
    for (let i = 0; i < 150 && !(fs.existsSync(portFile) && fs.readFileSync(portFile, 'utf8').includes('\n')); i++) await sleep(100);
    const port = fs.readFileSync(portFile, 'utf8').split('\n')[0].trim();
    const list = async () => (await fetch(`http://127.0.0.1:${port}/json/list`)).json();

    // Edge runs built-in extensions too; ours is the one with background.js.
    let worker = null;
    for (let i = 0; i < 50 && !worker; i++) {
      worker = (await list()).find((t) => t.type === 'service_worker' && t.url.startsWith('chrome-extension://') && t.url.endsWith('/background.js'));
      if (!worker) await sleep(200);
    }
    check('the extension loads and its service worker starts', worker);
    if (!worker) return;
    const id = new URL(worker.url).host;

    const sw = await connect(worker.webSocketDebuggerUrl);
    await sw.send('Runtime.enable');
    const limiter = await sw.evaluate('loadLimiterState().then(() => ({stamps: windowStamps.length, quota}))');
    check('limiter state loads from storage.session/local', limiter && typeof limiter.quota.count === 'number', limiter);
    const noKey = await sw.evaluate('queryVirusTotal("https://example.com/")');
    check('without an API key a link is not marked clean', noKey.ok === false && noKey.error === 'no_api_key', noKey);
    check('the badge API is available', await sw.evaluate('chrome.action.setBadgeText({text: ""}).then(() => true)'));
    check('the keep-alive API call works', await sw.evaluate('new Promise((r) => chrome.runtime.getPlatformInfo((i) => r(Boolean(i))))'));

    const open = async (page) => {
      const target = await (await fetch(`http://127.0.0.1:${port}/json/new?chrome-extension://${id}/${page}`, {method: 'PUT'})).json();
      const s = await connect(target.webSocketDebuggerUrl);
      await s.send('Runtime.enable');
      await sleep(1200);
      return s;
    };

    const options = await open('options.html');
    check('options page: no errors', options.errors().length === 0, options.errors());
    check('options page: defaults shown', await options.evaluate(
      'document.querySelector("input[name=scanMode]:checked").value + " " + requestsPerMinute.value + "/" + requestsPerDay.value') === 'visible 4/500');
    await options.evaluate('allowList.value = "bad line"; document.getElementById("save").click(); new Promise((r) => setTimeout(r, 300))');
    check('options page: invalid domains are refused', /Not a valid domain/.test(await options.evaluate('document.getElementById("status").textContent')));
    await options.evaluate('allowList.value = "Example.com\\n# note\\nbank.se"; document.querySelector("input[value=all]").checked = true; document.getElementById("save").click(); new Promise((r) => setTimeout(r, 300))');
    const saved = await options.evaluate('chrome.storage.sync.get(["allowList", "scanMode"])');
    check('options page: settings are saved normalized', JSON.stringify(saved) === JSON.stringify({allowList: ['example.com', 'bank.se'], scanMode: 'all'}), saved);
    const testKey = await options.evaluate('chrome.runtime.sendMessage({type: "testKey", key: "nope"})');
    check('options page (in a tab) can use "Test key"', testKey && testKey.ok === false && /does not look like/.test(testKey.message), testKey);
    options.close();

    const popup = await open('popup.html');
    check('popup: no errors', popup.errors().length === 0, popup.errors());
    const text = await popup.evaluate('document.body.innerText');
    check('popup: shows the request budget', /Today: 0 \/ 500/.test(text), text.slice(0, 200));
    check('popup: explains when the tab is not Gmail', /Open Gmail in this tab/.test(text));
    popup.close();
    sw.close();
  } finally {
    browser.kill();
    await sleep(300);
    fs.rmSync(profile, {recursive: true, force: true});
  }
}

main()
  .catch((e) => check(`smoke test ran (${e.message || e})`, false))
  .finally(() => {
    for (const r of results) console.log(`${r.ok ? 'PASS' : 'FAIL'}: ${r.name}${r.ok || r.detail === undefined ? '' : ' ' + JSON.stringify(r.detail)}`);
    const failed = results.filter((r) => !r.ok).length;
    console.log(`extension smoke test: ${results.length - failed} passed, ${failed} failed`);
    process.exitCode = failed ? 1 : 0;
  });
