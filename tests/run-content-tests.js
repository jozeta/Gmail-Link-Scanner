#!/usr/bin/env node
// Runs tests/content/index.html in a headless Chromium browser (Edge, Chrome or
// Chromium) with a throwaway profile, in real time over the DevTools protocol,
// and prints the results. No dependencies (needs Node 22+ for WebSocket).
// Usage: node tests/run-content-tests.js   (BROWSER=/path/to/browser to override)

const {spawn, execFileSync} = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const PAGE = 'file://' + path.join(__dirname, 'content', 'index.html');
const TIMEOUT_MS = 60000;

function findBrowser() {
  if (process.env.BROWSER) return process.env.BROWSER;
  const candidates = [
    '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Chromium.app/Contents/MacOS/Chromium',
    'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'
  ];
  for (const c of candidates) if (fs.existsSync(c)) return c;
  for (const name of ['microsoft-edge', 'google-chrome', 'chromium', 'chromium-browser']) {
    try {
      return execFileSync('which', [name], {encoding: 'utf8'}).trim();
    } catch (e) { /* not installed */ }
  }
  throw new Error('No Chromium-based browser found; set BROWSER=/path/to/browser');
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  if (typeof WebSocket === 'undefined') throw new Error('Needs Node 22+ (global WebSocket)');
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'gls-test-'));
  const browser = spawn(findBrowser(), [
    '--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
    `--user-data-dir=${profile}`, '--allow-file-access-from-files', '--window-size=1000,700',
    '--remote-debugging-port=0',
    // CI containers on Linux have no user namespaces for Chrome's sandbox.
    ...(process.platform === 'linux' && process.env.CI ? ['--no-sandbox'] : []),
    'about:blank'
  ], {stdio: ['ignore', 'ignore', 'pipe']});
  let browserErr = '';
  browser.stderr.on('data', (d) => { browserErr += d; });

  try {
    // The browser writes its debugging port to DevToolsActivePort.
    const portFile = path.join(profile, 'DevToolsActivePort');
    const started = Date.now();
    while (!fs.existsSync(portFile) || !fs.readFileSync(portFile, 'utf8').includes('\n')) {
      if (Date.now() - started > 30000) throw new Error('Browser did not start:\n' + browserErr.slice(-2000));
      await sleep(100);
    }
    const port = fs.readFileSync(portFile, 'utf8').split('\n')[0].trim();
    const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
    const page = targets.find((t) => t.type === 'page');

    const ws = new WebSocket(page.webSocketDebuggerUrl);
    await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = reject; });
    let seq = 0;
    const waiting = new Map();
    ws.onmessage = (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.id && waiting.has(msg.id)) {
        waiting.get(msg.id)(msg);
        waiting.delete(msg.id);
      }
    };
    const send = (method, params = {}) => new Promise((resolve) => {
      const id = ++seq;
      waiting.set(id, resolve);
      ws.send(JSON.stringify({id, method, params}));
    });

    await send('Page.enable');
    await send('Page.navigate', {url: PAGE});

    let results = null;
    const deadline = Date.now() + TIMEOUT_MS;
    while (Date.now() < deadline) {
      const r = await send('Runtime.evaluate', {
        expression: "document.getElementById('results') && document.getElementById('results').textContent",
        returnByValue: true
      });
      const value = r.result && r.result.result && r.result.result.value;
      if (typeof value === 'string' && value.includes('DONE')) {
        results = value;
        break;
      }
      await sleep(200);
    }
    ws.close();
    if (!results) throw new Error(`Content tests did not finish within ${TIMEOUT_MS / 1000} s`);

    const lines = results.split('\n').filter((l) => l && l !== 'DONE');
    for (const line of lines) console.log(line);
    const failed = lines.filter((l) => l.startsWith('FAIL')).length;
    console.log(`content tests: ${lines.length - failed} passed, ${failed} failed`);
    process.exitCode = failed ? 1 : 0;
  } finally {
    browser.kill();
    await sleep(300);
    fs.rmSync(profile, {recursive: true, force: true});
  }
}

main().catch((e) => {
  console.error(e.message || e);
  process.exitCode = 1;
});
