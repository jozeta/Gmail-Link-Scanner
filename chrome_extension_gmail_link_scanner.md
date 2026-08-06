# Gmail Link Scanner — Chrome Extension

This repository implements a Chrome extension (Manifest V3) that scans links in Gmail, queries VirusTotal for each URL, flags malicious links visually, and prompts the user with a confirmation dialog before navigating to a flagged site.

---

## Files

- `manifest.json`
- `contentScript.js`
- `background.js`
- `options.html`
- `options.js`
- `README.md`

---

## manifest.json

```json
{
  "manifest_version": 3,
  "name": "Gmail Link Scanner (VirusTotal)",
  "version": "1.0",
  "description": "Scans links in Gmail via VirusTotal and warns users before navigating to malicious sites.",
  "permissions": [
    "storage",
    "scripting",
    "activeTab",
    "tabs"
  ],
  "host_permissions": [
    "https://mail.google.com/*",
    "https://www.virustotal.com/*"
  ],
  "background": {
    "service_worker": "background.js"
  },
  "options_page": "options.html",
  "content_scripts": [
    {
      "matches": ["https://mail.google.com/*"],
      "js": ["contentScript.js"],
      "run_at": "document_idle"
    }
  ],
  "icons": {
    "48": "icon48.png",
    "128": "icon128.png"
  }
}
```

---

## contentScript.js

This script runs inside Gmail, finds links, decorates flagged links, and intercepts clicks to show a confirmation dialog when needed.

```javascript
// contentScript.js

const CHECK_TIMEOUT_MS = 30000; // fail-safe

// Helper to send message to background and get response
function checkUrlWithBackground(url) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({type: 'checkUrl', url}, (resp) => {
      if (!resp) return resolve({ok: false});
      resolve(resp);
    });
  });
}

// Decorate a link DOM element with an indicator
function markLink(el, result) {
  el.dataset.vtFlag = result.malicious ? 'malicious' : 'clean';
  if (result.malicious) {
    el.style.outline = '3px solid #d9534f';
    el.title = (el.title || '') + ' [Flagged by Gmail Link Scanner]';
  } else {
    // optional subtle marker for clean
    el.dataset.vtChecked = 'true';
  }
}

// Scan currently visible links inside Gmail message areas
async function scanLinks(root = document) {
  const anchors = Array.from(root.querySelectorAll('a[href]'))
    .filter(a => /^https?:\/\//i.test(a.href));

  for (const a of anchors) {
    if (a.dataset.vtChecked || a.dataset.vtFlag) continue;
    // mark as checking to avoid duplicate queries
    a.dataset.vtChecking = '1';
    try {
      const result = await checkUrlWithBackground(a.href);
      markLink(a, result);
    } catch (e) {
      console.error('VT check failed', e);
    } finally {
      delete a.dataset.vtChecking;
      a.dataset.vtChecked = 'true';
    }
  }
}

// Intercept clicks on links to prompt when flagged
function interceptClicks() {
  document.addEventListener('click', async (ev) => {
    const a = ev.target.closest('a[href]');
    if (!a) return;
    const href = a.href;
    if (!/^https?:\/\//i.test(href)) return;

    // If we already know it's malicious we show prompt
    const flagged = a.dataset.vtFlag === 'malicious';

    if (flagged) {
      ev.preventDefault();
      ev.stopImmediatePropagation();

      const proceed = window.confirm('This link was flagged as malicious by VirusTotal. Do you really want to proceed? Click OK to continue or Cancel to stay here.');
      if (proceed) {
        // Open in new tab to preserve Gmail
        window.open(href, '_blank');
      }
      return;
    }

    // If unknown, check in background before navigating
    if (!a.dataset.vtChecked && !a.dataset.vtChecking) {
      ev.preventDefault();
      ev.stopImmediatePropagation();

      // show a small synchronous prompt while checking
      try {
        const result = await checkUrlWithBackground(href);
        markLink(a, result);

        if (result.malicious) {
          const proceed = window.confirm('This link was flagged as malicious by VirusTotal. Do you really want to proceed? Click OK to continue or Cancel to stay here.');
          if (proceed) window.open(href, '_blank');
        } else {
          // not malicious -> follow default action
          window.open(href, '_blank');
        }
      } catch (e) {
        console.error('Error checking link', e);
        // fallback: let the user proceed
        window.open(href, '_blank');
      }
    }
  }, true);
}

// Observe DOM changes to scan newly loaded message content (Gmail is dynamic)
function startObserver() {
  const observer = new MutationObserver((mutations) => {
    for (const m of mutations) {
      if (m.addedNodes && m.addedNodes.length) {
        m.addedNodes.forEach(node => {
          if (node.nodeType !== 1) return;
          if (node.querySelectorAll) {
            scanLinks(node);
          }
        });
      }
    }
  });
  observer.observe(document.body, {childList: true, subtree: true});
}

// Initial run
(function init() {
  try {
    scanLinks(document);
    interceptClicks();
    startObserver();
    console.log('Gmail Link Scanner initialised');
  } catch (e) {
    console.error('Init failed', e);
  }
})();
```

---

## background.js

This service worker handles VirusTotal queries and caches results in `chrome.storage.local` to avoid repeated lookups. Add your VirusTotal API key in the options page.

```javascript
// background.js

const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24h cache
const POLL_INTERVAL_MS = 1500; // poll VT analysis
const MAX_POLL_ATTEMPTS = 10;

// Utility: simple cache in chrome.storage.local
async function getCache(url) {
  return new Promise((res) => {
    chrome.storage.local.get([url], (items) => {
      const entry = items[url];
      if (!entry) return res(null);
      if (Date.now() - entry.ts > CACHE_TTL_MS) return res(null);
      res(entry.result);
    });
  });
}

async function setCache(url, result) {
  return new Promise((res) => {
    const item = {};
    item[url] = {ts: Date.now(), result};
    chrome.storage.local.set(item, () => res());
  });
}

// Fetch stored API key from storage
async function getApiKey() {
  return new Promise((res) => {
    chrome.storage.sync.get(['vtApiKey'], (items) => {
      res(items.vtApiKey || null);
    });
  });
}

// Main VirusTotal check flow
async function queryVirusTotal(url) {
  const apiKey = await getApiKey();
  if (!apiKey) return {ok: false, error: 'no_api_key'};

  // First try cache
  const cached = await getCache(url);
  if (cached) return cached;

  try {
    // 1) POST the URL to /api/v3/urls to request an analysis
    const form = new URLSearchParams();
    form.append('url', url);

    const postResp = await fetch('https://www.virustotal.com/api/v3/urls', {
      method: 'POST',
      headers: { 'x-apikey': apiKey },
      body: form
    });

    if (!postResp.ok) {
      const txt = await postResp.text();
      return {ok: false, error: 'post_failed', status: postResp.status, text: txt};
    }

    const postJson = await postResp.json();
    const analysisId = postJson.data && postJson.data.id;
    if (!analysisId) return {ok: false, error: 'no_analysis_id'};

    // 2) Poll the analysis endpoint until completed or timeout
    let attempts = 0;
    while (attempts < MAX_POLL_ATTEMPTS) {
      attempts++;
      await new Promise(r => setTimeout(r, POLL_INTERVAL_MS));

      const analysisResp = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
        headers: { 'x-apikey': apiKey }
      });
      if (!analysisResp.ok) continue;
      const analysisJson = await analysisResp.json();

      const status = analysisJson.data && analysisJson.data.attributes && analysisJson.data.attributes.status;
      if (status === 'completed') {
        // Determine maliciousness. VirusTotal provides stats per engine.
        const stats = analysisJson.data.attributes.stats || {};
        const maliciousCount = stats.malicious || 0;
        const suspiciousCount = stats.suspicious || 0;
        const result = { ok: true, malicious: (maliciousCount > 0), suspicious: (suspiciousCount > 0), raw: analysisJson };
        await setCache(url, result);
        return result;
      }
    }

    // If polling expired, try to fetch URL object and use last_analysis_stats
    const encodedIdResp = await fetch('https://www.virustotal.com/api/v3/urls/' + encodeURIComponent(btoa(url)), {
      headers: { 'x-apikey': apiKey }
    });
    if (encodedIdResp.ok) {
      const info = await encodedIdResp.json();
      const stats = info.data && info.data.attributes && info.data.attributes.last_analysis_stats;
      const maliciousCount = stats ? (stats.malicious || 0) : 0;
      const result = { ok: true, malicious: (maliciousCount > 0), suspicious: false, raw: info };
      await setCache(url, result);
      return result;
    }

    return {ok: false, error: 'timeout'};
  } catch (e) {
    return {ok: false, error: String(e)};
  }
}

// Listener for messages from content script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message && message.type === 'checkUrl') {
    const url = message.url;
    // run async and respond once ready
    (async () => {
      const res = await queryVirusTotal(url);
      sendResponse(res);
    })();
    // inform chrome we will send response asynchronously
    return true;
  }
});
```

> Note: The `btoa(url)` approach for the `/api/v3/urls/{id}` call is a common pattern where VirusTotal expects the URL to be base64 encoded without padding. The code uses `btoa` for simplicity. If you encounter errors use a base64url function (replace `+`/`/` with `-`/`_` and remove `=` padding).

---

## options.html

A minimal page for storing the VirusTotal API key.

```html
<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Gmail Link Scanner — Options</title>
  </head>
  <body>
    <h2>VirusTotal API key</h2>
    <p>Enter your VirusTotal API key. This will be stored in Chrome Sync storage.</p>
    <input id="key" type="password" placeholder="VT API key" style="width: 420px" />
    <button id="save">Save</button>
    <script src="options.js"></script>
  </body>
</html>
```

## options.js

```javascript
// options.js

const input = document.getElementById('key');
const save = document.getElementById('save');

// load
chrome.storage.sync.get(['vtApiKey'], (items) => {
  if (items.vtApiKey) input.value = items.vtApiKey;
});

save.addEventListener('click', () => {
  const key = input.value.trim();
  chrome.storage.sync.set({vtApiKey: key}, () => {
    alert('Saved');
  });
});
```

---

## README.md

```markdown
# Gmail Link Scanner (VirusTotal)

Install steps:
1. Open `chrome://extensions` in Chrome.
2. Enable "Developer mode".
3. Click "Load unpacked" and select the folder with these files.
4. Open the extension Options and paste your VirusTotal API key.

Notes and caveats:
- You must have a valid VirusTotal API key. Free tier has rate limits. Use caching to reduce API calls.
- The extension polls the VT analysis endpoint. For high throughput or production use implement a server-side proxy to avoid exposing API keys and to handle rate limits.
- Base64 handling: VirusTotal expects a specific base64url form for some endpoints. If results seem wrong adjust the encoding logic.

Security and privacy:
- URLs scanned are sent to VirusTotal. Do not enable on highly sensitive mailboxes without consent.
- The API key is stored in Chrome Sync storage.
```

---

## Final notes

- The code is intentionally minimal and synchronous in parts to keep behavior predictable.
- For production use consider: server-side proxy, exponential backoff, better UI for warnings, and a more robust base64url encoding for URL ids.


