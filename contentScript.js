// contentScript.js

const CHECK_TIMEOUT_MS = 30000; // local fail-safe if the background worker never responds
const SCAN_CONCURRENCY = 4; // parallel VT lookups per scan pass

// Dedup concurrent checks for the same href within this tab (shared by
// background auto-scanning and click handling, so a click racing an
// in-progress scan of the same URL awaits the same result instead of
// slipping through unchecked).
const pendingChecks = new Map();

function checkUrlWithBackground(url) {
  if (pendingChecks.has(url)) return pendingChecks.get(url);

  const promise = new Promise((resolve) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      resolve({ok: false, error: 'timeout_local'});
    }, CHECK_TIMEOUT_MS);

    try {
      chrome.runtime.sendMessage({type: 'checkUrl', url}, (resp) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (chrome.runtime.lastError) {
          resolve({ok: false, error: chrome.runtime.lastError.message});
          return;
        }
        resolve(resp || {ok: false, error: 'no_response'});
      });
    } catch (e) {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        resolve({ok: false, error: String(e)});
      }
    }
  }).finally(() => {
    pendingChecks.delete(url);
  });

  pendingChecks.set(url, promise);
  return promise;
}

// Decorate a link DOM element with an indicator based on its verdict
function markLink(el, result) {
  el.vtResult = result;
  if (!result || !result.ok) return; // leave unflagged so a later click can retry

  const unwrapped = result.resolvedUrl && result.resolvedUrl !== el.href
    ? ` (resolved to ${result.resolvedUrl})` : '';

  if (result.malicious) {
    el.dataset.vtFlag = 'malicious';
    el.style.outline = '3px solid #d9534f';
    const reason = result.listed === 'deny' ? 'on your blocked list' : 'flagged malicious by VirusTotal';
    el.title = `${el.title ? el.title + ' ' : ''}[${reason}]${unwrapped}`;
  } else if (result.suspicious) {
    el.dataset.vtFlag = 'suspicious';
    el.style.outline = '3px solid #f0ad4e';
    el.title = `${el.title ? el.title + ' ' : ''}[Flagged suspicious by VirusTotal]${unwrapped}`;
  } else if (result.listed === 'allow') {
    el.dataset.vtFlag = 'allow';
  } else {
    el.dataset.vtFlag = 'clean';
  }
}

// Scan currently visible links inside Gmail message areas, in parallel
// (bounded by SCAN_CONCURRENCY to stay reasonable against VirusTotal's
// rate limits).
async function scanLinks(root = document) {
  const anchors = Array.from(root.querySelectorAll('a[href]'))
    .filter((a) => /^https?:\/\//i.test(a.href) && !a.dataset.vtChecked && !a.dataset.vtChecking && !a.dataset.vtFlag);

  if (anchors.length === 0) return;

  let idx = 0;
  async function worker() {
    while (idx < anchors.length) {
      const a = anchors[idx++];
      if (a.dataset.vtChecked || a.dataset.vtFlag || a.dataset.vtChecking) continue;
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

  const workerCount = Math.min(SCAN_CONCURRENCY, anchors.length);
  await Promise.all(Array.from({length: workerCount}, worker));
}

function openLink(href) {
  // noopener/noreferrer: never hand a (potentially malicious) destination
  // a reference back to this Gmail tab.
  window.open(href, '_blank', 'noopener,noreferrer');
}

async function handleVerdict(href, result) {
  if (!result || !result.ok) {
    const message = result && result.error === 'no_api_key'
      ? 'Gmail Link Scanner has no VirusTotal API key configured, so this link has not been checked.'
      : `Gmail Link Scanner could not verify this link (${(result && result.error) || 'unknown error'}).`;
    const proceed = window.confirm(`${message}\n\nProceed to:\n${href}\n?`);
    if (proceed) openLink(href);
    return;
  }

  if (result.malicious || result.suspicious) {
    const level = result.malicious ? 'MALICIOUS' : 'suspicious';
    const source = result.listed === 'deny'
      ? 'This domain is on your blocked list.'
      : `Flagged by VirusTotal (${result.maliciousCount || 0} malicious / ${result.suspiciousCount || 0} suspicious engine reports).`;
    const proceed = window.confirm(`This link looks ${level}.\n${source}\n\nDo you really want to proceed to:\n${href}\n?`);
    if (proceed) openLink(href);
    return;
  }

  openLink(href);
}

// Intercept clicks on links to check/prompt before navigating.
// Anything not already known-clean (or allow-listed) is intercepted,
// including links still being auto-scanned in the background, so a click
// can never slip through unchecked.
function interceptClicks() {
  document.addEventListener('click', async (ev) => {
    const a = ev.target.closest('a[href]');
    if (!a) return;
    const href = a.href;
    if (!/^https?:\/\//i.test(href)) return;

    const flag = a.dataset.vtFlag;
    if (flag === 'clean' || flag === 'allow') return; // verified safe, allow default navigation

    ev.preventDefault();
    ev.stopImmediatePropagation();

    const result = (flag === 'malicious' || flag === 'suspicious') && a.vtResult
      ? a.vtResult
      : await checkUrlWithBackground(href).then((r) => { markLink(a, r); return r; });

    await handleVerdict(href, result);
  }, true);
}

// Observe DOM changes to scan newly loaded message content (Gmail is dynamic)
function startObserver() {
  const observer = new MutationObserver((mutations) => {
    for (const m of mutations) {
      if (m.addedNodes && m.addedNodes.length) {
        m.addedNodes.forEach((node) => {
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
