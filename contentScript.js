// contentScript.js

const CHECK_TIMEOUT_MS = 30000; // local fail-safe if the background worker never responds
const SCAN_CONCURRENCY = 4; // parallel VT lookups per scan pass

// Gmail renders each message body in a div with class "a3s". Links are only
// scanned proactively inside message bodies, so Gmail's own interface doesn't
// use up the VirusTotal quota. Click interception still covers every external
// link: if Gmail ever renames this class, links are checked on click instead
// of on load (fail closed, not open).
const MESSAGE_BODY_SELECTOR = '.a3s';

// Dedup concurrent checks for the same href within this tab (shared by
// background auto-scanning and click handling, so a click racing an
// in-progress scan of the same URL awaits the same result instead of
// slipping through unchecked).
const pendingChecks = new Map();

// Verdicts are kept here, in the content script's isolated world, not in DOM
// attributes: email HTML and page scripts can't forge a "clean" verdict, and
// every verdict records the exact href it was for, so a link whose href
// changes after it was checked counts as unchecked again.
// el -> {href, result, flag, checking, originalTitle}
const linkState = new WeakMap();

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

// External http(s) links only. Links back into Gmail itself (same origin) are
// Gmail's own navigation and are neither scanned nor intercepted.
function isExternalHttpLink(a) {
  if (!/^https?:\/\//i.test(a.href)) return false;
  try {
    return new URL(a.href).origin !== location.origin;
  } catch (e) {
    return true; // can't tell: treat as external so it gets checked
  }
}

function stateFor(el) {
  let state = linkState.get(el);
  if (!state) {
    state = {href: null, result: null, flag: null, checking: null, originalTitle: el.title};
    linkState.set(el, state);
  }
  return state;
}

// The stored verdict for this element, only if it is a completed check of
// exactly this href.
function verdictFor(el, href) {
  const state = linkState.get(el);
  return state && state.href === href && state.result && state.result.ok ? state : null;
}

function needsScan(el) {
  const state = linkState.get(el);
  return !state || (state.href !== el.href && state.checking !== el.href);
}

function clearMark(el, state) {
  if (state.flag === 'malicious' || state.flag === 'suspicious') el.style.outline = '';
  el.title = state.originalTitle;
  delete el.dataset.vtFlag;
  state.href = null;
  state.result = null;
  state.flag = null;
}

// Decorate a link DOM element with an indicator based on its verdict for `href`.
function markLink(el, href, result) {
  if (el.href !== href) return; // href changed while checking; the new href gets its own check
  const state = stateFor(el);
  clearMark(el, state);
  state.href = href;
  state.result = result;
  if (!result || !result.ok) return; // leave unflagged so a later click can retry

  const unwrapped = result.resolvedUrl && result.resolvedUrl !== href
    ? ` (resolved to ${result.resolvedUrl})` : '';
  const via = result.flaggedUrl && result.flaggedUrl !== result.resolvedUrl
    ? ` (flagged: ${result.flaggedUrl})` : '';
  const base = state.originalTitle ? state.originalTitle + ' ' : '';

  if (result.malicious) {
    state.flag = 'malicious';
    el.style.outline = '3px solid #d9534f';
    const reason = result.listed === 'deny' ? 'on your blocked list' : 'flagged malicious by VirusTotal';
    el.title = `${base}[${reason}]${unwrapped}${via}`;
  } else if (result.suspicious) {
    state.flag = 'suspicious';
    el.style.outline = '3px solid #f0ad4e';
    el.title = `${base}[Flagged suspicious by VirusTotal]${unwrapped}${via}`;
  } else if (result.listed === 'allow') {
    state.flag = 'allow';
  } else {
    state.flag = 'clean';
  }
  // For DevTools only; never read back (an email could set the same attribute).
  el.dataset.vtFlag = state.flag;
}

function collectLinks(root) {
  const links = root.matches && root.matches('a[href]') ? [root] : [];
  if (root.querySelectorAll) links.push(...root.querySelectorAll('a[href]'));
  return links;
}

// Scan links inside Gmail message bodies, in parallel (bounded by
// SCAN_CONCURRENCY to stay reasonable against VirusTotal's rate limits).
async function scanLinks(root = document) {
  const anchors = collectLinks(root)
    .filter((a) => a.closest(MESSAGE_BODY_SELECTOR) && isExternalHttpLink(a) && needsScan(a));

  if (anchors.length === 0) return;

  let idx = 0;
  async function worker() {
    while (idx < anchors.length) {
      const a = anchors[idx++];
      if (!needsScan(a)) continue;
      const href = a.href;
      const state = stateFor(a);
      state.checking = href;
      try {
        const result = await checkUrlWithBackground(href);
        markLink(a, href, result);
      } catch (e) {
        console.error('VT check failed', e);
      } finally {
        if (state.checking === href) state.checking = null;
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
    const via = result.flaggedUrl && result.flaggedUrl !== href ? `\nFlagged address: ${result.flaggedUrl}` : '';
    const proceed = window.confirm(`This link looks ${level}.\n${source}${via}\n\nDo you really want to proceed to:\n${href}\n?`);
    if (proceed) openLink(href);
    return;
  }

  openLink(href);
}

// Intercept link activation to check/prompt before navigating. Anything not
// verified clean (or allow-listed) for its *current* href is intercepted,
// including links still being auto-scanned in the background, so a click can
// never slip through unchecked. `click` covers left clicks, modifier clicks
// (Ctrl/Cmd/Shift) and Enter; `auxclick` covers the middle button, which
// opens links in a new tab without firing `click`.
async function onLinkActivate(ev) {
  if (ev.type === 'auxclick' && ev.button !== 1) return;
  const a = ev.target && ev.target.closest && ev.target.closest('a[href]');
  if (!a || !isExternalHttpLink(a)) return;
  const href = a.href;

  const verdict = verdictFor(a, href);
  if (verdict && (verdict.flag === 'clean' || verdict.flag === 'allow')) return; // verified safe, allow default navigation

  ev.preventDefault();
  ev.stopImmediatePropagation();

  const result = verdict
    ? verdict.result
    : await checkUrlWithBackground(href).then((r) => { markLink(a, href, r); return r; });

  await handleVerdict(href, result);
}

function interceptClicks() {
  document.addEventListener('click', onLinkActivate, true);
  document.addEventListener('auxclick', onLinkActivate, true);
}

// Observe DOM changes to scan newly loaded message content (Gmail is dynamic),
// and links whose href is changed after they were checked.
function startObserver() {
  const observer = new MutationObserver((mutations) => {
    for (const m of mutations) {
      if (m.type === 'attributes') {
        const state = linkState.get(m.target);
        if (state && state.href && state.href !== m.target.href) clearMark(m.target, state);
        scanLinks(m.target);
        continue;
      }
      m.addedNodes.forEach((node) => {
        if (node.nodeType === 1) scanLinks(node);
      });
    }
  });
  observer.observe(document.body, {childList: true, subtree: true, attributes: true, attributeFilter: ['href']});
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
