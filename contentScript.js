// contentScript.js

// Gmail renders each email's content in a div with class "a3s". Only links
// inside it are scanned or intercepted; Gmail's own interface is left alone.
// If Gmail ever renames this class, links stop being checked, so the popup
// warns when an email is open but no message body can be found.
const MESSAGE_BODY_SELECTOR = '.a3s';

const SCAN_TIMEOUT_MS = 15 * 60 * 1000; // fail-safe for queued background scans
const CLICK_TIMEOUT_MS = 3 * 60 * 1000; // fail-safe while the warning panel waits
// Background scans in flight per tab. The background worker's rate limiter
// decides how many actually reach VirusTotal at once.
const SCAN_CONCURRENCY = {visible: 4, all: 16};
const VISIBLE_MARGIN = '300px'; // start scanning a little before a link scrolls into view
const MUTATION_BATCH_MS = 150;
const SCAN_MODES = ['visible', 'all', 'click'];

const settings = {scanMode: 'visible', allowList: []};

// Dedup concurrent checks for the same href and priority within this tab. A
// click always sends its own message, so the background worker can move a
// queued scan of the same URL to the front.
const pendingChecks = new Map();

// Verdicts are kept here, in the content script's isolated world, not in DOM
// attributes: email HTML and page scripts can't forge a "clean" verdict, and
// every verdict records the exact href it was for, so a link whose href
// changes after it was checked counts as unchecked again.
// el -> {href, result, flag, warnings, checking, originalTitle}
const linkState = new WeakMap();
const flaggedLinks = new Set();
let lastBadgeCount = -1;

function checkUrlWithBackground(url, priority = 'scan') {
  const key = `${priority} ${url}`;
  if (pendingChecks.has(key)) return pendingChecks.get(key);
  const timeoutMs = priority === 'click' ? CLICK_TIMEOUT_MS : SCAN_TIMEOUT_MS;

  const promise = new Promise((resolve) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      resolve({ok: false, error: 'timeout_local'});
    }, timeoutMs);

    try {
      chrome.runtime.sendMessage({type: 'checkUrl', url, priority}, (resp) => {
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
    pendingChecks.delete(key);
  });

  pendingChecks.set(key, promise);
  return promise;
}

// --- Which links count ---

// External http(s) links only. Links back into Gmail itself (same origin) are
// Gmail's own navigation.
function isExternalHttpLink(a) {
  if (!/^https?:\/\//i.test(a.href)) return false;
  try {
    return new URL(a.href).origin !== location.origin;
  } catch (e) {
    return true; // can't tell: treat as external so it gets checked
  }
}

function isInMessageBody(el) {
  return Boolean(el.closest(MESSAGE_BODY_SELECTOR));
}

function isCheckableLink(a) {
  return isInMessageBody(a) && isExternalHttpLink(a);
}

function linkText(a) {
  return (a.textContent || '').trim().slice(0, 300);
}

// --- Verdict state ---

function stateFor(el) {
  let state = linkState.get(el);
  if (!state) {
    state = {href: null, result: null, flag: null, warnings: [], checking: null, originalTitle: el.title};
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
  if (state.flag && state.flag !== 'clean' && state.flag !== 'allow') el.style.outline = '';
  el.title = state.originalTitle;
  delete el.dataset.vtFlag;
  state.href = null;
  state.result = null;
  state.flag = null;
  state.warnings = [];
  flaggedLinks.delete(el);
}

function computeWarnings(el, href, result) {
  if (!result || !result.ok || result.listed === 'allow' || result.listed === 'deny') return [];
  try {
    return LinkHeuristics.analyze({
      text: linkText(el), href, resolvedUrl: result.resolvedUrl, finalUrl: result.finalUrl,
      allowList: settings.allowList
    });
  } catch (e) {
    console.error('Gmail Link Scanner: heuristics failed', e);
    return [];
  }
}

function describeTargets(href, result) {
  const lines = [];
  if (result && result.resolvedUrl && result.resolvedUrl !== href) lines.push(['Goes to', result.resolvedUrl]);
  if (result && result.finalUrl) lines.push(['Ends up at', result.finalUrl]);
  if (result && result.flaggedUrl && result.flaggedUrl !== href && result.flaggedUrl !== result.resolvedUrl) {
    lines.push(['Flagged address', result.flaggedUrl]);
  }
  return lines;
}

// Decorate a link DOM element with an indicator based on its verdict for `href`.
function markLink(el, href, result) {
  if (el.href !== href) return; // href changed while checking; the new href gets its own check
  const state = stateFor(el);
  clearMark(el, state);
  state.href = href;
  state.result = result;
  if (!result || !result.ok) return; // leave unflagged so a later click can retry

  state.warnings = computeWarnings(el, href, result);
  let label;
  if (result.malicious) {
    state.flag = 'malicious';
    el.style.outline = '3px solid #d9534f';
    label = result.listed === 'deny' ? 'On your blocked list' : 'Flagged malicious by VirusTotal';
  } else if (result.suspicious) {
    state.flag = 'suspicious';
    el.style.outline = '3px solid #f0ad4e';
    label = 'Flagged suspicious by VirusTotal';
  } else if (state.warnings.length) {
    state.flag = 'misleading';
    el.style.outline = '2px dashed #f0ad4e';
    label = 'May be misleading';
  } else {
    state.flag = result.listed === 'allow' ? 'allow' : 'clean';
  }

  if (label) {
    const parts = [`[${label}]`, ...state.warnings.map((w) => w.message),
      ...describeTargets(href, result).map(([name, url]) => `${name}: ${url}`)];
    el.title = (state.originalTitle ? state.originalTitle + '\n' : '') + parts.join('\n');
    flaggedLinks.add(el);
  }
  // For DevTools only; never read back (an email could set the same attribute).
  el.dataset.vtFlag = state.flag;
  scheduleBadgeUpdate();
}

// --- Badge (flagged links in this tab) ---

let badgeTimer = null;

function refreshFlagged() {
  for (const el of flaggedLinks) if (!el.isConnected) flaggedLinks.delete(el);
  const count = flaggedLinks.size;
  if (count === lastBadgeCount) return;
  lastBadgeCount = count;
  try {
    chrome.runtime.sendMessage({type: 'flagCount', count}, () => void chrome.runtime.lastError);
  } catch (e) {
    // extension reloaded; nothing to update
  }
}

function scheduleBadgeUpdate() {
  if (!badgeTimer) badgeTimer = setTimeout(() => { badgeTimer = null; refreshFlagged(); }, 300);
}

// --- Background scanning ---

const scanQueue = [];
const queuedLinks = new WeakSet();
let activeScans = 0;
let visibilityObserver = null;

function collectLinks(root) {
  const links = root.matches && root.matches('a[href]') ? [root] : [];
  if (root.querySelectorAll) links.push(...root.querySelectorAll('a[href]'));
  return links;
}

function getVisibilityObserver() {
  if (!visibilityObserver) {
    visibilityObserver = new IntersectionObserver((entries) => {
      for (const entry of entries) {
        if (!entry.isIntersecting) continue;
        visibilityObserver.unobserve(entry.target);
        enqueueScan(entry.target);
      }
    }, {rootMargin: VISIBLE_MARGIN});
  }
  return visibilityObserver;
}

// "visible": scan links as they come into view (saves quota on long threads).
// "all": scan every link in the open email right away, in parallel.
// "click": no background scanning; links are checked when clicked.
function registerLinks(root) {
  if (settings.scanMode === 'click') return;
  for (const a of collectLinks(root)) {
    if (!isCheckableLink(a) || !needsScan(a)) continue;
    if (settings.scanMode === 'all') enqueueScan(a);
    else getVisibilityObserver().observe(a);
  }
}

function enqueueScan(a) {
  if (queuedLinks.has(a)) return;
  queuedLinks.add(a);
  scanQueue.push(a);
  pumpScans();
}

function pumpScans() {
  const limit = SCAN_CONCURRENCY[settings.scanMode] || SCAN_CONCURRENCY.visible;
  while (activeScans < limit && scanQueue.length) {
    const a = scanQueue.shift();
    queuedLinks.delete(a);
    if (!a.isConnected || !isCheckableLink(a) || !needsScan(a)) continue;
    activeScans++;
    scanOne(a).finally(() => {
      activeScans--;
      pumpScans();
    });
  }
}

async function scanOne(a) {
  const href = a.href;
  const state = stateFor(a);
  state.checking = href;
  try {
    markLink(a, href, await checkUrlWithBackground(href, 'scan'));
  } catch (e) {
    console.error('Gmail Link Scanner: check failed', e);
  } finally {
    if (state.checking === href) state.checking = null;
  }
}

function onScanModeChanged() {
  scanQueue.length = 0;
  if (visibilityObserver) {
    visibilityObserver.disconnect();
    visibilityObserver = null;
  }
  registerLinks(document);
}

// --- Warning panel (replaces confirm()) ---

// A closed shadow root keeps Gmail's and the email's styles out, and keeps
// page scripts from reading or clicking the panel. Its buttons are real user
// clicks, so window.open() isn't blocked as a popup even after a slow check.
const panel = (() => {
  let host = null;
  let shadow = null;
  let token = 0;
  let onCancel = null;

  const STYLE = `
    :host { all: initial; }
    .backdrop { position: fixed; inset: 0; z-index: 2147483647; display: flex; align-items: center;
      justify-content: center; background: rgba(15, 20, 25, 0.45); padding: 16px;
      font: 14px/1.45 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
    .dialog { --accent: #5b6b7a; box-sizing: border-box; width: min(520px, 100%); max-height: calc(100vh - 32px);
      overflow: auto; background: #fff; color: #1d2329; border-radius: 10px; border-top: 6px solid var(--accent);
      box-shadow: 0 12px 40px rgba(0, 0, 0, 0.3); padding: 20px 22px 18px; }
    .dialog.danger { --accent: #c9302c; }
    .dialog.warn { --accent: #e09a1b; }
    .dialog.ok { --accent: #2e7d32; }
    h2 { margin: 0 0 8px; font-size: 18px; line-height: 1.3; color: var(--accent); }
    .dialog.checking h2 { color: inherit; }
    p { margin: 0 0 8px; }
    ul { margin: 0 0 10px; padding-left: 20px; }
    li { margin-bottom: 4px; }
    dl { margin: 10px 0 0; display: grid; grid-template-columns: max-content 1fr; gap: 4px 10px; font-size: 13px; }
    dt { color: #5b6b7a; }
    dd { margin: 0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; word-break: break-all; }
    .buttons { display: flex; flex-wrap: wrap; gap: 8px; justify-content: flex-end; margin-top: 16px; }
    button { font: inherit; border-radius: 6px; padding: 7px 14px; cursor: pointer; border: 1px solid #b8c2cc;
      background: #f4f6f8; color: inherit; }
    button.primary { background: #1a73e8; border-color: #1a73e8; color: #fff; }
    button.danger { background: transparent; border-color: #c9302c; color: #c9302c; }
    button:focus-visible { outline: 3px solid #8ab4f8; outline-offset: 2px; }
    .spinner { display: inline-block; width: 14px; height: 14px; margin-right: 8px; vertical-align: -2px;
      border: 2px solid #b8c2cc; border-top-color: #1a73e8; border-radius: 50%; animation: spin 0.8s linear infinite; }
    @keyframes spin { to { transform: rotate(360deg); } }
    @media (prefers-color-scheme: dark) {
      .dialog { background: #20262c; color: #e6eaee; }
      dt { color: #9aa7b3; }
      button { background: #2c343c; border-color: #4a5560; }
      button.danger { color: #ff8a80; border-color: #ff8a80; }
      .dialog.danger { --accent: #ff6b63; }
      .dialog.warn { --accent: #ffb74d; }
      .dialog.ok { --accent: #81c784; }
    }
  `;

  function ensureHost() {
    if (host && host.isConnected) return;
    host = document.createElement('div');
    shadow = host.attachShadow({mode: 'closed'});
    // Keep Gmail's keyboard shortcuts and click handlers out of the panel.
    for (const type of ['keydown', 'keyup', 'keypress', 'click', 'mousedown', 'mouseup', 'auxclick']) {
      host.addEventListener(type, (ev) => ev.stopPropagation());
    }
    document.documentElement.appendChild(host);
  }

  function el(tag, attrs = {}, text) {
    const node = document.createElement(tag);
    for (const [name, value] of Object.entries(attrs)) node.setAttribute(name, value);
    if (text !== undefined) node.textContent = text;
    return node;
  }

  // spec: {tone, title, paragraphs[], bullets[], details[[label, value]], buttons[{label, kind, onClick, focus}], onCancel}
  function show(spec) {
    ensureHost();
    token++;
    onCancel = spec.onCancel || null;
    shadow.replaceChildren();
    const style = el('style');
    style.textContent = STYLE;
    const backdrop = el('div', {class: 'backdrop'});
    const dialog = el('div', {class: `dialog ${spec.tone || ''}`, role: 'alertdialog', 'aria-modal': 'true',
      'aria-labelledby': 'gls-title', 'aria-describedby': 'gls-body'});
    const title = el('h2', {id: 'gls-title'});
    if (spec.tone === 'checking') title.appendChild(el('span', {class: 'spinner', 'aria-hidden': 'true'}));
    title.appendChild(document.createTextNode(spec.title));
    const body = el('div', {id: 'gls-body'});
    for (const text of spec.paragraphs || []) body.appendChild(el('p', {}, text));
    if (spec.bullets && spec.bullets.length) {
      const list = el('ul');
      for (const text of spec.bullets) list.appendChild(el('li', {}, text));
      body.appendChild(list);
    }
    if (spec.details && spec.details.length) {
      const dl = el('dl');
      for (const [label, value] of spec.details) {
        dl.appendChild(el('dt', {}, label));
        dl.appendChild(el('dd', {}, value));
      }
      body.appendChild(dl);
    }
    const buttons = el('div', {class: 'buttons'});
    let focusTarget = null;
    for (const b of spec.buttons || []) {
      const button = el('button', {type: 'button', class: b.kind || ''}, b.label);
      button.addEventListener('click', () => b.onClick());
      buttons.appendChild(button);
      if (b.focus) focusTarget = button;
    }
    dialog.append(title, body, buttons);
    backdrop.appendChild(dialog);
    backdrop.addEventListener('click', (ev) => { if (ev.target === backdrop) cancel(); });
    dialog.addEventListener('keydown', (ev) => { if (ev.key === 'Escape') cancel(); });
    shadow.append(style, backdrop);
    (focusTarget || buttons.firstChild || dialog).focus();
    return token;
  }

  function close() {
    token++;
    onCancel = null;
    if (host) host.remove();
    host = null;
    shadow = null;
  }

  function cancel() {
    const callback = onCancel;
    close();
    if (callback) callback();
  }

  return {show, close, cancel, isCurrent: (t) => t === token && Boolean(host)};
})();

function openLink(href) {
  // noopener/noreferrer: never hand a (potentially malicious) destination
  // a reference back to this Gmail tab.
  window.open(href, '_blank', 'noopener,noreferrer');
}

function errorText(result) {
  const error = result && result.error;
  switch (error) {
    case 'no_api_key': return 'No VirusTotal API key is set up, so this link was not checked.';
    case 'invalid_api_key': return 'VirusTotal rejected the API key. Check it on the settings page.';
    case 'daily_limit': return 'The daily VirusTotal request limit is used up. Links can be checked again after midnight UTC.';
    case 'too_many_redirects': return 'The link redirects through more than 3 addresses, so its real destination could not be determined.';
    case 'timeout':
    case 'timeout_local': return 'VirusTotal did not answer in time.';
    default:
      if (result && result.status === 429) return 'VirusTotal\'s rate limit was hit. Try again in a minute.';
      return `The check failed (${error || 'unknown error'}).`;
  }
}

function showChecking(href) {
  return panel.show({
    tone: 'checking',
    title: 'Checking this link…',
    paragraphs: ['Asking VirusTotal before opening it. On a free API key this can take up to a minute when other links are queued.'],
    details: [['Link', href]],
    buttons: [{label: 'Cancel', kind: 'primary', focus: true, onClick: () => panel.cancel()}]
  });
}

function showVerdict(href, result, warnings, {autoOpenIfClean = false} = {}) {
  const details = [['Link', href], ...describeTargets(href, result)];
  const cancel = {label: 'Cancel', kind: 'primary', focus: true, onClick: () => panel.close()};
  const openAnyway = {label: 'Open anyway', kind: 'danger', onClick: () => { panel.close(); openLink(href); }};

  if (!result || !result.ok) {
    const buttons = [openAnyway, cancel];
    if (result && (result.error === 'no_api_key' || result.error === 'invalid_api_key')) {
      buttons.unshift({label: 'Open settings', onClick: () => {
        panel.close();
        chrome.runtime.sendMessage({type: 'openOptions'}, () => void chrome.runtime.lastError);
      }});
    }
    panel.show({tone: 'warn', title: 'This link could not be checked', paragraphs: [errorText(result)], details, buttons});
    return;
  }

  if (result.malicious || result.suspicious) {
    const blocked = result.listed === 'deny';
    panel.show({
      tone: result.malicious ? 'danger' : 'warn',
      title: blocked ? 'This domain is on your blocked list' : result.malicious ? 'Dangerous link' : 'Suspicious link',
      paragraphs: [blocked
        ? 'You added this domain to the blocked list in the extension settings.'
        : `VirusTotal: ${result.maliciousCount || 0} security vendors flag it as malicious, ${result.suspiciousCount || 0} as suspicious.`],
      bullets: warnings.map((w) => w.message),
      details,
      buttons: [openAnyway, cancel]
    });
    return;
  }

  if (warnings.length) {
    panel.show({
      tone: 'warn',
      title: 'This link may be misleading',
      paragraphs: ['VirusTotal has no reports against it, but it looks like a common phishing trick:'],
      bullets: warnings.map((w) => w.message),
      details,
      buttons: [openAnyway, cancel]
    });
    return;
  }

  // Clean. If the click's user activation is still fresh (a quick, cached
  // answer), open straight away; otherwise the browser would block the popup,
  // so ask for one more click.
  if (autoOpenIfClean && navigator.userActivation && navigator.userActivation.isActive) {
    panel.close();
    openLink(href);
    return;
  }
  panel.show({
    tone: 'ok',
    title: 'No problems found',
    paragraphs: [result.listed === 'allow' ? 'This domain is on your allow list.' : 'VirusTotal has no reports against this link.'],
    details,
    buttons: [{label: 'Cancel', onClick: () => panel.close()},
      {label: 'Open link', kind: 'primary', focus: true, onClick: () => { panel.close(); openLink(href); }}]
  });
}

// --- Click interception ---

// Intercept link activation to check before navigating. Anything not verified
// clean (or allow-listed) for its *current* href is intercepted, including
// links still being scanned in the background, so a click can never slip
// through unchecked. `click` covers left clicks, modifier clicks
// (Ctrl/Cmd/Shift) and Enter; `auxclick` covers the middle button, which opens
// links in a new tab without firing `click`.
async function onLinkActivate(ev) {
  if (ev.type === 'auxclick' && ev.button !== 1) return;
  const a = ev.target && ev.target.closest && ev.target.closest('a[href]');
  if (!a || !isCheckableLink(a)) return;
  const href = a.href;

  const verdict = verdictFor(a, href);
  if (verdict && (verdict.flag === 'clean' || verdict.flag === 'allow')) return; // verified safe, allow default navigation

  ev.preventDefault();
  ev.stopImmediatePropagation();

  if (verdict) {
    showVerdict(href, verdict.result, verdict.warnings);
    return;
  }

  const token = showChecking(href);
  const result = await checkUrlWithBackground(href, 'click');
  markLink(a, href, result);
  if (!panel.isCurrent(token)) return; // cancelled, or another link was clicked meanwhile
  showVerdict(href, result, computeWarnings(a, href, result), {autoOpenIfClean: true});
}

function interceptClicks() {
  document.addEventListener('click', onLinkActivate, true);
  document.addEventListener('auxclick', onLinkActivate, true);
}

// --- DOM observation (batched) ---

const pendingRoots = new Set();
let flushTimer = null;

function queueRoot(node) {
  pendingRoots.add(node);
  if (!flushTimer) flushTimer = setTimeout(flushRoots, MUTATION_BATCH_MS);
}

function flushRoots() {
  flushTimer = null;
  const roots = [...pendingRoots];
  pendingRoots.clear();
  for (const root of roots) if (root.isConnected) registerLinks(root);
  refreshFlagged();
}

// Gmail adds many nodes at a time; collect them and scan once per batch.
// Links whose href changes lose their verdict immediately.
function startObserver() {
  const observer = new MutationObserver((mutations) => {
    for (const m of mutations) {
      if (m.type === 'attributes') {
        const state = linkState.get(m.target);
        if (state && state.href && state.href !== m.target.href) clearMark(m.target, state);
        queueRoot(m.target);
        continue;
      }
      m.addedNodes.forEach((node) => {
        if (node.nodeType === 1) queueRoot(node);
      });
      if (m.removedNodes.length && flaggedLinks.size) scheduleBadgeUpdate();
    }
  });
  observer.observe(document.body, {childList: true, subtree: true, attributes: true, attributeFilter: ['href']});
}

// --- Settings ---

function applySettings(items) {
  if ('scanMode' in items) settings.scanMode = SCAN_MODES.includes(items.scanMode) ? items.scanMode : 'visible';
  if ('allowList' in items) settings.allowList = Array.isArray(items.allowList) ? items.allowList : [];
}

async function loadSettings() {
  try {
    applySettings(await chrome.storage.sync.get(['scanMode', 'allowList']));
  } catch (e) {
    console.error('Gmail Link Scanner: could not read settings', e);
  }
}

function watchSettings() {
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== 'sync') return;
    const previousMode = settings.scanMode;
    const updates = {};
    for (const [key, change] of Object.entries(changes)) updates[key] = change.newValue;
    applySettings(updates);
    if (settings.scanMode !== previousMode) onScanModeChanged();
  });
}

// --- Popup ---

// An open conversation has a message id at the end of the URL hash
// (#inbox/FMfcgz...). Used to warn when no message body can be found.
function looksLikeOpenConversation() {
  return /\/[A-Za-z0-9]{16,}$/.test(location.hash);
}

function pageSummary() {
  refreshFlagged();
  return {
    flagged: [...flaggedLinks].slice(0, 50).map((a) => {
      const state = linkState.get(a);
      return {
        href: state.href, flag: state.flag, text: linkText(a).slice(0, 80),
        warnings: state.warnings.map((w) => w.message),
        maliciousCount: state.result.maliciousCount || 0, suspiciousCount: state.result.suspiciousCount || 0
      };
    }),
    messageBodies: document.querySelectorAll(MESSAGE_BODY_SELECTOR).length,
    conversationOpen: looksLikeOpenConversation(),
    scanMode: settings.scanMode,
    queued: scanQueue.length,
    checking: activeScans
  };
}

function listenForPopup() {
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (sender.id !== chrome.runtime.id || !message || message.type !== 'getPageSummary') return;
    sendResponse(pageSummary());
  });
}

// --- Start ---

(function init() {
  try {
    interceptClicks(); // first, so nothing is clickable unchecked while settings load
    listenForPopup();
    watchSettings();
    startObserver();
    loadSettings().then(() => registerLinks(document));
    console.log('Gmail Link Scanner initialised');
  } catch (e) {
    console.error('Gmail Link Scanner: init failed', e);
  }
})();
