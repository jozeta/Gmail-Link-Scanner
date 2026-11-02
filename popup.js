// popup.js — everything shown here is built with textContent; URLs come from
// emails and are untrusted.

const $ = (id) => document.getElementById(id);

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function timeAgo(ts) {
  const s = Math.max(0, Math.round((Date.now() - ts) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  return `${Math.round(s / 3600)} h ago`;
}

const FLAG_LABELS = {malicious: 'malicious', suspicious: 'suspicious', misleading: 'misleading'};
const MODE_LABELS = {visible: 'scanning links as they come into view', all: 'scanning every link at once', click: 'checking links only when clicked'};

function renderStatus(status) {
  $('today').textContent = `Today: ${status.usedToday} / ${status.requestsPerDay}`;
  $('minute').textContent = `This minute: ${status.lastMinute} / ${status.requestsPerMinute}`;
  const share = Math.min(1, status.usedToday / status.requestsPerDay);
  $('meterFill').style.width = `${Math.round(share * 100)}%`;
  $('meter').classList.toggle('high', share >= 0.9);
  const parts = [];
  if (status.checking) parts.push(`${status.checking} link${status.checking === 1 ? '' : 's'} being checked`);
  if (status.queued) parts.push(`${status.queued} request${status.queued === 1 ? '' : 's'} waiting for the rate limit`);
  if (status.pausedForMs) parts.push(`paused ${Math.ceil(status.pausedForMs / 1000)} s after a VirusTotal rate-limit answer`);
  $('queue').textContent = parts.join(' · ') || 'Nothing waiting.';

  const list = $('recent');
  list.replaceChildren();
  if (!status.recent.length) {
    list.appendChild(el('li', 'empty', 'No links checked since the browser started.'));
    return;
  }
  for (const item of status.recent) {
    const li = el('li');
    const line = el('div', 'line');
    line.append(el('span', `pill ${item.verdict}`, item.verdict), el('span', 'url', item.url));
    li.appendChild(line);
    li.appendChild(el('div', 'note', item.error ? `${timeAgo(item.ts)} · ${item.error}` : timeAgo(item.ts)));
    list.appendChild(li);
  }
}

function renderPage(summary) {
  const page = $('page');
  page.replaceChildren();
  page.className = '';
  if (!summary) {
    page.className = 'empty';
    page.textContent = 'Open Gmail in this tab to see the open email\'s links.';
    return;
  }
  if (summary.conversationOpen && summary.messageBodies === 0) {
    page.className = 'alert';
    page.textContent = 'An email seems to be open, but its message body could not be found, so its links are not being checked. Gmail may have changed its layout; please report this.';
    return;
  }
  page.appendChild(el('div', 'note', `Mode: ${MODE_LABELS[summary.scanMode] || summary.scanMode}` +
    (summary.queued ? ` · ${summary.queued} waiting to be scanned` : '')));
  if (!summary.flagged.length) {
    page.appendChild(el('div', 'empty', summary.messageBodies ? 'No flagged links in the open email.' : 'No email is open.'));
    return;
  }
  const list = el('ul');
  for (const item of summary.flagged) {
    const li = el('li');
    const line = el('div', 'line');
    line.append(el('span', `pill ${item.flag}`, FLAG_LABELS[item.flag] || item.flag), el('span', 'text', item.text || '(no text)'));
    li.append(line, el('div', 'url', item.href));
    for (const warning of item.warnings) li.appendChild(el('div', 'note', warning));
    if (item.maliciousCount || item.suspiciousCount) {
      li.appendChild(el('div', 'note', `VirusTotal: ${item.maliciousCount} malicious, ${item.suspiciousCount} suspicious`));
    }
    list.appendChild(li);
  }
  page.appendChild(list);
}

async function refresh() {
  try {
    renderStatus(await chrome.runtime.sendMessage({type: 'getStatus'}));
  } catch (e) {
    $('queue').textContent = `Could not reach the extension: ${e.message || e}`;
  }
  let summary = null;
  try {
    // tabs.query and tabs.sendMessage need no "tabs" permission; the content
    // script only exists (and only answers) on mail.google.com.
    const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
    if (tab) summary = await chrome.tabs.sendMessage(tab.id, {type: 'getPageSummary'});
  } catch (e) {
    summary = null; // not a Gmail tab
  }
  renderPage(summary);
}

$('clearCache').addEventListener('click', async () => {
  const result = await chrome.runtime.sendMessage({type: 'clearCache'});
  $('footerStatus').textContent = `Cleared ${result ? result.removed : 0} cached results.`;
  refresh();
});
$('settings').addEventListener('click', () => chrome.runtime.openOptionsPage());

refresh();
setInterval(refresh, 2000);
