// options.js

const DEFAULTS = {scanMode: 'visible', requestsPerMinute: 4, requestsPerDay: 500};
const $ = (id) => document.getElementById(id);

const keyInput = $('key');
const allowListInput = $('allowList');
const denyListInput = $('denyList');
const perMinuteInput = $('requestsPerMinute');
const perDayInput = $('requestsPerDay');

function setStatus(el, text, kind) {
  el.textContent = text;
  el.className = `status ${kind || ''}`;
}

function flash(el, text, kind) {
  setStatus(el, text, kind);
  setTimeout(() => { if (el.textContent === text) setStatus(el, ''); }, 3000);
}

function selectedScanMode() {
  const checked = document.querySelector('input[name="scanMode"]:checked');
  return checked ? checked.value : DEFAULTS.scanMode;
}

function readInt(input, min, max) {
  const n = Number(input.value);
  return Number.isInteger(n) && n >= min && n <= max ? n : null;
}

async function load() {
  const items = await chrome.storage.sync.get(['vtApiKey', 'allowList', 'denyList', 'scanMode', 'requestsPerMinute', 'requestsPerDay']);
  if (items.vtApiKey) keyInput.value = items.vtApiKey;
  if (Array.isArray(items.allowList)) allowListInput.value = items.allowList.join('\n');
  if (Array.isArray(items.denyList)) denyListInput.value = items.denyList.join('\n');
  const mode = ['visible', 'all', 'click'].includes(items.scanMode) ? items.scanMode : DEFAULTS.scanMode;
  document.querySelector(`input[name="scanMode"][value="${mode}"]`).checked = true;
  perMinuteInput.value = items.requestsPerMinute || DEFAULTS.requestsPerMinute;
  perDayInput.value = items.requestsPerDay || DEFAULTS.requestsPerDay;
}

function collectLists(statusEl) {
  const allow = DomainLists.parseDomainList(allowListInput.value);
  const deny = DomainLists.parseDomainList(denyListInput.value);
  const invalid = [...allow.invalid, ...deny.invalid];
  if (invalid.length) {
    setStatus(statusEl, `Not a valid domain: ${invalid.slice(0, 3).join(', ')}${invalid.length > 3 ? '…' : ''}`, 'error');
    return null;
  }
  for (const [name, list] of [['Allowed', allow.domains], ['Blocked', deny.domains]]) {
    if (!DomainLists.fitsSyncStorage(list)) {
      setStatus(statusEl, `${name} domains: the list is too long for Chrome sync storage (about 8 KB).`, 'error');
      return null;
    }
  }
  return {allowList: allow.domains, denyList: deny.domains};
}

async function save() {
  const status = $('status');
  const lists = collectLists(status);
  if (!lists) return;
  const requestsPerMinute = readInt(perMinuteInput, 1, 1000);
  const requestsPerDay = readInt(perDayInput, 1, 10000000);
  if (requestsPerMinute === null || requestsPerDay === null) {
    setStatus(status, 'Requests per minute must be 1–1000 and per day 1–10,000,000.', 'error');
    return;
  }
  try {
    await chrome.storage.sync.set({
      vtApiKey: keyInput.value.trim(), ...lists, scanMode: selectedScanMode(), requestsPerMinute, requestsPerDay
    });
  } catch (e) {
    setStatus(status, `Error: ${e.message || e}`, 'error');
    return;
  }
  // Show the normalized lists, so what you see is what is stored.
  allowListInput.value = lists.allowList.join('\n');
  denyListInput.value = lists.denyList.join('\n');
  flash(status, 'Saved.', 'ok');
}

async function testKey() {
  const status = $('keyStatus');
  setStatus(status, 'Testing…');
  try {
    const result = await chrome.runtime.sendMessage({type: 'testKey', key: keyInput.value.trim()});
    setStatus(status, result ? result.message : 'No answer from the extension.', result && result.ok ? 'ok' : 'error');
  } catch (e) {
    setStatus(status, `Error: ${e.message || e}`, 'error');
  }
}

function exportLists() {
  const lists = collectLists($('listStatus'));
  if (!lists) return;
  const blob = new Blob([DomainLists.exportLists(lists.allowList, lists.denyList)], {type: 'application/json'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'gmail-link-scanner-lists.json';
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function importLists(file) {
  const status = $('listStatus');
  try {
    if (file.size > 100 * 1024) throw new Error('The file is too large.');
    const lists = DomainLists.parseImport(await file.text());
    allowListInput.value = lists.allowList.join('\n');
    denyListInput.value = lists.denyList.join('\n');
    setStatus(status, `Imported ${lists.allowList.length} allowed and ${lists.denyList.length} blocked domains. Click Save to keep them.`, 'ok');
  } catch (e) {
    setStatus(status, `Import failed: ${e.message || e}`, 'error');
  }
}

$('save').addEventListener('click', save);
$('testKey').addEventListener('click', testKey);
$('export').addEventListener('click', exportLists);
$('import').addEventListener('click', () => $('importFile').click());
$('importFile').addEventListener('change', (ev) => {
  const file = ev.target.files && ev.target.files[0];
  if (file) importLists(file);
  ev.target.value = '';
});

load().catch((e) => setStatus($('status'), `Could not load settings: ${e.message || e}`, 'error'));
