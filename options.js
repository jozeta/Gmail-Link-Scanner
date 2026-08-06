// options.js

const keyInput = document.getElementById('key');
const allowListInput = document.getElementById('allowList');
const denyListInput = document.getElementById('denyList');
const saveButton = document.getElementById('save');
const status = document.getElementById('status');

function parseDomainList(text) {
  return Array.from(new Set(
    text.split('\n')
      .map((line) => line.trim().toLowerCase())
      .filter(Boolean)
      .map((line) => line.replace(/^https?:\/\//, '').replace(/\/.*$/, ''))
  ));
}

chrome.storage.sync.get(['vtApiKey', 'allowList', 'denyList'], (items) => {
  if (items.vtApiKey) keyInput.value = items.vtApiKey;
  if (Array.isArray(items.allowList)) allowListInput.value = items.allowList.join('\n');
  if (Array.isArray(items.denyList)) denyListInput.value = items.denyList.join('\n');
});

saveButton.addEventListener('click', () => {
  const vtApiKey = keyInput.value.trim();
  const allowList = parseDomainList(allowListInput.value);
  const denyList = parseDomainList(denyListInput.value);

  chrome.storage.sync.set({vtApiKey, allowList, denyList}, () => {
    if (chrome.runtime.lastError) {
      status.textContent = `Error: ${chrome.runtime.lastError.message}`;
      status.style.color = '#c62828';
      return;
    }
    status.textContent = 'Saved.';
    status.style.color = '#2e7d32';
    setTimeout(() => { status.textContent = ''; }, 2000);
  });
});
