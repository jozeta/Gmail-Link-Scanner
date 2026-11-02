// Run with: node --test tests/
const test = require('node:test');
const assert = require('node:assert/strict');
const {loadBackground} = require('./helpers/load-background');

const fresh = (bg, stats = {malicious: 0, suspicious: 0}, extra = {}) => ({stats, date: bg.now(), ...extra});
const posts = (bg) => bg.vt.requests.filter((r) => r.method === 'POST');

// --- Redirect chains (the wrapper-hides-destination bypass) ---

test('a malicious wrapper with a clean destination is flagged', async () => {
  const bg = loadBackground();
  const link = 'https://evil.example/?u=https://google.com/';
  bg.vt.reports[link] = fresh(bg, {malicious: 5});
  bg.vt.reports['https://google.com/'] = fresh(bg);
  const r = await bg.run(bg.query(link));
  assert.equal(r.malicious, true);
  assert.equal(r.flaggedUrl, link);
  assert.equal(r.resolvedUrl, 'https://google.com/');
});

test('an allow-listed destination does not skip scanning the wrapper', async () => {
  const bg = loadBackground();
  bg.sync.data.allowList = ['google.com'];
  const link = 'https://evil.example/?u=https://google.com/';
  bg.vt.reports[link] = fresh(bg, {malicious: 1});
  const r = await bg.run(bg.query(link));
  assert.notEqual(r.listed, 'allow');
  assert.equal(r.malicious, true);
});

test('google.com/url is trusted: only its destination is scanned', async () => {
  const bg = loadBackground();
  bg.vt.reports['https://bad.example/x'] = fresh(bg, {malicious: 3});
  const r = await bg.run(bg.query('https://www.google.com/url?q=https://bad.example/x&sa=D'));
  assert.equal(r.malicious, true);
  assert.equal(bg.vt.requests.length, 1);
  assert.equal(Buffer.from(bg.vt.requests[0].path.slice(6), 'base64url').toString(), 'https://bad.example/x');
});

test('allow list through a trusted wrapper needs no request', async () => {
  const bg = loadBackground();
  bg.sync.data.allowList = ['good.example'];
  const r = await bg.run(bg.query('https://www.google.com/url?q=https://good.example/a'));
  assert.equal(r.listed, 'allow');
  assert.equal(bg.vt.requests.length, 0);
});

test('a deny-listed wrapper host blocks the link', async () => {
  const bg = loadBackground();
  bg.sync.data.denyList = ['evil.example'];
  const r = await bg.run(bg.query('https://evil.example/?u=https://google.com/'));
  assert.equal(r.listed, 'deny');
  assert.equal(r.malicious, true);
});

test('the worst verdict across hops wins', async () => {
  const bg = loadBackground();
  bg.vt.reports['https://t.example/?url=https://m.example/'] = fresh(bg, {suspicious: 1});
  bg.vt.reports['https://m.example/'] = fresh(bg, {malicious: 4});
  const r = await bg.run(bg.query('https://t.example/?url=https://m.example/'));
  assert.equal(r.malicious, true);
  assert.equal(r.flaggedUrl, 'https://m.example/');
});

test('an error on any hop fails the whole check', async () => {
  const bg = loadBackground();
  bg.vt.reports['https://t.example/?url=https://m.example/'] = fresh(bg);
  bg.vt.reports['https://m.example/'] = 'error';
  const r = await bg.run(bg.query('https://t.example/?url=https://m.example/'));
  assert.equal(r.ok, false);
});

test('more than 3 redirect hops fails closed', async () => {
  const bg = loadBackground();
  const deep = 'https://a.example/?u=' + encodeURIComponent('https://b.example/?u=' +
    encodeURIComponent('https://c.example/?u=' + encodeURIComponent('https://d.example/?u=https://e.example/')));
  const r = await bg.run(bg.query(deep));
  assert.equal(r.ok, false);
  assert.equal(r.error, 'too_many_redirects');
});

test('no API key gives no_api_key, not clean', async () => {
  const bg = loadBackground();
  delete bg.sync.data.vtApiKey;
  const r = await bg.run(bg.query('https://plain.example/'));
  assert.equal(r.ok, false);
  assert.equal(r.error, 'no_api_key');
});

// --- Report first, submit only when needed ---

test('a fresh existing report costs exactly one request', async () => {
  const bg = loadBackground();
  bg.vt.reports['https://known.example/'] = fresh(bg);
  const r = await bg.run(bg.query('https://known.example/'));
  assert.equal(r.ok, true);
  assert.equal(r.malicious, false);
  assert.equal(bg.vt.requests.length, 1);
  assert.equal(posts(bg).length, 0);
});

test('an unknown URL is submitted and polled', async () => {
  const bg = loadBackground();
  bg.vt.analysis['https://new.example/'] = {malicious: 2};
  const r = await bg.run(bg.query('https://new.example/'));
  assert.equal(r.malicious, true);
  assert.equal(r.maliciousCount, 2);
  assert.deepEqual(bg.vt.requests.map((q) => q.method + ' ' + q.path.split('/')[1]), ['GET urls', 'POST urls', 'GET analyses']);
});

test('a stale clean report is re-scanned', async () => {
  const bg = loadBackground();
  bg.vt.reports['https://old.example/'] = {stats: {malicious: 0}, date: bg.now() - 30 * bg.DAY_MS};
  bg.vt.analysis['https://old.example/'] = {suspicious: 1};
  const r = await bg.run(bg.query('https://old.example/'));
  assert.equal(r.suspicious, true);
  assert.equal(posts(bg).length, 1);
});

test('a stale report that already flags the URL is reused', async () => {
  const bg = loadBackground();
  bg.vt.reports['https://oldbad.example/'] = {stats: {malicious: 7}, date: bg.now() - 300 * bg.DAY_MS};
  const r = await bg.run(bg.query('https://oldbad.example/'));
  assert.equal(r.malicious, true);
  assert.equal(bg.vt.requests.length, 1);
});

test('an analysis that never completes falls back to a late report, else times out', async () => {
  const bg = loadBackground();
  bg.vt.pendingPolls['https://slow.example/'] = 99;
  const r = await bg.run(bg.query('https://slow.example/'));
  assert.equal(r.ok, false);
  assert.equal(r.error, 'timeout');
});

test('the final destination from the report is returned', async () => {
  const bg = loadBackground();
  bg.vt.reports['https://bit.example/abc'] = fresh(bg, undefined, {finalUrl: 'https://landing.example/page'});
  const r = await bg.run(bg.query('https://bit.example/abc'));
  assert.equal(r.finalUrl, 'https://landing.example/page');
});

// --- Normalization ---

test('tracking parameters and fragments are stripped before scanning', async () => {
  const bg = loadBackground();
  const clean = 'https://shop.example/item?id=7';
  bg.vt.reports[clean] = fresh(bg);
  await bg.run(bg.query('https://shop.example/item?id=7&utm_source=news&fbclid=abc#top'));
  await bg.run(bg.query('https://shop.example/item?utm_campaign=x&id=7&mc_eid=me'));
  assert.equal(bg.vt.requests.length, 1, 'second variant should hit the cache');
  assert.equal(Buffer.from(bg.vt.requests[0].path.slice(6), 'base64url').toString(), clean);
});

test('other parameters are left exactly as they were', () => {
  const bg = loadBackground();
  assert.equal(bg.call('normalizeForScan("https://x.example/a?q=a%20b&x=1")'), 'https://x.example/a?q=a%20b&x=1');
  assert.equal(bg.call('normalizeForScan("https://x.example/a?utm_source=z")'), 'https://x.example/a');
});

test('toBase64Url encodes UTF-8', () => {
  const bg = loadBackground();
  const url = 'https://例え.jp/ö';
  assert.equal(bg.call(`toBase64Url(${JSON.stringify(url)})`), Buffer.from(url, 'utf8').toString('base64url'));
});

// --- Rate limiter ---

test('no more than 4 requests are sent per minute', async () => {
  const bg = loadBackground();
  const urls = Array.from({length: 6}, (_, i) => `https://site${i}.example/`);
  for (const u of urls) bg.vt.reports[u] = fresh(bg);
  const all = Promise.all(urls.map((u) => bg.query(u)));
  await bg.advance(1000);
  assert.equal(bg.vt.requests.length, 4);
  await bg.advance(30 * 1000);
  assert.equal(bg.vt.requests.length, 4);
  await bg.run(all);
  assert.equal(bg.vt.requests.length, 6);
  assert.ok(bg.vt.requests[4].at - bg.vt.requests[0].at >= 60 * 1000);
});

test('the per-minute limit can be raised for premium keys', async () => {
  const bg = loadBackground();
  bg.sync.data.requestsPerMinute = 100;
  const urls = Array.from({length: 10}, (_, i) => `https://p${i}.example/`);
  for (const u of urls) bg.vt.reports[u] = fresh(bg);
  const all = Promise.all(urls.map((u) => bg.query(u)));
  await bg.advance(1000);
  assert.equal(bg.vt.requests.length, 10, 'all ten should go out in parallel');
  await bg.run(all);
});

test('a click jumps ahead of queued scans', async () => {
  const bg = loadBackground();
  const scans = Array.from({length: 8}, (_, i) => `https://scan${i}.example/`);
  for (const u of [...scans, 'https://clicked.example/']) bg.vt.reports[u] = fresh(bg);
  const pending = scans.map((u) => bg.query(u, 1));
  await bg.advance(1000); // 4 scans sent, 4 waiting
  const click = bg.query('https://clicked.example/', 0);
  await bg.run(click);
  const fifth = bg.vt.requests[4];
  assert.equal(Buffer.from(fifth.path.slice(6), 'base64url').toString(), 'https://clicked.example/');
  await bg.run(Promise.all(pending));
});

test('a click on a link that is queued for a scan raises its priority', async () => {
  const bg = loadBackground();
  const scans = Array.from({length: 8}, (_, i) => `https://q${i}.example/`);
  for (const u of scans) bg.vt.reports[u] = fresh(bg);
  const pending = scans.map((u) => bg.query(u, 1));
  await bg.advance(1000);
  const click = bg.query('https://q7.example/', 0); // last in the queue
  await bg.run(click);
  assert.equal(Buffer.from(bg.vt.requests[4].path.slice(6), 'base64url').toString(), 'https://q7.example/');
  await bg.run(Promise.all(pending));
  assert.equal(bg.vt.requests.length, 8, 'the shared lookup is not repeated');
});

test('the daily limit stops requests and fails closed', async () => {
  const bg = loadBackground();
  bg.local.data.vtquota = {day: new Date(bg.now()).toISOString().slice(0, 10), count: 500};
  const r = await bg.run(bg.query('https://any.example/'));
  assert.equal(r.ok, false);
  assert.equal(r.error, 'daily_limit');
  assert.equal(bg.vt.requests.length, 0);
});

test('the daily count resets at midnight UTC', async () => {
  const bg = loadBackground();
  bg.local.data.vtquota = {day: '2026-11-01', count: 500};
  bg.vt.reports['https://any.example/'] = fresh(bg);
  const r = await bg.run(bg.query('https://any.example/'));
  assert.equal(r.ok, true);
  assert.equal(bg.local.data.vtquota.count, 1);
});

test('an unexpected 429 pauses the queue for a minute', async () => {
  const bg = loadBackground();
  bg.vt.status = 429;
  const r = await bg.run(bg.query('https://a.example/'));
  assert.equal(r.ok, false);
  bg.vt.status = null;
  bg.vt.reports['https://b.example/'] = fresh(bg);
  const startedAt = bg.now();
  await bg.run(bg.query('https://b.example/'));
  assert.ok(bg.vt.requests[1].at - startedAt >= 50 * 1000, 'second request waits for the pause');
});

// --- Messages ---

test('checkUrl rejects non-http URLs', async () => {
  const bg = loadBackground();
  const r = await bg.send({type: 'checkUrl', url: 'javascript:alert(1)'});
  assert.equal(r.ok, false);
  assert.equal(r.error, 'invalid_url');
});

test('popup-only messages are refused from content scripts', async () => {
  const bg = loadBackground();
  assert.equal(await bg.send({type: 'clearCache'}), undefined);
  const fromGmail = {id: 'ext-id', tab: {id: 1}, url: 'https://mail.google.com/mail/u/0/#inbox'};
  assert.equal(await bg.send({type: 'clearCache'}, fromGmail), undefined);
  // The options page runs in a tab, so it has sender.tab too.
  const optionsTab = {id: 'ext-id', tab: {id: 2}, url: 'chrome-extension://ext-id/options.html'};
  assert.equal((await bg.send({type: 'getStatus'}, optionsTab)).requestsPerDay, 500);
  const fromPopup = {id: 'ext-id', url: 'chrome-extension://ext-id/popup.html'};
  const status = await bg.send({type: 'getStatus'}, fromPopup);
  assert.equal(status.requestsPerDay, 500);
  assert.equal(status.usedToday, 0);
});

test('checks show up in the recent list and clearCache empties it', async () => {
  const bg = loadBackground();
  bg.vt.reports['https://r.example/'] = fresh(bg, {malicious: 1});
  await bg.run(bg.send({type: 'checkUrl', url: 'https://r.example/'}));
  const fromPopup = {id: 'ext-id', url: 'chrome-extension://ext-id/popup.html'};
  const status = await bg.run(bg.send({type: 'getStatus'}, fromPopup));
  assert.equal(status.recent[0].url, 'https://r.example/');
  assert.equal(status.recent[0].verdict, 'malicious');
  assert.equal(status.usedToday, 1);
  const cleared = await bg.run(bg.send({type: 'clearCache'}, fromPopup));
  assert.equal(cleared.removed, 1);
});

test('flagCount sets the tab badge', async () => {
  const bg = loadBackground();
  await bg.send({type: 'flagCount', count: 3}, {id: 'ext-id', tab: {id: 9}});
  assert.equal(bg.badge[9], '3');
  await bg.send({type: 'flagCount', count: 0}, {id: 'ext-id', tab: {id: 9}});
  assert.equal(bg.badge[9], '');
});

test('testKey validates the format and reports VirusTotal answers', async () => {
  const bg = loadBackground();
  const fromOptions = {id: 'ext-id', url: 'chrome-extension://ext-id/options.html'};
  assert.equal((await bg.send({type: 'testKey', key: 'bad key!'}, fromOptions)).ok, false);
  const good = await bg.run(bg.send({type: 'testKey', key: 'a'.repeat(64)}, fromOptions)); // secret-scan:allow
  assert.equal(good.ok, true);
  bg.vt.status = 401;
  const rejected = await bg.run(bg.send({type: 'testKey', key: 'b'.repeat(64)}, fromOptions)); // secret-scan:allow
  assert.equal(rejected.ok, false);
});
