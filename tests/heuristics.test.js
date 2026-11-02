// Run with: node --test tests/
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const {domainToASCII, domainToUnicode} = require('url');

const ctx = {URL};
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(path.join(__dirname, '..', 'heuristics.js'), 'utf8'), ctx);
const H = ctx.LinkHeuristics;

const types = (warnings) => warnings.map((w) => w.type);
// Arrays from the VM have another realm's prototype, so compare contents, not identity.
const assertNone = (warnings, label) => assert.equal(warnings.length, 0, `${label || ''} ${JSON.stringify(warnings)}`);
const analyze = (args) => H.analyze({allowList: [], ...args});

test('punycode decoding matches Node for real-world labels', () => {
  for (const host of ['münchen.de', 'björnsson.se', 'räksmörgås.se', 'аррӏе.com', 'пример.рф', '例え.jp', 'ελλάδα.gr']) {
    const ascii = domainToASCII(host);
    assert.equal(H.toUnicodeHost(ascii), domainToUnicode(ascii), host);
  }
  assert.equal(H.decodePunycode('!!!'), null);
});

test('registrable domain handles common two-part suffixes', () => {
  assert.equal(H.registrableDomain('a.b.example.com'), 'example.com');
  assert.equal(H.registrableDomain('www.bbc.co.uk'), 'bbc.co.uk');
  assert.equal(H.registrableDomain('shop.example.com.au'), 'example.com.au');
  assert.equal(H.registrableDomain('192.168.0.1'), '192.168.0.1');
});

test('link text counts as a domain only when it really looks like one', () => {
  assert.equal(H.hostFromText('paypal.com'), 'paypal.com');
  assert.equal(H.hostFromText('https://www.paypal.com/signin'), 'www.paypal.com');
  assert.equal(H.hostFromText('(www.example.org)'), 'www.example.org');
  assert.equal(H.hostFromText('Read more'), null);
  assert.equal(H.hostFromText('Node.js'), null);
  assert.equal(H.hostFromText('report.pdf'), null);
  assert.equal(H.hostFromText('click here: paypal.com'), null);
});

test('#7 text showing one domain but linking to another is flagged', () => {
  const w = analyze({text: 'www.paypal.com', href: 'https://paypal-login.example/x', resolvedUrl: 'https://paypal-login.example/x'});
  assert.ok(types(w).includes('text-mismatch'));
});

test('#7 text matching the destination is fine, even through a tracker that ends there', () => {
  assertNone(analyze({text: 'example.com', href: 'https://www.example.com/', resolvedUrl: 'https://www.example.com/'}));
  assertNone(analyze({text: 'example.com', href: 'https://click.tracker.example/abc',
    resolvedUrl: 'https://click.tracker.example/abc', finalUrl: 'https://example.com/landing'}));
});

test('#7 a google.com/url wrapper cannot vouch for text that shows google.com', () => {
  const w = analyze({text: 'google.com', href: 'https://www.google.com/url?q=https://evil.example/', resolvedUrl: 'https://evil.example/'});
  assert.ok(types(w).includes('text-mismatch'));
});

test('#8 mixed-script and all-confusable IDN domains are flagged', () => {
  assert.ok(types(analyze({text: 'x', href: 'https://' + domainToASCII('pаypal.com') + '/'})).includes('idn')); // Cyrillic а
  assert.ok(types(analyze({text: 'x', href: 'https://' + domainToASCII('аррӏе.com') + '/'})).includes('idn'));
});

test('#8 Swedish and other accented Latin domains are not flagged', () => {
  for (const host of ['räksmörgås.se', 'björnsson.se', 'münchen.de', 'café.fr']) {
    assertNone(analyze({text: 'x', href: `https://${domainToASCII(host)}/`}), host);
  }
});

test('#8 typosquats of well-known domains are flagged', () => {
  for (const host of ['paypa1.com', 'rnicrosoft.com', 'micros0ft.com', 'pay-pal.com', 'linkedln.com', 'dropboxx.com']) {
    assert.ok(types(analyze({text: 'x', href: `https://${host}/`})).includes('lookalike'), host);
  }
});

test('#8 the real domains and unrelated domains are not flagged', () => {
  for (const host of ['www.paypal.com', 'login.microsoftonline.com', 'mail.google.com', 'google.se', 'example.com', 'apnews.com', 'ample.com']) {
    assertNone(analyze({text: 'x', href: `https://${host}/`}), host);
  }
});

test('#8 a real domain used as a subdomain is flagged', () => {
  assert.ok(types(analyze({text: 'x', href: 'https://paypal.com.secure-check.example/'})).includes('brand-subdomain'));
});

test('#8 near-matches to the allow list are flagged, allow-listed hosts are not', () => {
  const allowList = ['handelsbanken.se'];
  assert.ok(types(H.analyze({text: 'x', href: 'https://handelsbankem.se/', allowList})).includes('lookalike'));
  assertNone(H.analyze({text: 'x', href: 'https://www.handelsbanken.se/', allowList}));
});
