// Run with: node --test tests/
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ctx = {URL, TextEncoder};
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(path.join(__dirname, '..', 'domains.js'), 'utf8'), ctx);
const D = ctx.DomainLists;
const plain = (v) => JSON.parse(JSON.stringify(v)); // VM objects -> this realm

test('domains are normalized', () => {
  assert.equal(D.normalizeDomain('  Example.COM '), 'example.com');
  assert.equal(D.normalizeDomain('https://www.example.com/path?x=1'), 'www.example.com');
  assert.equal(D.normalizeDomain('*.example.org'), 'example.org');
  assert.equal(D.normalizeDomain('räksmörgås.se'), 'xn--rksmrgs-5wao1o.se');
});

test('invalid domains are rejected', () => {
  for (const bad of ['', 'localhost', 'not a domain', 'user@example.com', 'example.com:8080', '-bad.com', '1.2.3.4', 'a..b.com', '<script>.com']) {
    assert.equal(D.normalizeDomain(bad), null, bad);
  }
});

test('text area parsing reports invalid lines and skips comments', () => {
  const r = plain(D.parseDomainList('example.com\n# my bank\n\nbad entry\nEXAMPLE.com\nbank.se'));
  assert.deepEqual(r, {domains: ['example.com', 'bank.se'], invalid: ['bad entry']});
});

test('export and import round-trip', () => {
  const text = D.exportLists(['a.example'], ['b.example']);
  assert.deepEqual(plain(D.parseImport(text)), {allowList: ['a.example'], denyList: ['b.example']});
});

test('imports are validated as untrusted input', () => {
  assert.throws(() => D.parseImport('not json'), /not valid JSON/);
  assert.throws(() => D.parseImport('[]'), /does not contain/);
  assert.throws(() => D.parseImport('{"format":"other"}'), /not a Gmail Link Scanner export/);
  assert.throws(() => D.parseImport('{"allowList":"example.com"}'), /must be a list/);
  assert.throws(() => D.parseImport('{"allowList":[{"x":1}]}'), /not a valid domain/);
  assert.throws(() => D.parseImport('{"denyList":["javascript:alert(1)"]}'), /not a valid domain/);
  assert.throws(() => D.parseImport('x'.repeat(200 * 1024)), /too large/);
  const many = Array.from({length: 1000}, (_, i) => `domain-number-${i}.example`);
  assert.throws(() => D.parseImport(JSON.stringify({allowList: many})), /too long/);
  assert.deepEqual(plain(D.parseImport('{"allowList":["ok.example"]}')), {allowList: ['ok.example'], denyList: []});
});
