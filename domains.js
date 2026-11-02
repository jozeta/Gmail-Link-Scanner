// domains.js
//
// Parsing and validation for the allow/deny domain lists, used by the options
// page for both the text areas and imported files. Exposed as `DomainLists`.

(function (root) {
  'use strict';

  const HOSTNAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/;
  // chrome.storage.sync allows 8192 bytes per item, key included.
  const MAX_LIST_BYTES = 8000;
  const MAX_IMPORT_BYTES = 100 * 1024;

  // "https://Sub.Example.com/path" -> "sub.example.com"; Unicode -> punycode;
  // null when it isn't a valid domain name.
  function normalizeDomain(input) {
    let value = String(input).trim().toLowerCase();
    if (!value) return null;
    value = value.replace(/^[a-z][a-z0-9+.-]*:\/\//, '').replace(/[/?#].*$/, '').replace(/^\*\./, '').replace(/\.$/, '');
    if (value.includes('@') || value.includes(':')) return null; // credentials, ports, IPv6
    let host;
    try {
      host = new URL('http://' + value).hostname;
    } catch (e) {
      return null;
    }
    return HOSTNAME.test(host) ? host : null;
  }

  // Text area contents -> {domains, invalid}. Blank lines and # comments are ignored.
  function parseDomainList(text) {
    const domains = [];
    const invalid = [];
    for (const line of String(text).split('\n')) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const domain = normalizeDomain(trimmed);
      if (domain) {
        if (!domains.includes(domain)) domains.push(domain);
      } else {
        invalid.push(trimmed.slice(0, 100));
      }
    }
    return {domains, invalid};
  }

  function fitsSyncStorage(list) {
    return new TextEncoder().encode(JSON.stringify(list)).length <= MAX_LIST_BYTES;
  }

  function exportLists(allowList, denyList) {
    return JSON.stringify({format: 'gmail-link-scanner-lists', version: 1, allowList, denyList}, null, 2);
  }

  // Imported file text -> {allowList, denyList}. Throws an Error with a
  // message fit for the user. The file is untrusted input: only plain arrays
  // of valid domain names are accepted.
  function parseImport(text) {
    if (typeof text !== 'string' || text.length > MAX_IMPORT_BYTES) throw new Error('The file is too large.');
    let data;
    try {
      data = JSON.parse(text);
    } catch (e) {
      throw new Error('The file is not valid JSON.');
    }
    if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('The file does not contain domain lists.');
    if (data.format !== undefined && data.format !== 'gmail-link-scanner-lists') throw new Error('The file is not a Gmail Link Scanner export.');

    const lists = {};
    for (const name of ['allowList', 'denyList']) {
      const value = data[name] === undefined ? [] : data[name];
      if (!Array.isArray(value)) throw new Error(`"${name}" must be a list of domains.`);
      const domains = [];
      for (const item of value) {
        const domain = typeof item === 'string' ? normalizeDomain(item) : null;
        if (!domain) throw new Error(`"${String(item).slice(0, 60)}" in ${name} is not a valid domain.`);
        if (!domains.includes(domain)) domains.push(domain);
      }
      if (!fitsSyncStorage(domains)) throw new Error(`${name} is too long to store in Chrome sync storage.`);
      lists[name] = domains;
    }
    return lists;
  }

  root.DomainLists = {normalizeDomain, parseDomainList, fitsSyncStorage, exportLists, parseImport};
})(globalThis);
