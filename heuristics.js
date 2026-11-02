// heuristics.js
//
// Local phishing signals that need no network request: link text that shows a
// different domain than the link goes to, look-alike international characters,
// and domains that imitate well-known or allow-listed ones. Loaded before
// contentScript.js (same isolated world) and exposed as `LinkHeuristics`.

(function (root) {
  'use strict';

  // Frequent phishing targets, plus whatever is on the user's allow list.
  const WELL_KNOWN_DOMAINS = [
    'google.com', 'gmail.com', 'microsoft.com', 'office.com', 'live.com', 'outlook.com',
    'apple.com', 'icloud.com', 'paypal.com', 'amazon.com', 'facebook.com', 'instagram.com',
    'linkedin.com', 'netflix.com', 'dropbox.com', 'docusign.com', 'adobe.com', 'github.com',
    'bankid.com'
  ];

  // Second-level labels under a two-letter country code that form a public
  // suffix (example.co.uk, example.com.au). A small stand-in for the full
  // Public Suffix List, which would be large to ship.
  const COUNTRY_SECOND_LEVELS = new Set(['co', 'com', 'net', 'org', 'gov', 'ac', 'edu', 'or', 'ne', 'go', 'ltd', 'plc', 'sch', 'nhs', 'gv']);

  // Common TLDs. Link text without "http://" or "www." only counts as a
  // domain when it ends in one of these, so "Node.js" or "report.pdf" don't.
  const COMMON_TLDS = new Set([
    'com', 'net', 'org', 'info', 'biz', 'io', 'co', 'app', 'dev', 'ai', 'me', 'tv', 'xyz', 'online', 'site',
    'shop', 'store', 'top', 'club', 'live', 'cloud', 'email', 'link', 'click', 'gov', 'edu',
    'se', 'nu', 'no', 'dk', 'fi', 'is', 'de', 'at', 'ch', 'nl', 'be', 'fr', 'es', 'it', 'pt', 'pl', 'cz',
    'uk', 'ie', 'eu', 'us', 'ca', 'au', 'nz', 'jp', 'cn', 'in', 'br', 'ru', 'ua'
  ]);

  // Characters that look like Latin letters, mapped to the letter they imitate.
  const CONFUSABLES = {
    // Cyrillic
    'а': 'a', 'в': 'b', 'е': 'e', 'ё': 'e', 'к': 'k', 'м': 'm', 'н': 'h', 'о': 'o', 'р': 'p', 'с': 'c',
    'т': 't', 'у': 'y', 'х': 'x', 'ѕ': 's', 'і': 'i', 'ї': 'i', 'ј': 'j', 'һ': 'h', 'ԁ': 'd', 'ԛ': 'q',
    'ԝ': 'w', 'ӏ': 'l', 'ɡ': 'g',
    // Greek
    'α': 'a', 'β': 'b', 'ε': 'e', 'η': 'n', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ο': 'o', 'ρ': 'p', 'τ': 't',
    'υ': 'u', 'χ': 'x', 'ω': 'w',
    // Digits and letter pairs used in ASCII typosquats
    '0': 'o', '1': 'l', '3': 'e', '5': 's', '|': 'l'
  };

  // --- Punycode (RFC 3492) decoding, for xn-- labels ---

  const BASE = 36, T_MIN = 1, T_MAX = 26, SKEW = 38, DAMP = 700, INITIAL_BIAS = 72, INITIAL_N = 128;

  function adapt(delta, numPoints, firstTime) {
    delta = firstTime ? Math.floor(delta / DAMP) : delta >> 1;
    delta += Math.floor(delta / numPoints);
    let k = 0;
    while (delta > ((BASE - T_MIN) * T_MAX) >> 1) {
      delta = Math.floor(delta / (BASE - T_MIN));
      k += BASE;
    }
    return Math.floor(k + ((BASE - T_MIN + 1) * delta) / (delta + SKEW));
  }

  function digitValue(code) {
    if (code >= 48 && code <= 57) return code - 22; // 0-9 -> 26-35
    if (code >= 65 && code <= 90) return code - 65; // A-Z
    if (code >= 97 && code <= 122) return code - 97; // a-z
    return BASE;
  }

  // Decodes the part after "xn--". Returns null for invalid input.
  function decodePunycode(input) {
    const output = [];
    let n = INITIAL_N, i = 0, bias = INITIAL_BIAS;
    const basic = Math.max(input.lastIndexOf('-'), 0);
    for (let j = 0; j < basic; j++) {
      const code = input.charCodeAt(j);
      if (code >= 0x80) return null;
      output.push(code);
    }
    for (let index = basic > 0 ? basic + 1 : 0; index < input.length;) {
      const oldI = i;
      let w = 1;
      for (let k = BASE; ; k += BASE) {
        if (index >= input.length) return null;
        const digit = digitValue(input.charCodeAt(index++));
        if (digit >= BASE || digit > Math.floor((0x7fffffff - i) / w)) return null;
        i += digit * w;
        const t = k <= bias ? T_MIN : k >= bias + T_MAX ? T_MAX : k - bias;
        if (digit < t) break;
        w *= BASE - t;
      }
      const length = output.length + 1;
      bias = adapt(i - oldI, length, oldI === 0);
      n += Math.floor(i / length);
      if (n > 0x10ffff) return null;
      i %= length;
      output.splice(i++, 0, n);
    }
    return String.fromCodePoint(...output);
  }

  function toUnicodeHost(host) {
    return host.split('.').map((label) => {
      if (!label.startsWith('xn--')) return label;
      return decodePunycode(label.slice(4)) || label;
    }).join('.');
  }

  // --- Domains ---

  function registrableDomain(host) {
    host = String(host || '').toLowerCase().replace(/\.$/, '');
    if (!host || /^[\d.]+$/.test(host) || host.includes(':') || host.startsWith('[')) return host;
    const labels = host.split('.');
    if (labels.length <= 2) return host;
    const tld = labels[labels.length - 1];
    const second = labels[labels.length - 2];
    const take = tld.length === 2 && COUNTRY_SECOND_LEVELS.has(second) ? 3 : 2;
    return labels.slice(-take).join('.');
  }

  // The registrable domain without its public suffix: "paypal" for paypal.co.uk.
  function mainLabel(host) {
    return registrableDomain(host).split('.')[0];
  }

  function hostOf(url) {
    try {
      return new URL(url).hostname.toLowerCase();
    } catch (e) {
      return null;
    }
  }

  function hostMatchesList(host, list) {
    return Boolean(host) && list.some((entry) => host === entry || host.endsWith('.' + entry));
  }

  // --- Link text that looks like a domain ---

  const TEXT_URL = /^(https?:\/\/)?((?:[\p{L}\p{N}](?:[\p{L}\p{N}-]{0,61}[\p{L}\p{N}])?\.)+[\p{L}]{2,63})(?::\d{1,5})?(?:[/?#]\S*)?$/iu;

  // Returns the hostname shown by a link's text, or null when the text isn't a
  // URL or domain.
  function hostFromText(text) {
    const trimmed = String(text || '').trim().replace(/^[<([]+|[>)\].,;:!]+$/g, '');
    if (!trimmed || trimmed.length > 2048 || /\s/.test(trimmed)) return null;
    const match = TEXT_URL.exec(trimmed);
    if (!match) return null;
    const explicit = Boolean(match[1]) || /^www\./i.test(match[2]);
    const tld = match[2].split('.').pop().toLowerCase();
    if (!explicit && !COMMON_TLDS.has(tld)) return null;
    return hostOf('http://' + match[2]); // also converts Unicode to punycode
  }

  // --- Look-alike checks ---

  function scriptOf(char) {
    const code = char.codePointAt(0);
    if ((code >= 0x61 && code <= 0x7a) || (code >= 0xc0 && code <= 0x24f)) return 'latin';
    if (code >= 0x400 && code <= 0x52f) return 'cyrillic';
    if (code >= 0x370 && code <= 0x3ff) return 'greek';
    if (/\p{L}/u.test(char)) return 'other';
    return null; // digits, hyphens
  }

  // Why a decoded label is risky, or null. Accented Latin (åäö, é, ü) is fine.
  function labelScriptRisk(label) {
    const scripts = new Set();
    let allConfusable = true;
    for (const char of label) {
      const script = scriptOf(char);
      if (script) scripts.add(script);
      if (script && script !== 'latin' && !(char in CONFUSABLES)) allConfusable = false;
    }
    const lookalikeScripts = scripts.has('cyrillic') || scripts.has('greek');
    if (lookalikeScripts && scripts.has('latin')) return 'mixes Latin letters with look-alike letters from another alphabet';
    if (lookalikeScripts && !scripts.has('latin') && !scripts.has('other') && allConfusable) {
      return 'is written entirely in letters that imitate Latin ones';
    }
    return null;
  }

  function skeleton(label) {
    let out = '';
    for (const char of label.toLowerCase()) out += CONFUSABLES[char] || char;
    return out.replace(/-/g, '').replace(/rn/g, 'm').replace(/vv/g, 'w');
  }

  function editDistance(a, b) {
    if (Math.abs(a.length - b.length) > 2) return 3;
    let prev = Array.from({length: b.length + 1}, (_, i) => i);
    for (let i = 1; i <= a.length; i++) {
      const cur = [i];
      for (let j = 1; j <= b.length; j++) {
        cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      }
      prev = cur;
    }
    return prev[b.length];
  }

  function lookalikeWarnings(host, protectedDomains) {
    const warnings = [];
    const unicodeHost = toUnicodeHost(host);
    const registrable = registrableDomain(host);

    if (unicodeHost !== host) {
      for (const label of unicodeHost.split('.')) {
        const risk = labelScriptRisk(label);
        if (risk) {
          warnings.push({type: 'idn', host, message: `${unicodeHost} ${risk}.`});
          break;
        }
      }
    }

    const label = toUnicodeHost(mainLabel(host));
    for (const domain of protectedDomains) {
      if (registrable === domain) return warnings; // it *is* the real domain
    }
    for (const domain of protectedDomains) {
      // paypal.com.evil.example: the real domain used as a subdomain.
      if (host.startsWith(domain + '.') || host.includes('.' + domain + '.')) {
        warnings.push({type: 'brand-subdomain', host, imitates: domain,
          message: `${host} starts like ${domain}, but the site is ${registrable}.`});
        break;
      }
      const target = mainLabel(domain);
      if (label === target) continue; // same name under another suffix (google.se): not a typo
      const similar = (label.length >= 4 && skeleton(label) === skeleton(target)) ||
        (Math.min(label.length, target.length) >= 6 && editDistance(label, target) === 1);
      if (similar) {
        warnings.push({type: 'lookalike', host, imitates: domain,
          message: `${toUnicodeHost(registrable)} looks like ${domain}, but is a different site.`});
        break;
      }
    }
    return warnings;
  }

  // --- Entry point ---

  // {text, href, resolvedUrl, finalUrl, allowList} -> [{type, message, ...}]
  function analyze({text, href, resolvedUrl, finalUrl, allowList = []}) {
    const warnings = [];
    const allow = allowList.map((d) => String(d).toLowerCase());
    const protectedDomains = [...new Set([...WELL_KNOWN_DOMAINS, ...allow.map(registrableDomain)])];

    const hrefHost = hostOf(href);
    const resolvedHost = hostOf(resolvedUrl || href);
    const finalHost = finalUrl ? hostOf(finalUrl) : null;

    // 1. The link text shows one domain, the link goes to another. Compared
    //    with where the link really ends up (after unwrapping), not with a
    //    google.com/url wrapper's host.
    const shown = hostFromText(text);
    if (shown) {
      const shownDomain = registrableDomain(shown);
      const destinations = [resolvedHost, finalHost].filter(Boolean);
      if (!destinations.some((h) => registrableDomain(h) === shownDomain)) {
        const actual = finalHost || resolvedHost;
        warnings.push({type: 'text-mismatch', shown, actual,
          message: `The link text shows ${toUnicodeHost(shown)}, but the link goes to ${toUnicodeHost(actual || '?')}.`});
      }
    }

    // 2. Look-alike domains, for every distinct host the link passes through.
    const seen = new Set();
    for (const host of [hrefHost, resolvedHost, finalHost]) {
      if (!host || seen.has(host) || hostMatchesList(host, allow)) continue;
      seen.add(host);
      warnings.push(...lookalikeWarnings(host, protectedDomains));
    }
    return warnings;
  }

  root.LinkHeuristics = {
    analyze, hostFromText, registrableDomain, decodePunycode, toUnicodeHost,
    labelScriptRisk, skeleton, editDistance, WELL_KNOWN_DOMAINS
  };
})(globalThis);
