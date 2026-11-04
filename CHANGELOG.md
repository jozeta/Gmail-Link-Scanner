# Changelog

All notable changes to Gmail-Link-Scanner are listed here, newest first.

Releases follow the project's git tags. The 1.1.0 entry was reconstructed from the commit history.

## [Unreleased]

- ESLint (flat config, with the no-unsanitized rule) as a dev-only tool; CI runs `npm run lint`
- CI workflow: lint and the existing tests on every push

## [1.2.0] - 2026-11-02

### Added

- In-page warning panel instead of the browser's `confirm()` dialog: shows the VirusTotal counts,
  the reasons and the real destination, with *Open anyway* / *Cancel* (Escape cancels). Opening
  from the panel is a real click, so the new tab is no longer blocked as a popup after a slow check.
- Local phishing heuristics (`heuristics.js`, no network): link text that shows a different domain
  than the link goes to, look-alike international characters (accented Latin such as å/ä/ö is
  fine), typosquats of well-known and allow-listed domains, and real domains used as subdomains.
  Such links get an amber dashed outline and a warning on click.
- Shows where a link finally ends up (VirusTotal's `last_final_url`), e.g. behind URL shorteners.
- Scan modes: links as they come into view (default), every link in an opened email at once in
  parallel, or only when clicked.
- Configurable request limits per minute and per day, for premium VirusTotal keys.
- Toolbar popup: today's request budget and queue, flagged links in the open email, recent checks,
  *Clear cache*, and a warning when an email is open but its message body can't be found. The
  badge shows the number of flagged links in the open email.
- Settings: *Test key* button, domain validation, and JSON export/import of the allow/deny lists
  (imports are validated as untrusted input).
- Tests: `node --test tests/` (background, heuristics, domain lists), a headless-browser test for
  the content script, and a smoke test that loads the real extension.

### Changed

- Only links inside email message bodies are scanned **and intercepted**; Gmail's own interface
  is no longer touched at all.
- VirusTotal lookups fetch the existing report first (one request) and only submit a new scan for
  unknown URLs or clean reports older than 7 days. Polling uses 4 polls with growing gaps instead
  of 10 polls 1.5 s apart.
- All VirusTotal requests go through one rate limiter (4/min and 500/day by default) with clicks
  ahead of background scans, a pause after an unexpected 429, and a service-worker keep-alive.
- Tracking parameters (`utm_*`, `fbclid`, `mc_eid`…) and fragments are stripped before a URL is
  looked up or cached.
- Links are scanned in batches as Gmail adds content, instead of once per added DOM node.

### Security

- Redirect wrappers can no longer make a malicious link look clean. Previously a link such as
  `https://evil.example/?u=https://google.com` was judged (and allow-list matched) only by its
  destination, while the click went to `evil.example`. Every address in the redirect chain is now
  checked, except Google's own `google.com/url` wrapper, and the worst verdict wins. A chain
  deeper than 3 hops gets a "could not verify" warning instead of being judged by its last
  address.
- Middle-clicks are now intercepted (`auxclick`), so they can no longer open an unchecked or
  flagged link in a new tab.
- A verdict now only applies to the exact `href` that was checked. If a link's address changes
  later, it is treated as unchecked and re-scanned. Verdicts are kept privately in the content
  script, so an email can't forge a "clean" verdict with a `data-vt-flag` attribute.

### Fixed

- Gmail's own interface links no longer use up the VirusTotal quota (see *Changed*: only links
  in email message bodies are scanned).
- The VirusTotal URL-id fallback no longer fails on addresses with characters outside Latin-1
  (it now encodes the URL as UTF-8 before base64url).

### Docs

- README and CLAUDE.md describe the new behaviour, mention Microsoft Edge, document the tests,
  and list the opening methods that can't be intercepted (context-menu *Open in new tab*,
  dragging a link). New screenshots of the warning panel, popup and settings (demo data).

## [1.1.0] - 2026-11-02

- Gmail Link Scanner extension: VirusTotal checks for links in Gmail, red/amber outlines,
  confirmation before opening flagged or unverified links, redirect unwrapping, allow/deny
  domain lists, caching and de-duplicated lookups.
- Repository housekeeping: `.gitignore` baseline, CLAUDE.md, README screenshot, security policy.
