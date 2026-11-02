# Changelog

All notable changes to Gmail-Link-Scanner are listed here, newest first.

Releases follow the project's git tags. The 1.1.0 entry was reconstructed from the commit history.

## [Unreleased]

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

- Links are only scanned on load inside email message bodies, so Gmail's own interface no
  longer uses up the VirusTotal quota. Links elsewhere are still checked when clicked, and links
  back into Gmail itself are ignored.
- The VirusTotal URL-id fallback no longer fails on addresses with characters outside Latin-1
  (it now encodes the URL as UTF-8 before base64url).

### Docs

- README and CLAUDE.md describe the new behaviour, mention Microsoft Edge, and list the opening
  methods that can't be intercepted (context-menu *Open in new tab*, dragging a link).

## [1.1.0] - 2026-11-02

- Gmail Link Scanner extension: VirusTotal checks for links in Gmail, red/amber outlines,
  confirmation before opening flagged or unverified links, redirect unwrapping, allow/deny
  domain lists, caching and de-duplicated lookups.
- Repository housekeeping: `.gitignore` baseline, CLAUDE.md, README screenshot, security policy.
