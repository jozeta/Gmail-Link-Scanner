# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Chromium extension (Manifest V3; Chrome and Edge) that scans links in Gmail messages with VirusTotal, outlines
malicious (red) or suspicious (amber) links, and asks for confirmation before opening anything
flagged or unverified. Plain JS, no build step, no dependencies.

## Running

1. `chrome://extensions` (or `edge://extensions`) → Developer mode → **Load unpacked** → this folder.
2. Extension options → paste a VirusTotal API key (free tier), optionally allow/deny domains.
3. Open Gmail. After editing code, click **Reload** on the extension card and refresh Gmail.

There is no automated test suite. Debug the content script in Gmail's DevTools and the service
worker via "Inspect views: service worker" on the extension card.

## Architecture

- **`contentScript.js`** (on `mail.google.com`): scans external http(s) `<a href>` links inside
  message bodies (`MESSAGE_BODY_SELECTOR = '.a3s'`) with bounded concurrency (4), decorates them
  (`markLink`), and intercepts `click` and middle-button `auxclick` on *every* external link in the
  capture phase: anything not verified clean or allow-listed for its current `href` is held until
  its check resolves (local 30 s fail-safe), with `confirm()` before opening risky links via
  `window.open(href, '_blank', 'noopener,noreferrer')`. Verdicts live in the `linkState` WeakMap
  (keyed by element, storing the checked `href`); `data-vt-flag` is written for DevTools only and
  must never be read back, because email HTML could set it. A `MutationObserver` catches new links
  and `href` changes. Same-origin (Gmail) links are ignored. `pendingChecks` de-dupes in-flight checks.
- **`background.js`** (service worker): handles `checkUrl` messages; builds the redirect chain
  (`redirectChain`: `google.com/url?q=`, `url=`/`u=`/`redirect=`…, max 3 hops, deeper fails
  closed). Every hop except the trusted `google.com/url` wrapper is checked (deny list → allow
  list → VirusTotal, sequentially) and the worst verdict wins, so a malicious wrapper can't hide
  behind a clean destination. Per URL (`scanUrl`): the
  `chrome.storage.local` cache (24 h verdicts, 5 min for retryable errors); otherwise
  `POST /api/v3/urls`, polls `GET /api/v3/analyses/{id}` (10 × 1.5 s), falls back to
  `GET /api/v3/urls/{id}` (unpadded base64url). Returns
  `{ ok, malicious, suspicious, maliciousCount, suspiciousCount, resolvedUrl, flaggedUrl?, listed? }`.
- **`options.html` / `options.js`**: API key and allow/deny lists in `chrome.storage.sync`.
- `chrome_extension_gmail_link_scanner.md`: the original design spec.

## Rules

- **Fail closed:** errors, timeouts and rate limits must never mark a link clean.
- Keep permissions minimal: `storage` plus host permissions for `mail.google.com` and
  `www.virustotal.com` only. Don't add `tabs`, `scripting` or `activeTab`.
- Respect the VirusTotal free-tier limits (4 requests/min, 500/day): keep caching and de-duping.
- Never log or hard-code an API key. Never send link data anywhere except VirusTotal.
- Bump `version` in `manifest.json` for releases.
