# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Chrome extension (Manifest V3) that scans links in Gmail messages with VirusTotal, outlines
malicious (red) or suspicious (amber) links, and asks for confirmation before opening anything
flagged or unverified. Plain JS, no build step, no dependencies.

## Running

1. `chrome://extensions` → Developer mode → **Load unpacked** → this folder.
2. Extension options → paste a VirusTotal API key (free tier), optionally allow/deny domains.
3. Open Gmail. After editing code, click **Reload** on the extension card and refresh Gmail.

There is no automated test suite. Debug the content script in Gmail's DevTools and the service
worker via "Inspect views: service worker" on the extension card.

## Architecture

- **`contentScript.js`** (on `mail.google.com`): finds `<a href>` http(s) links, asks the
  background worker to check them with bounded concurrency (4), decorates them (`markLink`), and
  intercepts clicks in the capture phase: anything not verified clean or allow-listed is held
  until its check resolves (local 30 s fail-safe), with `confirm()` before opening risky links
  via `window.open(href, '_blank', 'noopener,noreferrer')`. A `MutationObserver` catches links
  that render later. `pendingChecks` de-dupes in-flight checks.
- **`background.js`** (service worker): handles `checkUrl` messages; unwraps redirect wrappers
  (`google.com/url?q=`, `url=`/`u=`/`redirect=`…, up to 3 hops); applies allow/deny lists; checks the
  `chrome.storage.local` cache (24 h verdicts, 5 min for retryable errors); otherwise
  `POST /api/v3/urls`, polls `GET /api/v3/analyses/{id}` (10 × 1.5 s), falls back to
  `GET /api/v3/urls/{id}` (unpadded base64url). Returns
  `{ ok, malicious, suspicious, maliciousCount, suspiciousCount, resolvedUrl, listed? }`.
- **`options.html` / `options.js`**: API key and allow/deny lists in `chrome.storage.sync`.
- `chrome_extension_gmail_link_scanner.md`: the original design spec.

## Rules

- **Fail closed:** errors, timeouts and rate limits must never mark a link clean.
- Keep permissions minimal: `storage` plus host permissions for `mail.google.com` and
  `www.virustotal.com` only. Don't add `tabs`, `scripting` or `activeTab`.
- Respect the VirusTotal free-tier limits (4 requests/min, 500/day): keep caching and de-duping.
- Never log or hard-code an API key. Never send link data anywhere except VirusTotal.
- Bump `version` in `manifest.json` for releases.
