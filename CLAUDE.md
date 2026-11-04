# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Chromium extension (Manifest V3; Chrome and Edge) that checks links in Gmail messages with
VirusTotal and local phishing heuristics, outlines malicious (red), suspicious (amber) or
misleading (amber dashed) links, and shows an in-page warning panel before opening anything
flagged or unverified. Plain JS, no build step, no dependencies.

## Running

1. `chrome://extensions` (or `edge://extensions`) → Developer mode → **Load unpacked** → this folder.
2. Extension options → paste a VirusTotal API key (free tier), **Test key**, pick a scan mode.
3. Open Gmail. After editing code, click **Reload** on the extension card and refresh Gmail.

Debug the content script in Gmail's DevTools and the service worker via "Inspect views: service
worker" on the extension card.

## Tests

No dependencies; Node 22+.

- `node --test tests/` — background logic (fake clock, fake `chrome`, fake VirusTotal; loaded with
  `vm` from `tests/helpers/load-background.js`), heuristics, domain lists.
- `node tests/run-content-tests.js` — `tests/content/index.html` + `page-tests.js` in headless
  Edge/Chrome over the DevTools protocol (real time; `--virtual-time-budget` doesn't render frames,
  so `IntersectionObserver` never fires with it). The page opens the panel's closed shadow root by
  patching `attachShadow`.
- `node tests/run-extension-smoke.js` — loads the real extension (Edge/Chromium only; Chrome
  ignores `--load-extension`) and checks the service worker, options page and popup.

Run all three after changes. Browser-only test files must not be named `test.js` (`node --test`
would pick them up).

## Architecture

- **`contentScript.js`** (+ **`heuristics.js`**, same isolated world, exposes `LinkHeuristics`):
  only links inside message bodies (`MESSAGE_BODY_SELECTOR = '.a3s'`) are scanned or intercepted;
  Gmail's interface and same-origin links are left alone. Scan modes (`scanMode` in sync storage):
  `visible` (IntersectionObserver), `all` (everything at once, 16 in flight), `click` (none).
  Mutations are batched. Verdicts live in the `linkState` WeakMap with the checked `href`;
  `data-vt-flag` is for DevTools only and must never be read back (emails could set it). `click`
  and middle-button `auxclick` are intercepted in the capture phase; the warning `panel` is a
  closed shadow root. Clean results auto-open only while `navigator.userActivation.isActive`,
  otherwise the panel asks for one more click (popup blocking). Sends `flagCount` for the badge and
  answers `getPageSummary` for the popup.
- **`background.js`** (service worker): `redirectChain` (max 3 hops, deeper fails closed); every hop
  except the trusted `google.com/url` wrapper is checked (deny → allow → VirusTotal, sequentially),
  worst verdict wins. `scanUrl`: `normalizeForScan` (drops fragments and tracking params) → cache
  (24 h, 5 min for retryable errors) → in-flight de-dupe → `fetchFromVirusTotal`: `GET /urls/{id}`
  first (reused if fresh ≤ 7 days, or flagged at any age), else `POST /urls` + polls with
  `POLL_DELAYS_MS`. Every request goes through `vtRequest` → `acquireSlot`: one priority queue
  (click 0, scan 1; priority is raised if a click hits a queued URL), per-minute and per-day limits
  from settings (defaults 4/500), state persisted in `storage.session`/`storage.local`, 60 s pause
  after a 429, keep-alive while busy. Messages: `checkUrl`, `flagCount`, `openOptions` from content
  scripts; `getStatus`, `clearCache`, `testKey` only from extension pages (`isExtensionPage` checks
  the sender URL — the options page runs in a tab, so `sender.tab` can't be used).
- **`popup.html` / `popup.js`**: request budget, flagged links in the active tab, recent checks,
  clear cache. **`options.html` / `options.js` / `domains.js`** (`DomainLists`): settings,
  validated lists, JSON export/import.
- `chrome_extension_gmail_link_scanner.md`: the original design spec.

## Rules

- **Fail closed:** errors, timeouts, rate limits and quota exhaustion must never mark a link clean.
- **Only email content:** never scan or intercept links outside message bodies.
- Keep permissions minimal: `storage` plus host permissions for `mail.google.com` and
  `www.virustotal.com` only. Don't add `tabs`, `scripting` or `activeTab`.
- Respect the VirusTotal free-tier limits by default (4 requests/min, 500/day): every request goes
  through the rate limiter; keep caching and de-duping.
- Never log or hard-code an API key. Never send link data anywhere except VirusTotal.
- Untrusted input (link text, URLs, imported files) is only ever rendered with `textContent`.
- Bump `version` in `manifest.json` for releases.

## App standards

This repo follows the app standards in `~/Desktop/code/tools/standards/STANDARDS.md` (rule IDs,
severities; decisions and waivers in `.claude-standards`). `claude-check --repo .` checks it.

```sh
npm ci && npm run lint   # ESLint (dev-only), incl. the no-unsanitized rule; CI runs it too
node --test tests/ && node tests/run-content-tests.js # the tests CI runs
```

Unsafe DOM sinks (`innerHTML` and friends with unescaped data) are lint errors and fail CI, like
eval, undefined names and parse errors.
