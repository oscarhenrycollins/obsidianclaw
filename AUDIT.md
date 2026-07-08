# OcO Obsidian Plugin Audit

**Repository:** `bighill/oco-obsidian-plugin`  
**Commit audited:** `e3e28d4` (`style: add 3rem vertical margin to user bubble`)  
**Date:** 2026-07-07  
**Auditor:** coding-agent harness (pi)

---

## 1. Scope & Methodology

Audited the TypeScript source under `src/`, build/release tooling, manifest, documentation, and the OpenClaw gateway patch script. Smoke checks run:

- `npm run lint` — passed
- `npm run typecheck` — passed
- `npm test` — 42/42 passed
- `npm run build` — passed

Findings are grouped by severity: **Critical / High**, **Medium**, **Low / Informational**. Line references are approximate and point to the audited commit.

---

## 2. Executive Summary

The plugin is functionally coherent: build, lint, type-check, and tests all pass; DOM construction uses Obsidian helpers and avoids `innerHTML`/`eval`; and the gateway handshake includes token + Ed25519 device signatures. However, several **security-sensitive workflows are undermined by documentation, stale code, or missing guardrails**:

1. The **gateway origin patch is installed with `curl | sudo bash`**, creating a supply-chain / privilege-escalation risk.
2. **Tool-call URLs from the gateway are opened in the default browser without scheme validation**, allowing a compromised gateway to push `javascript:` links.
3. The **auth token and Ed25519 private key live as plaintext in `data.json`** inside the vault, which conflicts with the security doc’s claim that keys “never leave your machine” when Obsidian Sync is enabled.

Code-quality debt is also significant: `src/chat-view.ts` is a ~3,000-line monolith with duplicated tab-action logic and many unused private methods. Several actual UI bugs exist (hanging promises, stale session state, incomplete persistence).

---

## 3. Findings

### 🔴 Critical / High

#### H1 — Gateway patch script is delivered and executed via `curl | sudo bash`
- **Files:** `scripts/patch-openclaw.sh`, `README.md` (Prerequisites section)
- **Risk:** Supply-chain compromise, local privilege escalation, silent failure if upstream source is tampered with.
- **Details:** The README instructs users to run:
  ```bash
  curl -fsSL https://raw.githubusercontent.com/bighill/oco-obsidian-plugin/main/scripts/patch-openclaw.sh | sudo bash
  ```
  The script itself is idempotent and backs up the target file, but piping remote shell into `sudo` is an anti-pattern. An attacker who can modify the script (repo compromise, MITM, or future maintainer change) gains root on the gateway machine.
- **Recommendation:** Provide a verified, checksum-pinned install path; document manual patching as the preferred method; or work with upstream to eliminate the need for the patch (the README already acknowledges the upstream fix is desired).

#### H2 — Tool-call links open arbitrary gateway-controlled URLs without validation
- **File:** `src/chat-view.ts` (~`buildToolLabel`, `appendToolCall`, `createStreamItemEl`)
- **Risk:** Cross-context script execution if a compromised gateway emits a `web_fetch` URL with a `javascript:` or custom scheme.
- **Details:** URLs returned from the gateway in tool-call payloads are rendered as `<a href="{url}">` and handled with `window.open(url, '_blank')`. There is no allow-list or scheme check. A malicious gateway (or a malicious agent manipulating gateway state) could inject links that execute in Obsidian’s renderer context.
- **Recommendation:** Validate URLs before opening (require `http://`/`https://` or an Obsidian-internal scheme) and/or use Obsidian’s `require('electron').shell.openExternal` with user confirmation.

#### H3 — Auth token and private device key are stored as plaintext in vault plugin data
- **Files:** `src/crypto.ts` (`getOrCreateDeviceIdentity`), `src/main.ts` (`loadData`/`saveData`), `SECURITY.md`
- **Risk:** Exposure of long-lived credentials if the vault is synced, backed up to untrusted storage, or opened on a shared machine.
- **Details:** `data.json` contains `token`, `devicePrivateKey`, `devicePublicKey`, and `deviceId`. `SECURITY.md` states: “Your private key (never transmitted)” and “Your keys never leave your machine.” That is true for the wire, but plugin data is stored in `.obsidian/plugins/openclaw/data.json` inside the vault. If the user enables Obsidian Sync, the vault (including plugin data) is synchronized across devices, contradicting the claim.
- **Recommendation:** Update `SECURITY.md` to accurately describe the storage model and Sync implications. Consider deriving the private key from a user-supplied passphrase or using the OS keychain where available, if Obsidian APIs permit.

---

### 🟡 Medium

#### M1 — `main.js` is tracked in Git despite `.gitignore` and project policy
- **Files:** `.gitignore` (lists `main.js`), `AGENTS.md`, `main.js`
- **Risk:** Merge conflicts, accidental releases of unreviewed build artifacts, repo bloat, violation of stated agent policy.
- **Details:** `.gitignore` contains `main.js`, and `AGENTS.md` says: “Don’t commit generated artifacts (`main.js`) unless they changed meaningfully.” `git ls-files` confirms `main.js` is tracked and currently clean in the working tree.
- **Recommendation:** `git rm --cached main.js` and rely on release assets / CI artifacts. Update CI to verify the committed artifact matches the source build if you need reproducibility.

#### M2 — `ConfirmCloseModal` promise hangs when the modal is dismissed via Escape/overlay click
- **File:** `src/modals.ts` (~lines 56–113)
- **Risk:** UI action deadlocks; user cannot complete the tab reset/close they started.
- **Details:** `confirmTabClose` returns a `Promise<boolean>` that only resolves through the button click callbacks. `onClose()` only empties `contentEl`. If the user presses Escape, clicks the modal overlay, or uses an Obsidian-provided close affordance, the promise never resolves, leaving the async caller awaiting forever.
- **Recommendation:** Track whether the callback already fired and resolve/reject from `onClose()` as well.

#### M3 — `syncFromSettings` does not propagate a changed `sessionKey` to the active view
- **File:** `src/chat-view.ts` (line ~508)
- **Risk:** The Settings tab and the chat view fall out of sync; changing the conversation key in settings does not switch the active tab/history.
- **Details:** `syncFromSettings()` clears messages, reloads history, and re-renders tabs, but never updates `this.sessionKey` from `this.plugin.settings.sessionKey`. It therefore loads the history of the *old* session. The Settings tab already broadcasts `syncFromSettings()` whenever the session key changes.
- **Recommendation:** Add `this.sessionKey = this.plugin.settings.sessionKey || 'main'` at the top of `syncFromSettings()`.

#### M4 — README / manifest descriptions and command names are stale
- **Files:** `README.md`, `src/main.ts`, `manifest.json`
- **Risk:** User confusion; support burden; mismatched expectations.
- **Details:**
  - README says the plugin provides a **“chat sidebar”** and command **“OcO: Toggle chat sidebar”**; the code opens the view in a **document tab** (`getLeaf('tab')`) and the command is **“Open chat in new tab”**.
  - `manifest.json` description says “OpenClaw **tab** for Obsidian” while the README still calls it a sidebar.
  - README command list names differ from the actual registered command IDs/names in `main.ts`.
- **Recommendation:** Align README, manifest, and code; remove obsolete sidebar references.

#### M5 — `GatewayClient` reconnect behavior has gaps
- **File:** `src/gateway-client.ts` (`scheduleReconnect`, `stop`)
- **Risk:** Resource leakage and misleading connection state; connect errors are swallowed.
- **Details:**
  - `scheduleReconnect()` schedules a `window.setTimeout` but **does not store the timer handle**, so `stop()` cannot cancel it. While `this.closed` prevents reconnection, the timer still fires and there is no cap on attempts.
  - The `WebSocket` `error` listener is empty; `onConnectError` is not surfaced in the UI (`lastGatewayConnectError` in `main.ts` is written but never displayed).
- **Recommendation:** Store reconnect timer IDs and clear them in `stop()`; cap retries or implement exponential backoff with a max; surface the last error in the status UI.

#### M6 — No transport-security enforcement or warning for remote gateway URLs
- **Files:** `src/gateway-client.ts` (`normalizeGatewayUrl`), `src/settings-tab.ts`
- **Risk:** Credential and vault-content exposure if a user connects to an unencrypted gateway over a network.
- **Details:** `normalizeGatewayUrl` silently converts `http://` → `ws://` and `https://` → `wss://`. There is no UI warning that `ws://` is unencrypted, and the settings tab accepts arbitrary hosts. The security model assumes loopback, but the UI does not enforce or even warn about non-loopback `ws://`.
- **Recommendation:** Show a warning when the URL is non-loopback and not `wss://`; default to `wss://` for non-localhost hosts; document the loopback-only assumption.

#### M7 — `askAboutNote` can load arbitrarily large notes and does not resize the input
- **File:** `src/main.ts` (line ~253)
- **Risk:** UI freeze; poor mobile UX.
- **Details:** The active note’s entire content is inserted into the textarea with no size cap, and the `input` event is not fired, so the textarea is not auto-resized (the input row may show only one line of a huge message).
- **Recommendation:** Cap the inserted content (e.g., 16k chars) with a truncation notice; trigger the input/auto-resize logic after setting `value`.

#### M8 — `chat-view.ts` is a monolith with duplicated logic and dead methods
- **File:** `src/chat-view.ts` (~3,000 lines)
- **Risk:** High maintenance cost; inconsistencies between duplicated code paths; regressions.
- **Details:**
  - Tab actions exist as both private methods (`resetTabAction`, `closeTabAction`, `createNewTabAction`) and inline event handlers inside `_renderTabsInner`. The inline versions are used; the private methods are dead.
  - Many other methods are never called: `startRecording`, `stopRecording`, `finishRecording`, `playTTSAudio`, `compactSession`, `newSession`, `resetCurrentTab`, `contextColor`.
  - The class manages DOM, gateway RPC, state machines, tab logic, image resizing, audio playback, and touch gestures.
- **Recommendation:** Deduplicate tab actions into the existing private methods and delete unused code; split the view into focused modules (e.g., `tab-bar.ts`, `stream-renderer.ts`, `voice.ts`, `attachment-handler.ts`).

#### M9 — `streamItemsMap` is written but never read
- **Files:** `src/types.ts`, `src/chat-view.ts` (`handleChatEvent` final branch)
- **Risk:** Incomplete feature; wasted storage; user expectation mismatch.
- **Details:** `OpenClawSettings.streamItemsMap` is populated when a stream finalizes but is never restored on view open or tab switch. It accumulates data in `data.json` without benefit.
- **Recommendation:** Either implement restoration of persisted stream items on `loadHistory`/`restoreStreamUI`, or remove the field until persistence is designed end-to-end.

---

### 🟢 Low / Informational

#### L1 — Dead exports in `src/modals.ts` and `src/svgs.ts`
- **Details:** `_ConfirmModal`, `_TextInputModal`, `_AttachmentModal` are exported but unused. `SVG_HAMBURGER`, `SVG_CHEVRON_LEFT`, `SVG_CHEVRON_RIGHT`, `SVG_HOME_16`, `SVG_RESET_12` are also unused. They inflate the bundle slightly and add noise.
- **Recommendation:** Remove unused exports or keep them in a clearly marked “legacy” module.

#### L2 — Voice recording methods are dead code
- **File:** `src/chat-view.ts` (lines ~868–911, `startRecording`/`stopRecording`/`finishRecording`)
- **Details:** The send button comment says “Voice recording disabled - base64 in message text bloats context,” yet the methods remain. They also contain their own base64-in-text logic that contradicts the stated reason for disabling.
- **Recommendation:** Delete the methods and related CSS classes until voice is intentionally re-enabled.

#### L3 — `buildVoiceUrl` can produce a double slash
- **File:** `src/chat-view.ts` (line ~2724)
- **Details:** It returns `${httpUrl}/${voicePath}`. If `voicePath` begins with `/`, the result is `http://host//path`. Browsers usually tolerate this, but it is untidy and may confuse gateway routing.
- **Recommendation:** Normalize the slash between base URL and path.

#### L4 — `extractContent` regexes may strip legitimate user text
- **File:** `src/chat-view.ts` (`extractContent`, `cleanText`)
- **Details:** Patterns such as `^File saved at:.*$`, `^To send an image back.*$`, `^\[.*?GMT[+-]\d+\]\s*`, and metadata JSON fences are removed from *all* assistant messages. A legitimate note discussion containing those strings will be redacted in the UI.
- **Recommendation:** Move content filtering to the gateway, or gate these heuristics behind explicit markers that cannot collide with user content.

#### L5 — `loadHistory` hides the first user message by heuristic
- **File:** `src/chat-view.ts` (`loadHistory`)
- **Details:** It slices off `messages[0]` if it has `role === 'user'`, assuming it is a `/new` or `/reset` system prompt. If the gateway changes ordering or the first message is real user content, it disappears silently.
- **Recommendation:** Ask the gateway to omit internal system prompts from `chat.history` instead of post-processing in the plugin.

#### L6 — Build script auto-copies artifacts into adjacent `.obsidian/plugins/openclaw` directories
- **File:** `esbuild.config.mjs`
- **Details:** The production build walks up three parent directories looking for `.obsidian/plugins/openclaw` and overwrites `main.js`, `styles.css`, and `manifest.json`. Convenient for local dev, but surprising in CI or if a developer’s filesystem layout accidentally matches.
- **Recommendation:** Make the copy opt-in (e.g., an env var) so CI builds do not have side effects.

#### L7 — `isDesktopOnly: false` for a localhost-gateway plugin
- **File:** `manifest.json`
- **Details:** Mobile Obsidian can run the plugin, but the default gateway URL (`127.0.0.1`) and the required desktop OpenClaw gateway make mobile usage non-functional without a remote gateway and the same origin patch.
- **Recommendation:** Set `isDesktopOnly: true` until mobile support is intentionally validated.

#### L8 — Prettier is configured but not enforced; test files use different quote style
- **Files:** `.prettierrc`, `src/*.test.ts`
- **Details:** Test files use double quotes, while source files and `.prettierrc` use single quotes. Prettier is not installed as a dev dependency and there is no `format` check in CI, so style drift is inevitable.
- **Recommendation:** Add `prettier` to devDependencies and a format check to CI, or remove `.prettierrc` if not used.

#### L9 — `minAppVersion` may be too low for WebCrypto Ed25519
- **File:** `manifest.json`, `src/crypto.ts`
- **Details:** `minAppVersion` is `"1.0.0"`. Ed25519 support landed in Chromium later than the Electron version bundled with very old Obsidian. The code catches identity creation failure and falls back to token-only auth, which silently degrades device pairing.
- **Recommendation:** Raise `minAppVersion` to an Obsidian version with a Chromium that supports Ed25519, or surface a clear notice when device identity cannot be created.

#### L10 — `WelcomeModal` can open after plugin unload
- **File:** `src/main.ts` (`onload`)
- **Details:** The welcome modal is scheduled with `window.setTimeout(..., 500)` and is not cancelled in `onunload`. Rapidly disabling the plugin could cause a detached modal to open.
- **Recommendation:** Store the timer handle and clear it in `onunload`.

#### L11 — `AGENTS.md` claims there is no test suite
- **File:** `AGENTS.md`, `src/lib.test.ts`, `src/at-mention.test.ts`
- **Details:** The agent notes state: “No test suite yet. Build success (`npm run build`) is the smoke test.” In reality there are 42 passing unit tests run by `npm test`.
- **Recommendation:** Update `AGENTS.md` to reflect the existing tests and expectations.

---

## 4. Action Items

### 🔴 Critical / High

- [x] **H1 — Stop piping the gateway patch script into `sudo bash`.** Provide a checksum-verified install path or replace it with a manual patching guide / upstream fix.
- [x] **H2 — Validate gateway-controlled URLs before opening them externally.** Only allow `http://`/`https://` schemes; reject `javascript:`, `data:`, and custom schemes.
- [x] **H3 — Clarify credential/key storage in `SECURITY.md`.** The token and Ed25519 private key live in the vault’s `.obsidian/plugins/openclaw/data.json` and are synced with Obsidian Sync; update claims that they “never leave your machine.”

### 🟡 Medium

- [x] **M1 — Stop tracking the generated `main.js` artifact in Git.** Run `git rm --cached main.js` and rely on CI/release assets.
- [x] **M2 — Fix `ConfirmCloseModal` promise hang on Escape / overlay click.** Resolve the promise in `onClose()` when the button callback has not already fired.
- [x] **M3 — Fix `syncFromSettings()` to honor a changed `sessionKey`.** Set `this.sessionKey = this.plugin.settings.sessionKey || 'main'` before reloading history.
- [x] **M4 — Align README / manifest / code descriptions.** Remove stale “sidebar” wording and match command names to the actual registered commands.
- [x] **M5 — Harden `GatewayClient` reconnect behavior.** Store reconnect timer IDs so `stop()` can clear them, surface connection errors in the UI, and cap retry attempts.
- [x] **M6 — Add transport-security UI warnings for remote gateway URLs.** Warn when the URL is non-loopback and not `wss://`; default remote hosts to `wss://`.
- [x] **M7 — Cap `askAboutNote` content size and trigger input resize.** Avoid inserting arbitrarily large notes and failing to auto-resize the textarea.
- [x] **M8 — Refactor `chat-view.ts` and remove dead code.** Deduplicate tab-action logic into the existing private methods and delete unused recording/reset/context methods.
- [x] **M9 — Complete or remove `streamItemsMap` persistence.** Either restore persisted stream items on tab switch/view load, or delete the field.

### 🟢 Low / Informational

- [x] **L1 — Remove dead exports from `src/modals.ts` and `src/svgs.ts`.** Delete unused modal classes and SVG definitions, or move them to a legacy module.
- [x] **L2 — Delete dead voice-recording methods and CSS.** Remove `startRecording`/`stopRecording`/`finishRecording` and related classes.
- [ ] **L3 — Fix double-slash in `buildVoiceUrl`.** Normalize the slash between base URL and `voicePath`.
- [ ] **L4 — Make `extractContent` / `cleanText` filters safer.** Move gateway-specific stripping to the server, or gate behind explicit markers.
- [ ] **L5 — Stop hiding the first user message by heuristic in `loadHistory`.** Ask the gateway to omit internal `/new` / `/reset` prompts instead.
- [ ] **L6 — Make the esbuild copy-to-`.obsidian` step opt-in.** Avoid side effects during CI / production builds.
- [ ] **L7 — Consider setting `isDesktopOnly: true` in `manifest.json`.** Mobile requires a remote gateway and the same origin patch.
- [ ] **L8 — Enforce Prettier in CI.** Install `prettier` and add a format check; align test-file quote style with `.prettierrc`.
- [ ] **L9 — Review `minAppVersion` for WebCrypto Ed25519 support.** Raise it or surface a notice when device identity creation fails.
- [ ] **L10 — Cancel the `WelcomeModal` timer in `onunload`.** Prevent detached modals on rapid plugin disable.
- [ ] **L11 — Update `AGENTS.md` to reflect the existing test suite.** It currently says there is no test suite.

---

## 5. Positive Findings

- **No `innerHTML` or `eval`**: DOM construction uses Obsidian helpers (`createEl`/`createDiv`/`createSpan`, `ownerDocument.createElementNS` for SVGs), satisfying the ObsidianReviewBot guidelines stated in `AGENTS.md`.
- **Build, lint, typecheck, and tests pass** at the audited commit.
- **Auth design is reasonable**: token + per-device Ed25519 signatures + server nonce make replay and device spoofing hard, when the storage caveat is addressed.
- **Release attestation**: `.github/workflows/release-plugin.yml` uses `actions/attest-build-provenance` to sign release artifacts.
- **Pure, unit-tested helpers**: `lib.ts` and `at-mention.ts` isolate logic from Obsidian APIs and have good coverage.

---

## 6. Conclusion

The plugin works and ships with a sensible security *design*, but several **high-risk user-facing workflows** (patch install, gateway-controlled links, credential storage claims) need hardening before broader distribution. Medium-severity code bugs (hanging promises, stale session state, large note injection) and significant technical debt in `chat-view.ts` should be addressed to prevent regressions. The most important immediate actions are:

1. Remove or replace the `curl | sudo bash` patch path.
2. Sanitize gateway-controlled URLs before opening them.
3. Align `SECURITY.md` with the actual storage model.
4. Fix `ConfirmCloseModal` and `syncFromSettings`.
5. Stop committing `main.js`.
