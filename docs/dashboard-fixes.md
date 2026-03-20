# Dashboard Fixes — SSE Reconnecting & Policy Update

**Date:** 2026-03-20
**Phase:** 10 (Hardened Cgroup Agents)
**Affected components:** Web Dashboard (guardian binary)

---

## Issues

### 1. Dashboard always shows "Reconnecting..."

The SSE (Server-Sent Events) connection status indicator on the Overview and Events pages permanently displayed "Reconnecting..." even though the SSE stream was working correctly on the server side.

### 2. Policy update from dashboard has no effect

Editing agent policies (file access rules, exec policy default/allow/deny) on the `/policy` page and clicking "Save Policy" produced no feedback and did not persist changes. The URL bar showed the form data as query parameters — a clear sign of a regular GET form submission instead of an AJAX request.

---

## Root Causes

### SSE "Reconnecting" — Two independent causes

**Cause A: Race condition on page load**

The SSE connection (`EventSource`) is created in an inline `<script>` IIFE in `base.html`. Alpine.js is loaded with `defer`, so it initializes *after* the DOM is fully parsed. If the SSE `onopen` event fires before Alpine registers its `guardian:sse-open` listener, the `connected` state is never set to `true`.

Timeline of the race:
```
1. base.html IIFE runs → EventSource('/events/stream') created
2. SSE connection opens → sse.onopen fires → dispatches 'guardian:sse-open'
   ↑ No Alpine listener registered yet — event is lost
3. Alpine.js loads (defer) → component init() runs
4. init() checks readyState — may or may not be OPEN at this exact moment
5. Registers listener for 'guardian:sse-open' — but the event already fired
6. connected stays false → "Reconnecting..." displayed forever
```

**Cause B: Aggressive error state on normal reconnects**

The `EventSource.onerror` callback fired on *any* error, including the normal browser auto-reconnect cycle. Even a momentary reconnect (e.g., TCP keepalive timeout) would immediately set `connected = false`, and the UI showed "Reconnecting..." before `onopen` could fire again. With high event volume (30+ events/sec from Claude Code monitoring), brief reconnects were frequent.

### Policy Update — SRI integrity hash mismatch

The htmx library was loaded from the unpkg CDN with a Subresource Integrity (SRI) hash:

```html
<script src="https://unpkg.com/htmx.org@2.0.4"
        integrity="sha384-M06VwgoUOHG3FN0UchwWKqh9jS4ejwpoL0yjF3EVljtsxFwFETEYMkyNL5lXbJ5/"
        crossorigin="anonymous"></script>
```

The actual SHA-384 hash of the file served by unpkg was:
```
sha384-HGfztofotfshcF7+8n44JQL2oJmowVChPTg48S+jvZoztPfvwD79OC/LTtG6dMp+
```

These did not match. The browser's SRI check **silently blocked htmx from loading**. Without htmx:

- All `hx-put`, `hx-post`, `hx-get` attributes were ignored
- The `<form hx-put="/api/policy/...">` had no `action` or `method` attributes
- The browser fell back to a default GET submission to the current URL
- The policy page reloaded with form data as query parameters (visible in the URL bar)
- No data was sent to the API endpoint — the update never happened

This also broke: the "Reload Config" sidebar button, the auto-refreshing status cards, agent stop/grant buttons, and alert configuration saves.

---

## Fixes Applied

### Fix 1: Embed htmx and Alpine.js locally

**Files changed:**
- `guardian/static/htmx.min.js` — new file (htmx 2.0.4, 51KB)
- `guardian/static/alpine.min.js` — new file (Alpine.js 3.14.8, 45KB)
- `guardian/templates/base.html` — updated script tags

**Before:**
```html
<script src="https://unpkg.com/htmx.org@2.0.4" integrity="sha384-..." crossorigin="anonymous"></script>
<script defer src="https://unpkg.com/alpinejs@3.14.8/dist/cdn.min.js" integrity="sha384-..." crossorigin="anonymous"></script>
```

**After:**
```html
<script src="/static/htmx.min.js"></script>
<script defer src="/static/alpine.min.js"></script>
```

**Why:** Eliminates CDN dependency entirely. The files are embedded into the guardian binary via `rust-embed` at compile time. The dashboard now works fully offline — no internet required. SRI hash mismatches can never occur.

**Trade-off:** Binary size increases by ~96KB (compressed). This is negligible for a security daemon.

### Fix 2: Remove unused htmx-ext-sse extension

**File changed:** `guardian/templates/base.html`

Removed the `htmx-ext-sse@2.2.2` script tag. The SSE connection is managed by custom JavaScript (EventSource API), not htmx's SSE extension. The extension was loaded but never used (no `hx-ext="sse"` or `sse-connect` attributes in any template). Removing it eliminates a potential source of interference and one fewer CDN dependency.

### Fix 3: SSE connection state tracking with debounce

**Files changed:**
- `guardian/templates/base.html` — SSE IIFE rewritten
- `guardian/templates/index.html` — init() updated
- `guardian/templates/events.html` — init() updated

**Changes to base.html IIFE:**

1. **Window-level state tracking:** `window.__guardianSSEConnected` is set in `onopen`/`onerror` callbacks so Alpine components can read the state even if the event was dispatched before their listener was registered.

2. **Debounced error state:** Instead of immediately marking as disconnected on `onerror`, a 2-second timer starts. If `onopen` fires within 2 seconds (normal reconnect), the timer is cancelled and the status stays "Connected". Only persistent disconnections (>2s) show "Reconnecting...".

3. **Event-based auto-recovery:** Receiving any SSE data event (`event` or `permission`) automatically sets `connected = true`, regardless of whether `onopen` was missed.

**Changes to index.html and events.html:**

1. **Initial state from window:** `self.connected = window.__guardianSSEConnected || readyState === OPEN` handles the race condition where `onopen` fires before Alpine init.

2. **Periodic self-heal:** A 3-second `setInterval` checks `EventSource.readyState` directly and corrects `connected = true` if the connection is open. This catches any edge cases where both the event and the window flag were missed.

### Fix 4: Policy update — POST fallback and auto-reload

**Files changed:**
- `guardian/templates/policy.html` — form attributes updated
- `guardian/src/dashboard/mod.rs` — route updated
- `guardian/src/dashboard/routes/api.rs` — handler updated

1. **POST route added alongside PUT:** The policy endpoint now accepts both `PUT` (htmx) and `POST` (fallback) methods.

2. **Auto-reload after save:** The form now includes `hx-on::after-request` to reload the page 1.5 seconds after a successful save, giving visual confirmation that the policy was applied.

3. **Config reload after write:** After writing the config to disk, the handler now re-reads the config file into memory to ensure consistency. The success message changed from "Send SIGHUP or use reload to apply" to "Policy saved and applied."

### Fix 5: Config serialization completeness

**File changed:** `guardian/src/dashboard/routes/api.rs` (`write_config_toml`)

Added serialization for fields that were previously silently dropped when saving config from the dashboard:

| Field | Section | Risk if lost |
|-------|---------|-------------|
| `auth_token` | `[dashboard]` | Dashboard becomes unauthenticated after save |
| `network_policy` | `[[agents]]` | Network deny/allow ports lost |
| `fail_closed` | `[[agents]]` | Fail-closed enforcement disabled |

---

## Verification

After rebuilding and restarting the daemon:

1. **SSE status:** Overview and Events pages should show "Live" / "Connected" within 3 seconds of page load
2. **Policy update:** Edit any agent's policy on `/policy`, click "Save Policy" → green toast appears → page auto-reloads with updated values
3. **Offline operation:** Dashboard works without internet access (no CDN requests in browser dev tools Network tab)
4. **htmx features:** "Reload Config" sidebar button works, status cards auto-refresh every 5s, agent stop/grant buttons work

---

## Files Modified

| File | Change |
|------|--------|
| `guardian/static/htmx.min.js` | New — embedded htmx 2.0.4 |
| `guardian/static/alpine.min.js` | New — embedded Alpine.js 3.14.8 |
| `guardian/static/app.js` | Cleaned up dead htmx-ext-sse code |
| `guardian/templates/base.html` | Local JS, SSE debounce, removed htmx-ext-sse |
| `guardian/templates/index.html` | Robust SSE connected state |
| `guardian/templates/events.html` | Robust SSE connected state |
| `guardian/templates/policy.html` | Auto-reload after save |
| `guardian/src/dashboard/mod.rs` | POST fallback route for policy |
| `guardian/src/dashboard/routes/api.rs` | Config reload after save, serialization fixes |
