// update_handler.js — client side of the hub/spoke "Update All" flow.
//
// POST /setup/update -> core/src/main.py perform_update (orchestrates the
// git pull + service restart for the hub and/or spokes). When the hub itself
// restarts (status === 'success'), _waitForHubReadyThenReload() polls
// /status until the new process is ready, mirroring the server-side restart
// watchdog in /usr/local/bin/lm-update-restart (which snapshots pre-swap and
// rolls back on boot failure — see core/src/update_recovery.py).
async function triggerUpdate(evt) {
    // Defense-in-depth: the footer button is only rendered for admins and the
    // /setup/update route enforces admin server-side (403), but bail here too
    // so a non-admin can never trigger the action from the client.
    if (typeof isAdmin === 'function' && !isAdmin()) {
        if (typeof showToast === 'function') showToast('Admin access required to run an update.', 'error');
        return;
    }
    const btn = (evt && evt.currentTarget) || document.getElementById('update-btn');
    if (!btn) return;

    const originalText = btn.textContent;
    btn.disabled = true;
    btn.textContent = 'Updating...';
    btn.classList.add('opacity-50', 'cursor-not-allowed');

    try {
        const response = await fetch('/setup/update?force_spokes=true', { method: 'POST' });
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Update failed');
        }
        const data = await response.json();
        if (typeof showToast === 'function') {
            showToast(data.message || 'Update triggered.', data.status === 'success' ? 'success' : 'info');
        }

        // Only the hub-restart path (status === 'success') actually restarts the
        // server; a spoke-only trigger ('checked'/'no_update') does not, so
        // re-enable the button instead of reloading (the toast already reported it).
        if (data.status === 'success') {
            // The hub is restarting. Reloading on a fixed delay risks landing on
            // the still-down (or still-starting) server → browser "page cannot be
            // displayed", followed by a manual re-login. Instead, poll /status:
            // it returns 503 while the hub is starting and 200 once ready. We only
            // reload after observing the restart actually happen (the old process
            // stops responding) AND the new process reports ready — so we never
            // reload the pre-restart process, and never reload a half-up server.
            _waitForHubReadyThenReload(btn);
        } else {
            btn.disabled = false;
            btn.textContent = originalText;
            btn.classList.remove('opacity-50', 'cursor-not-allowed');
        }
    } catch (err) {
        if (typeof showToast === 'function') showToast('Critical Error: ' + err.message, 'error');
        btn.disabled = false;
        btn.textContent = originalText;
        btn.classList.remove('opacity-50', 'cursor-not-allowed');
    }
}

// Poll /status until the hub has restarted and is ready, then reload.
//
// Phases (driven by the /status response, which is 200 when ready and 503
// while the WebSocket server is still starting; a network error means the old
// process has exited and the new one is not yet listening):
//   1. Wait for the restart to begin: the old process keeps returning 200, so
//      keep polling (sawDown stays false) until /status stops being 200.
//   2. Once we see a non-200 (network error or 503), mark sawDown — the
//      restart is in progress.
//   3. Reload the instant /status returns 200 again (new process ready).
//
// If the hub never comes back within maxWait, reload anyway as a best-effort
// fallback so the user is not left on a stuck "Restarting…" button.
function _waitForHubReadyThenReload(btn) {
    let sawDown = false;
    let elapsed = 0;
    const interval = 1500;      // poll every 1.5s
    const maxWait = 120000;     // give up and reload after 2 min
    const setLabel = (t) => { if (btn) btn.textContent = t; };

    const tick = async () => {
        elapsed += interval;
        if (elapsed > maxWait) {
            setLabel('Reloading…');
            window.location.reload();
            return;
        }
        let status = 'down'; // 'ready' (200) | 'starting' (any non-200 response) | 'down' (network error)
        try {
            const r = await fetch('/status', { credentials: 'same-origin' });
            status = r.ok ? 'ready' : 'starting';
        } catch (e) {
            status = 'down';
        }
        if (status !== 'ready') {
            sawDown = true; // restart is in progress (old process gone or new one starting)
            setLabel(`Restarting… (${Math.round(elapsed / 1000)}s)`);
            setTimeout(tick, interval);
            return;
        }
        // /status is 200. If we already saw the restart begin, the new process
        // is ready — reload. Otherwise the old process is still up and the
        // restart hasn't started yet; keep waiting.
        if (sawDown) {
            setLabel('Reloading…');
            window.location.reload();
        } else {
            setLabel(`Restarting… (${Math.round(elapsed / 1000)}s)`);
            setTimeout(tick, interval);
        }
    };
    // Small initial delay so the restart has a moment to begin before polling.
    setTimeout(tick, 1000);
}