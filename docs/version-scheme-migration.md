# Version-Scheme Migration — `.NN` → `MAJOR.MM`

> Target: production `1.00`, hotfixes `1.02`, `1.04`, …; major release `2.00`. Format
> `^\d+\.\d{2}$` (2-digit zero-padded minor), compared numerically as `(major, minor)`.
>
> **Status: MECHANISM SHIPPED (dual-format transition).** The hub now accepts BOTH `.NN`
> and `MAJOR.MM` (`_parse_nn`→tuple, `_is_nn`/`_isNN` dual, `_version_behind` tuple-compare),
> and every repo's `version-bump.yml` is format-aware (`minor+=2`, hold at `.98`, legacy
> `.NN` preserved). `scripts/set-version.sh` handles the coordinated major/cutover.
> **Not yet done:** the actual cutover (resetting VERSIONs to `1.00`) is the deliberate
> production milestone — run `set-version.sh 1.00` per repo when you're ready. **`nw` repo
> workflow still pending** (its checkout is divergent — update when synced). `cs` `.sh`
> `version=` headers left as-is (optional, §D).

## TL;DR
The **update delivery** is keyed on git commit SHA, not version — the spoke fan-out's
primary gate (`last_pushed[sid] == remote_tip`) and BugFixer's self-update (`old_commit !=
new_commit`) both ignore the version string. So versions are used only for **display
("out of date" chips)**, a **corrective re-push evidence override**, and a hub-self-update
**fallback**. That makes this a **display + bump-automation** change, low-risk for the
update engine — but there are two regex traps that would visibly break the fleet on
cutover if missed.

## The two traps (must fix, or the whole fleet mis-renders)
1. **`version_skew` false-positive → entire fleet shows "out of date" at cutover.**
   `_is_nn("1.00")` is **False** (`^\.\d+$` needs a leading dot). Skew fires for every
   spoke reporting `1.00`. Fix all three format checks (below) *before* any VERSION is
   reset to `1.00`.
2. **`version_behind` silently stops detecting drift.** `_parse_nn("1.00")` → `None` →
   `_version_behind` always False → the genuine "spoke older than its repo" signal AND the
   corrective re-push (`update_pipeline.py:1494`) go dark. Fix `_parse_nn` to return a
   `(major, minor)` tuple. Footgun: a lazy fix (strip dot, `int` the digits) makes
   `1.00→100`, `2.00→200` order correctly *by luck* and masks the real requirement — use a
   tuple.

---

## A. Hub parse / compare / display (lm repo)

Change the format checks to `^\d+\.\d{2}$` and make the parser return a tuple:

1. `core/src/routes/setup_admin.py:103-104` — `_is_nn` regex `^\.\d+$` → `^\d+\.\d{2}$`.
2. `core/src/update_pipeline.py:140-147` — `_parse_nn`: regex + **return `(major, minor)` tuple** (not int).
3. `WebUI/main.js:13326` — `_isNN` regex (mirror of #1; used at `:13359` for pxmx agents).

No logic change, but **verify** once #2 returns tuples:
4. `core/src/update_pipeline.py:150-162` — `_version_behind`: `r < l` works unchanged on tuples; keep the `None` guard. Update the docstring.
5. `core/src/update_pipeline.py:363, 369, 436` — `latest_version_for_module` + GitHub-cache validity gates (`_parse_nn(...) is not None`) — now accept the new format automatically once #2 lands.

Behavior that **re-activates** (was inert under `.NN`) — confirm intended:
6. `core/src/update_pipeline.py:217-224` `_ver` and `core/src/update_recovery.py:149-158`
   `_ver_tuple` already do numeric-tuple compare (they returned `(0,0,0)` for `.NN`, i.e.
   dead). Under `MAJOR.MM` they start ordering correctly, which re-arms `ver_ahead`
   (`update_pipeline.py:248`) in the hub self-update decision. Previously the hub relied on
   commit SHA; make sure a live `ver_ahead` is desired (it is correct, just newly active).

Format-agnostic — **no change** (verified): `get_local_version`, `_read_version_cached`,
`get_remote_version`, spoke_versions store (`main.py:4618`), `_compute_version_drift`
(`main.py:5859`), `_webui_version` (`api.py:978`), footer render (`main.js:2337`), spoke
reporters (`agent_spoke.py:1198`, `console_spoke.py:427`).

Tests encoding the old scheme: `core/tests/test_version_behind.py` (`.400/.486/.612`
literals), `test_version_drift.py`, `test_update_gate.py`,
`test_spoke_update_fanout_gating.py:253`.

Docs/comments still saying `.NN`: `setup_admin.py:94-104,184-204`;
`update_pipeline.py:124-127,165-190,377`; `main.js:13236-13245,13322-13325`.

---

## B. Bump automation (the CRITICAL rewrite — 11 files)

Every repo except **truenas** carries an identical `.github/workflows/version-bump.yml`
that fires on push to `main` and does **`int(last-numeric-run) + 1`**, zero-pad-preserving,
**no carry** (`0.99→0.100`). It bumps *every* tracked `VERSION` file (`git ls-files | grep
VERSION`) — in lm that's 9 files per push.

Rewrite the increment to: **minor += 2**, output `MAJOR.MM` (2-digit minor), and:
- **Never auto-cross a major.** `X.98 + 2` must **stop/hold**, not roll to `(X+1).00`.
  Major (`X.00`) is set **by hand**. (Hotfix range per major = `.00 .02 … .98` = 50 slots.)
- Guard the format: refuse to write anything not matching `^\d+\.\d{2}$`.

Files to rewrite (identical logic in each):
1. `lm/.github/workflows/version-bump.yml`
2. `bugfixer/.github/workflows/version-bump.yml`
3. `cs/.github/workflows/version-bump.yml`
4. `pxmx/.github/workflows/version-bump.yml`
5. `nw/.github/workflows/version-bump.yml`
6. `netbox/.github/workflows/version-bump.yml`
7. `opnsense/.github/workflows/version-bump.yml`
8. `cppm/.github/workflows/version-bump.yml`
9. `ldap/.github/workflows/version-bump.yml`
10. `le/.github/workflows/version-bump.yml`
11. `bugfixer/github_ops.py` — `bump_repo_version()` (lines 180-219), BugFixer's in-code
    reimplementation used when it pushes an AI fix. Change the same increment logic **and**
    the seed `new_version = "0.01"` (line 206) → `"1.00"`.

**truenas has NO workflow** (no `.github/`); its `VERSION` = `1.0` is hand-set and never
auto-bumps. Add a workflow if it should participate.

---

## C. VERSION files to reset to `1.00` at cutover

Sibling repos (single file each): `bugfixer` (0.71), `cs` (.435), `pxmx` (.173), `nw`
(.39), `netbox` (.72), `opnsense` (.40), `cppm` (.35), `ldap` (.26), `le` (.14),
`truenas` (`1.0` → `1.00` — note it's one-digit today, fails the format).

**lm has 9 tracked VERSION files, currently inconsistent** (decision required, see §F):
`VERSION`=`0.29`; `WebUI/`,`agent/`,`client_sim/`,`core/`,`dhcp/`,`dns/` = `.1250`;
`console/`=`1.0.1049` (X.Y.Z); `statuspage/`=`0.1.667` (X.Y.Z).

---

## D. `.sh version=` headers (cs repo only — ~20, inconsistent, no automation)

Only `cs` uses a `version=` header, and nothing bumps them (hand-maintained). Formats are a
mix (`version=.01`, `version=1.0`, `version=1.6`, `version=".11"`, `VERSION="0.17"`,
`VERSION=1.11`) across `cs/clients/linux/*.sh`, `cs/svr-mgmt/clone.sh`,
`cs/proxmox/clone.sh`, `cs/installers/install*.sh`. If they must conform to `^\d+\.\d{2}$`,
that's a **manual pass** (or leave them — they're per-script, not the fleet version).

---

## E. BugFixer specifics

- Its self-update is **SHA-based** (`workers.py` `old_commit != new_commit`), so the
  migration does **not** break its update trigger — VERSION is display-only for it.
- But the hub renders it "out of date" today purely because `0.72` isn't `.NN`
  (`version_skew`), and the hub never computes a "latest" for it (its module_type isn't in
  `_MODULE_REPO_DIR` → `version_behind` always False). After migrating BugFixer to `1.00`,
  the skew flag clears **only if the §A regexes are fixed**. Alternatively, special-case
  deploy-role module_types to suppress skew.
- `github_ops.py` `bump_repo_version` + `"0.01"` seed must change with the workflows (§B.11).

---

## F. Chosen model: per-repo independent MINOR, fleet-coordinated MAJOR

**Decided.** Each repo versions **independently on the MINOR** (its own auto-bump, `minor
+= 2` per hotfix), so at any time components legitimately differ within a major — e.g. `cs`
at `2.30` while `nw` is `2.14`. The **MAJOR is a fleet-wide milestone**: cutting `V2.00`
sets **every** repo's VERSION to `2.00` at once (a coordinated hand action, §H), after which
each repo's minor drifts independently again.

This keeps the existing architecture intact — the hub already fetches *each repo's* `raw
.../<repo>/main/VERSION` and compares a spoke only to **its own repo's** latest
(`update_pipeline.py:165-190`). So **no `update_pipeline` compare refactor** — only the
parser regex (§A) + bump scripts (§B). The `(major, minor)` tuple compare (§A.2) naturally
handles the major boundary: a spoke on `1.98` vs its repo's new `2.00` orders `(1,98) <
(2,00)` → correctly "behind" during a major rollout.

Within **lm**, the 9 tracked VERSION files reset to `1.00` together and the lm workflow
bumps all 9 on each push, so they stay in lockstep inside the repo (fine — one repo, one
minor). No collapse needed.

## H. Major-release coordination (`V X.00`)

The auto-bump **never touches the MAJOR** — it only advances MINOR and holds at `.98`. A
major release is therefore an explicit, coordinated action across all repos. Provide a small
release script (run once per major):

- For every repo (lm + siblings), write `X.00` to each tracked VERSION file (`git ls-files
  | grep -E '(^|/)VERSION$'` — 9 files in lm, 1 elsewhere).
- Commit `release vX.00 [skip ci]` and push. The `[skip ci]` (and the fact that the bump
  workflow ignores non-`chore: bump version` commits) stops the workflow from immediately
  bumping the minor off `.00`.
- truenas needs its workflow added first (§B) or its VERSION set by hand.

After the release commit, each repo resumes independent `X.02`, `X.04`, … on its own pushes.

---

## G. Cutover ordering (do this, or the fleet flashes "out of date")

1. **Ship the hub parser changes first** (§A), ideally accepting **both** `.NN` *and*
   `MAJOR.MM` during the transition, so nothing flips to "out of date" mid-migration.
2. Roll out the **new bump workflows** (§B) and **reset VERSION files to `1.00`** (§C)
   per repo. Because delivery is SHA-based, spokes update on the commit regardless; the
   version chip is correct only once #1 is deployed.
3. **BugFixer:** migrate its VERSION + `github_ops.py`, or suppress deploy-role skew.
4. Update tests + docs (§A) so CI is green.
5. Majors (`2.00`) remain a **hand edit** to VERSION; the workflow never crosses a major.
