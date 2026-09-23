---
summary: "Mandatory caching contract: every cache uses core/src/cache_core.py — one debounced atomic writer (JsonCacheFile) and one staleness ladder (StalenessPolicy), so 'cached' means the same thing on every page."
keywords: [cache, cache_core, caching, contract, debounce, JsonCacheFile, le_cache, lm, nw_cache, persistence, stale, StalenessPolicy, truenas_cache, warm_cache]
---

# Caching Contract (every module)

**Status: MANDATORY.** Applies to every hub module that keeps data between
requests. Audience: developers adding or modifying a cache.

When a feature says "this data is cached", that must mean one specific thing.
Before `cache_core` it meant five different things: four modules had each grown
their own copy of the persist logic (`truenas_cache` was a verbatim clone of
`nw_cache`), two of them had no write debounce at all, and the only real
staleness thresholds in the platform lived in the console routes. A fix or a
tuning change landed in one copy and silently missed the rest.

So: **do not write cache persistence or age comparisons by hand.** Use
`core/src/cache_core.py`.

## The two pieces

### `JsonCacheFile` — how it reaches the disk

Owns *no* data. You give it a label, a callable returning the file path, and a
**snapshot function** that returns the thing to serialize; it owns the writing.

```python
self._nw_cache_file = JsonCacheFile(
    "nw cache", self._nw_cache_path,
    lambda: {"fleet": self.nw_fleet_cache, "devices": self.nw_device_cache},
    flush_delay_s=self._NW_CACHE_FLUSH_DELAY_S)
```

- `schedule_save()` — mark dirty. A burst of N writes produces **one** file
  write at most every `flush_delay_s` (default 5s), not N full dumps. Call it
  freely on every set; that is the point.
- `flush_now()` — skip the coalescing window and write now. **Shutdown paths
  must call this**, or the last few seconds of writes die with the process.
- `load()` — rehydrate on startup. **Never raises**: a missing, truncated, or
  non-JSON file degrades to a cold start (empty cache, UI 503s once, first live
  fetch repopulates) rather than taking the hub down with it.

The write is atomic (`tmp` file then `os.replace`) and the file is **0600** —
caches hold fleet topology, MAC tables and cert metadata, so owner-only is not
optional. Snapshots are taken *at write time*, so the file always reflects the
latest state rather than whatever was current when the save was queued.

### `StalenessPolicy` — how old is too old

Three thresholds, because "is this stale" is really three different questions
and collapsing them is what produced the `Timed out waiting for spoke response`
error pages:

| threshold | default | meaning |
|---|---|---|
| `refresh_after_s` | 30s | Still serve it, but kick off a background refresh. |
| `stale_after_s` | 120s | Still serve it, but **badge it** in the UI. |
| `expire_after_s` | 86400s | Too old to be worth showing; now you may error. |

`classify(fetched_at)` returns `fresh` / `refresh` / `stale` / `expired` /
`missing`. Routes call that instead of comparing ages themselves.

`missing` is deliberately distinct from `fresh`: a never-populated cache has
`fetched_at == 0.0`, and a naive `now - fetched_at` comparison would have to be
written carefully every single time to avoid reporting a cold start as current
data. Clock skew (a `fetched_at` in the future) is clamped rather than trusted.

## The rules

1. **One cache module per data source, and it is a leaf.** `cache_core` imports
   stdlib only (there is a test asserting this). Cache modules must not import
   routes or the hub; keep them importable from anywhere.
2. **Store the raw envelope**, not a rendered or filtered view. The same cache
   entry gets read by callers with different tenant scopes — filter on the way
   *out* (see `_filter_nw_optional`), never on the way in, or you will persist
   one tenant's view and serve it to another.
3. **Serve stale data when the source is unreachable.** A disconnected spoke is
   the case caching exists for. Serve the cache, mark it stale, and let the UI
   badge it; only `expired` justifies an error.
4. **Wire the shutdown flush.** If a new cache mixin joins `LabManagerHub`, add
   its `*_cache_flush_now()` to the shutdown path alongside
   `hub.nw_cache_flush_now()`.
5. **Don't re-tune thresholds per page.** If a data source genuinely needs a
   different ladder, pass an explicit `StalenessPolicy`, don't open-code an age
   check in the route.

## Modules on the contract

`nw_cache` (fleet + per-device), `truenas_cache` (fleet + per-appliance),
`le_cache` (certs/status), and `warm_cache` (generic, namespaced — used by the
console port list and Proxmox VM list). Each exposes `*_cache_load()`,
`*_cache_flush_now()` and a `*_state()`/`*_cache_*_state()` staleness verdict.

`core/tests/test_cache_modules_shared.py` asserts the uniformity across all
four — restart survival, debounce, 0600 + valid JSON, and a shared policy — so
a new cache that skips `cache_core` should be added there and will fail loudly.
