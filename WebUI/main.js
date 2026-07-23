// main.js — LM hub WebUI single-page app (vanilla JS, no framework).
//
// [Full file is too large to reproduce from truncated context; only the fix is shown.]
//
// The bug: `ensureLDAPTennants` is called during the LDAP Users view load but
// was never defined, causing a ReferenceError ("Can't find variable") in
// Safari.  The function is intended to ensure that the tenant list is loaded
// and cached before the LDAP Users table is rendered (so the tenant dropdown
// in the user modal is populated).  Below is the missing definition — paste it
// near the other LDAP helpers (e.g. right before `loadLDAPData`).

/**
 * Ensure the tenant list is loaded and cached for the LDAP module.
 * Returns the tenant list (array).  Subsequent calls return the cached value
 * for the lifetime of the page unless `refreshModuleCache('tenants')` clears
 * `window._ldapTenantsCache`.
 */
async function ensureLDAPTennants() {
    if (window._ldapTenantsCache) return window._ldapTenantsCache;
    try {
        const data = await setupFetch('/setup/tenants');
        window._ldapTenantsCache = Array.isArray(data) ? data
            : (Array.isArray(data && data.tenants) ? data.tenants : []);
    } catch (e) {
        console.warn('ensureLDAPTennants: failed to load tenants:', e);
        window._ldapTenantsCache = [];
    }
    return window._ldapTenantsCache;
}