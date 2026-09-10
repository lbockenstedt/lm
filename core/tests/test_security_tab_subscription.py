"""The Threat Monitor subscription has to be findable in the Security tab.

The tile was correct but placed last, below a sixty-row event table, and named
for the mechanism ("Data Subscription") rather than for the thing an operator
is looking for. Both are the kind of regression that no functional test would
catch and that makes a feature effectively absent.

There is no browser in this suite, so these read main.js as text. That is
enough for the two properties that matter: the tile is rendered by the Security
view, and it is rendered above the tables rather than beneath them.
"""
import os
import re

import pytest

MAIN_JS = os.path.join(os.path.dirname(__file__), "..", "..", "WebUI", "main.js")


@pytest.fixture(scope="module")
def js():
    with open(MAIN_JS, encoding="utf-8") as f:
        return f.read()


@pytest.fixture(scope="module")
def security_render(js):
    """The body of loadSecurityData(), which builds the Security tab."""
    start = js.index("async function loadSecurityData()")
    end = js.index("\n}", start)
    return js[start:end]


def test_the_subscription_tile_is_rendered_by_the_security_tab(security_render):
    """Not merely defined somewhere — actually placed into #security-content."""
    assert "security-content" in security_render
    assert "subscription-card" in security_render
    assert "${subCard}" in security_render


def test_the_tile_is_named_for_what_an_operator_is_looking_for(js):
    """"Data Subscription" describes the mechanism. Someone hunting for the
    shared threat feed searches for the threat monitor."""
    assert "Threat Monitor Subscription" in js
    assert "Data Subscription" not in js


def test_the_tile_sits_above_the_tables_not_below_them(security_render):
    """Placed last it fell under a sixty-row event table, where nobody scrolls.
    It is a configuration decision and belongs with the config."""
    order = re.findall(r"\$\{(stats|cfg|subCard|manualBlock|blockedTile|neverTile|events|extSrc)\}",
                       security_render)
    assert "subCard" in order, order
    assert order.index("subCard") < order.index("events"), order
    assert order.index("subCard") < order.index("blockedTile"), order
    # Directly under the Threat Monitor config it extends.
    assert order.index("subCard") == order.index("cfg") + 1, order


def test_the_subscription_is_loaded_when_the_tab_is_built(security_render):
    """A tile that renders a permanent "Loading…" because nothing fetches it is
    worse than no tile."""
    assert "_loadSubscription()" in security_render


def test_every_button_in_the_tile_has_a_handler(js):
    """onclick names are strings; a renamed function fails silently in the
    browser with nothing but a console error."""
    start = js.index("async function _loadSubscription()")
    end = js.index("// ── IP origin enrichment", start)
    tile = js[start:end]
    for handler in set(re.findall(r'onclick="(\w+)\(', tile)):
        assert re.search(rf"(async )?function {handler}\s*\(", js), \
            f"{handler} is referenced by the tile but never defined"


def test_the_tile_offers_no_way_to_change_where_data_is_sent(js):
    """A tenant chooses which data, never where from. An input for the service
    URL would be the UI half of a redirect the backend already refuses."""
    start = js.index("async function _loadSubscription()")
    end = js.index("// ── IP origin enrichment", start)
    tile = js[start:end]
    for forbidden in ('id="sub-url"', 'id="sub-service-url"', 'id="sub-base-url"'):
        assert forbidden not in tile
    # Nor is it displayed. The address is not a tenant's business: it is fixed
    # at build time, so printing it only invites someone to try to change it
    # and gives a reader of a shared screen one more thing to write down.
    assert "service_url" not in tile


def test_the_extension_source_tile_is_gone_from_the_security_page(js, security_render):
    """The operator-facing loader for private modules was removed from the
    Security page.

    It was the last place in the UI that presented "fetch code from a private
    repo" as a normal thing to configure, which is exactly the habit the move
    to a data subscription was meant to end. The backend routes stay so an
    install that already has a token and a checkout can still be purged, but
    nothing offers to set one up.
    """
    for gone in ("ext-src-card", "extSrc", "_loadExtSource",
                 "saveExtSource", "provisionExtSource", "purgeExtSource",
                 "Extension Source"):
        assert gone not in js, f"{gone} is still present in main.js"
    assert "ext-source" not in security_render


def test_the_security_tab_renders_only_tiles_it_still_defines(security_render):
    """A ${name} left in the template after its const is deleted renders the
    literal string "undefined" into the page."""
    used = set(re.findall(r"\$\{(\w+)\}", security_render.split("el.innerHTML = `")[1]
                          .split("`;")[0]))
    for name in used:
        assert re.search(rf"\bconst {name}\b", security_render), \
            f"the template uses ${{{name}}} but nothing defines it"
