import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from warm_cache import WarmCacheMixin  # noqa: E402


class _H(WarmCacheMixin):
    cache_dir = "."


def test_warm_drop_invalidates_only_matching_spoke_and_namespace(tmp_path):
    h = _H()
    h.cache_dir = str(tmp_path)
    h.warm_cache_init()

    async def run():
        await h.warm_set("netsvc_dhcp_list_res", "s1|abc", {"a": 1})
        await h.warm_set("netsvc_dhcp_list_res", "s2|abc", {"a": 2})
        await h.warm_set("netsvc_dhcp_list_res", "merge|abc", {"a": 3})
        await h.warm_set("other_ns", "s1|abc", {"a": 4})
        return h.warm_drop("netsvc_", ("s1|", "merge|"))

    assert asyncio.run(run()) == 2
    assert h.warm_get("netsvc_dhcp_list_res", "s1|abc") is None
    assert h.warm_get("netsvc_dhcp_list_res", "s2|abc") == {"a": 2}
    assert h.warm_get("other_ns", "s1|abc") == {"a": 4}


def test_warm_invalidate_keeps_last_known_data(tmp_path):
    h = _H()
    h.cache_dir = str(tmp_path)
    h.warm_cache_init()

    async def run():
        await h.warm_set("netsvc_x", "s1|abc", {"a": 1})
        return h.warm_invalidate("netsvc_", ("s1|",))

    assert asyncio.run(run()) == 1
    assert h.warm_get("netsvc_x", "s1|abc") == {"a": 1}
    assert h.warm_state("netsvc_x", "s1|abc") == "missing"
    assert h.warm_last_fetched_at("netsvc_x", "s1|abc")


def test_default_badge_threshold_is_five_minutes():
    from cache_core import DEFAULT_STALE_AFTER_S
    assert DEFAULT_STALE_AFTER_S == 300.0
