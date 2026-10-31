"""main.js + js/*.js load as one app; index.html must load every part.

A js/*.js file missing from index.html would never run, and its functions
would only fail when a user clicks something. The error guard in index.html
treats the app as initialized only once the LAST part has run, so a missing
or broken part still triggers the reload-once recovery.
"""
from webui_src import WEBUI, main_js_parts


def test_index_html_loads_main_js_first_and_every_js_part():
    parts = main_js_parts()
    on_disk = {f"js/{p.name}" for p in (WEBUI / "js").glob("*.js")}
    assert parts[0] == "main.js"
    assert len(parts) == len(set(parts))
    assert set(parts[1:]) == on_disk


def test_last_part_marks_the_core_loaded_for_the_error_guard():
    last = (WEBUI / main_js_parts()[-1]).read_text(encoding="utf-8")
    assert last.rstrip().endswith("window.lmCoreLoaded = true;")
    index = (WEBUI / "index.html").read_text(encoding="utf-8")
    assert "coreAsset && !window.lmCoreLoaded" in index
    assert "if (!window.lmCoreLoaded) onFatal(" in index
    # A part that 404s fires a resource error with no filename; the guard
    # must read the <script src> so a missing middle part is still fatal.
    assert "t.tagName === 'SCRIPT' && t.src" in index
