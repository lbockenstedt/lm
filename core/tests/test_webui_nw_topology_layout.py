"""Network → Topology map layout (``_nwTopoLayout`` in ``WebUI/js/nw.js``).

The map is a tidy tree rooted at the tenant's gateways, built from fact links
(LLDP, declared, NetBox) before MAC-table guesses. These run the real function
under node on the SSPLM shape that drew everything off the core: two VPNCs →
core → TOR-AGG → TORs, plus a lab switch with more links than the core.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

NW_JS = Path(__file__).resolve().parents[2] / "WebUI" / "js" / "nw.js"

pytestmark = pytest.mark.skipif(shutil.which("node") is None,
                                reason="node is required to execute the WebUI helper")


def _layout(nodes, edges, **opts):
    """Run ``_nwTopoLayout`` under node and return depth, parent, slot order and hidden info."""
    src = NW_JS.read_text()
    strong = src[src.index("const _NW_TOPO_STRONG"):]
    strong = strong[:strong.index("\n") + 1]
    geom = src[src.index("const _NW_TOPO_GEOM"):]
    geom = geom[:geom.index("\n};\n") + 4]
    start = src.index("function _nwTopoLayout")
    fn = src[start:src.index("\n}\n", start) + 3]
    opts_js = json.dumps({k: v for k, v in opts.items() if k != "collapsed"})
    collapsed = json.dumps(opts.get("collapsed", []))
    harness = (strong + geom + fn +
               f"\nconst o = Object.assign({opts_js}, {{collapsed: new Set({collapsed})}});"
               f"\nconst l = _nwTopoLayout({json.dumps(nodes)}, {json.dumps(edges)}, o);"
               "\nconsole.log(JSON.stringify({depth: l.depth, parent: l.parent, pos: l.pos,"
               " hidden: [...l.hidden], hiddenCount: l.hiddenCount, roots: l.roots,"
               " loose: l.loose.map(n => n.id)}));")
    out = subprocess.run(["node", "-e", harness], capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


def _n(i, kind="switch"):
    """A map node whose name is its id."""
    return {"id": i, "name": i, "kind": kind}


def _e(a, b, source="lldp"):
    """A link between two node ids."""
    return {"a": a, "b": b, "source": source}


_LAB = [f"LAB-{i}" for i in range(8)]
_NODES = ([_n("VPNC1", "gateway"), _n("VPNC2", "gateway"), _n("CORE"), _n("TOR-AGG"),
           _n("TOR-A"), _n("TOR-B"), _n("LAB-HUB"), _n("SRV", "other")]
          + [_n(x) for x in _LAB])
_EDGES = ([_e("VPNC1", "CORE"), _e("VPNC2", "CORE"), _e("CORE", "TOR-AGG"),
           _e("TOR-AGG", "TOR-A"), _e("TOR-AGG", "TOR-B"), _e("TOR-B", "LAB-HUB"),
           # SRV hangs off TOR-A by LLDP; the core's MAC table also sees it.
           _e("TOR-A", "SRV"), _e("CORE", "SRV", "mac")]
          + [_e("LAB-HUB", x) for x in _LAB])


def test_tree_is_rooted_at_the_gateways_not_the_busiest_switch():
    lay = _layout(_NODES, _EDGES)
    d = lay["depth"]
    assert sorted(lay["roots"]) == ["VPNC1", "VPNC2"]
    assert (d["VPNC1"], d["CORE"], d["TOR-AGG"], d["TOR-A"], d["TOR-B"]) == (0, 1, 2, 3, 3)
    assert lay["parent"]["TOR-A"] == "TOR-AGG" and lay["parent"]["LAB-HUB"] == "TOR-B"


def test_a_mac_link_never_re_parents_a_device_lldp_placed():
    lay = _layout(_NODES, _EDGES)
    assert lay["parent"]["SRV"] == "TOR-A" and lay["depth"]["SRV"] == 4


def test_mac_links_still_place_a_device_no_fact_reaches():
    lay = _layout(_NODES + [_n("PDU", "other")], _EDGES + [_e("TOR-A", "PDU", "mac")])
    assert lay["parent"]["PDU"] == "TOR-A"


def test_second_gateway_sits_beside_the_first_over_the_core():
    lay = _layout(_NODES, _EDGES)
    p = lay["pos"]
    assert p["VPNC1"]["y"] == p["VPNC2"]["y"] < p["CORE"]["y"]
    assert abs(p["VPNC1"]["x"] - p["VPNC2"]["x"]) >= 150
    assert min(p["VPNC1"]["x"], p["VPNC2"]["x"]) <= p["CORE"]["x"] <= max(p["VPNC1"]["x"], p["VPNC2"]["x"])


def test_no_gateway_roots_at_the_best_connected_switch_and_a_pin_overrides():
    nodes = [n for n in _NODES if n["kind"] != "gateway"]
    edges = [e for e in _EDGES if "VPNC" not in e["a"]]
    assert _layout(nodes, edges)["roots"] == ["LAB-HUB"]
    assert _layout(nodes, edges, root="CORE")["roots"] == ["CORE"]
    assert _layout(_NODES, _EDGES, root="TOR-AGG")["depth"]["VPNC1"] == 2


def test_collapsing_hides_only_the_branch_and_counts_it():
    lay = _layout(_NODES, _EDGES, collapsed=["TOR-B"])
    assert set(lay["hidden"]) == {"LAB-HUB", *_LAB}
    assert lay["hiddenCount"]["TOR-B"] == 9
    assert "TOR-A" in lay["pos"] and "LAB-HUB" not in lay["pos"]


def test_left_to_right_puts_hops_in_columns():
    lay = _layout(_NODES, _EDGES, orient="lr")
    p = lay["pos"]
    assert p["VPNC1"]["x"] < p["CORE"]["x"] < p["TOR-AGG"]["x"] < p["TOR-A"]["x"]


def _fn(src, name):
    """The source of one top-level ``function name`` in nw.js."""
    start = src.index(f"function {name}(")
    return src[start:src.index("\n}\n", start) + 3]


def test_a_full_render_draws_with_no_stale_selection():
    # A refresh or tab re-entry clears the selection; the SVG must be built
    # from the cleared state, not dimmed around the node selected before.
    src = NW_JS.read_text()
    state = src[src.index("const _nwTopoState"):]
    state = state[:state.index("\n};\n") + 4]
    harness = ("let currentTenant = 't1';\nconst localStorage = {getItem() { return null; }};\n"
               + state + _fn(src, "_nwTopoPref") + _fn(src, "_nwTopoRootKey") + _fn(src, "_nwTopoView")
               + "\n_nwTopoView(); _nwTopoState.selected = 'CORE';"
               "\nconst kept = _nwTopoView().selected, fresh = _nwTopoView(true).selected;"
               "\nconsole.log(JSON.stringify({kept, fresh, after: _nwTopoState.selected}));")
    out = subprocess.run(["node", "-e", harness], capture_output=True, text=True, check=True)
    assert json.loads(out.stdout) == {"kept": "CORE", "fresh": "", "after": ""}
    render = _fn(src, "_renderNwTopologyTab")
    assert render.index("_nwTopoView(true)") < render.index("_nwTopoSvg(")


_STUB = r"""
const fs = require('fs'), vm = require('vm');
class E {
  constructor(id) { this.id = id; this.children = []; this.style = {}; this.dataset = {};
                    this.clientWidth = 1000; this.clientHeight = 600; this.scrollLeft = 0;
                    this.scrollTop = 0; this.value = ''; this.attrs = {}; }
  append(...c) { this.children.push(...c); }
  replaceChildren() { this.children = []; }
  addEventListener() {}
  setAttribute(k, v) { this.attrs[k] = v; }
  getAttribute(k) { return this.attrs[k]; }
  querySelector() { return this.svg || null; }
  querySelectorAll() { return []; }
  closest() { return null; }
  get textContent() { return this._t || ''; }
  set textContent(v) { this._t = String(v); }
  walk() { return [this, ...this.children.flatMap(c => (c && c.walk) ? c.walk() : [])]; }
}
const els = {};
const toasts = [];
const ctx = { console, toasts, E, els, currentTenant: 't1', isAdmin: () => true, isTenantAdmin: () => true,
  escapeHtml: x => String(x), showToast: (m, k) => toasts.push([m, k]),
  localStorage: { getItem() { return null; }, setItem() {}, removeItem() {} },
  document: { addEventListener() {}, getElementById: id => (els[id] = els[id] || new E(id)),
              createElement: t => new E(t), querySelector: () => null, querySelectorAll: () => [] } };
ctx.window = ctx;
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(process.argv[1], 'utf8'), ctx);
const out = vm.runInContext(process.argv[2], ctx);
console.log(JSON.stringify(out));
"""


def _run(body):
    """Load the whole of nw.js under node with a stub DOM, run ``body`` and return its value."""
    out = subprocess.run(["node", "-e", _STUB, str(NW_JS), body],
                         capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


def test_wheel_zoom_keeps_the_point_under_the_pointer_on_a_centred_map():
    # A 600px map in a 1000px frame is centred (200px gap); zooming to 2x at
    # frame x 500 (map x 300) must leave map x 300 under the pointer.
    got = _run("""(() => {
      const host = document.getElementById('nw-topo-svg'); host.svg = new E('svg');
      _nwTopoState.drawn = { W: 600, H: 300, lay: {} }; _nwTopoState.zoom = 1;
      _nwTopoZoom(2, 500, 100);
      return host.scrollLeft;
    })()""")
    assert got == 300 * 2 - 500


def test_auto_fold_waits_for_a_map_that_needs_it_and_then_settles_per_tenant():
    got = _run("""(() => {
      const n = (id, kind) => ({ id, name: id, kind: kind || 'switch', infra: true });
      const small = { nodes: [n('GW', 'gateway'), n('CORE')], edges: [{ a: 'GW', b: 'CORE', source: 'lldp' }] };
      const big = { nodes: [...small.nodes, n('AGG')], edges: [...small.edges, { a: 'CORE', b: 'AGG', source: 'lldp' }] };
      for (let t = 0; t < 4; t++) {
        big.nodes.push(n('TOR' + t)); big.edges.push({ a: 'AGG', b: 'TOR' + t, source: 'lldp' });
        for (let h = 0; h < 30; h++) {
          big.nodes.push(n(`H${t}-${h}`)); big.edges.push({ a: 'TOR' + t, b: `H${t}-${h}`, source: 'lldp' });
        }
      }
      const s = _nwTopoState, r = [];
      _nwTopoView();
      s.graph = small; r.push(_nwTopoAutoFold());           // fits: nothing to do yet
      s.graph = big;   r.push(_nwTopoAutoFold());           // a refresh grew it: fold
      const folded = s.collapsed.size;
      s.collapsed.clear();                                  // Expand all
      r.push(_nwTopoAutoFold());                            // settled: never refolds
      currentTenant = 't2'; _nwTopoView();                  // switch away ...
      currentTenant = 't1'; _nwTopoView();                  // ... and back: collapse was dropped
      r.push(_nwTopoAutoFold());                            // so it folds again
      return { r, folded };
    })()""")
    assert got["r"] == [False, True, False, True]
    assert got["folded"] > 0


def test_start_map_here_is_not_offered_for_an_unlinked_device():
    got = _run("""(() => {
      const s = _nwTopoState;
      s.graph = { nodes: [{ id: 'LONE', name: 'LONE', kind: 'switch' }, { id: 'A', name: 'A', kind: 'switch' },
                          { id: 'B', name: 'B', kind: 'switch' }],
                  edges: [{ a: 'A', b: 'B', source: 'lldp' }] };
      const lay = { loose: [{ id: 'LONE' }] };
      s.drawn = { lay, pos: {} };
      const acts = id => { s.selected = id; _nwTopoDetails();
        return document.getElementById('nw-topo-details').walk().filter(x => x.dataset && x.dataset.topoAct === 'root').length; };
      return { lone: acts('LONE'), linked: acts('A') };
    })()""")
    assert got == {"lone": 0, "linked": 1}


def test_find_runs_once_when_enter_also_fires_change():
    got = _run("""(() => {
      _nwTopoState.graph = { nodes: [{ id: 'A', name: 'A', kind: 'switch', infra: true }], edges: [] };
      _nwTopoBindView();
      const f = document.getElementById('nw-topo-find');
      f.value = 'NO-SUCH-DEVICE'; f.oninput();
      f.onkeydown({ key: 'Enter', preventDefault() {} }); f.onchange();
      return toasts.length;
    })()""")
    assert got == 1
