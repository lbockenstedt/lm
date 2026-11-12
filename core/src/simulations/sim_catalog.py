"""The one list of simulations: ``sims.json`` next to this file.

Every sim list in the fleet comes from here. The hub (``sim_quota``,
``routes``) and the cs spoke (which runs lm core from /opt/lm) import
``SIM_META``. The client scripts and the sim-views.js UI cannot import it, so a
cs test fails the push when any of them misses a sim.

Each entry: ``category`` (failure | traffic), ``multi_capable`` (may share a
client with other sims) and ``media`` (any | wired | wireless: the NIC a client
needs to run it).
"""

import json
from pathlib import Path

SIM_META = json.loads(Path(__file__).with_name("sims.json").read_text(encoding="utf-8"))
