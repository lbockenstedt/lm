"""pytest path bootstrap for the henet spoke test suite.

``henet_spoke`` imports its sibling ``henet_manager`` as a bare name, so
``henet/src`` must be on ``sys.path``. It also inherits ``BaseSpoke`` from the LM
``core`` repo (``core.src.base_spoke`` / bare ``base_spoke``), so core's parent
dir must be on the path too — in dev that's the sibling ``lm`` checkout, in prod
``/opt/lm/core`` alongside the henet checkout. Mirrors the dns spoke conftest.
"""

import os
import sys
from pathlib import Path

os.environ.setdefault("LM_DEP_GUARD_DISABLE", "1")

HERE = Path(__file__).resolve().parent          # henet/tests
HENET_ROOT = HERE.parent                          # henet
SRC = HENET_ROOT / "src"
for p in (str(SRC), str(HENET_ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

# When henet ships vendored inside the lm repo (lm/henet), core is a sibling
# dir (lm/core). Also support a standalone checkout beside the lm repo.
LM_ROOT = HENET_ROOT.parent                        # lm  (or .../vscode)
for cand in (LM_ROOT / "core", LM_ROOT / "lm" / "core", HENET_ROOT / "core"):
    if (cand / "src" / "base_spoke.py").is_file():
        for cp in (str(cand.parent), str(cand / "src")):
            if cp not in sys.path:
                sys.path.insert(0, cp)
        break
