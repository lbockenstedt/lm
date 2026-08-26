"""Simulation Build Assistant — a multi-turn chat, embedded in the
Simulations module, that helps a user scope a NEW client simulation
(e.g. "I want to build a simulation that runs this script", or "copy
dns_fail but tweak it for the LRB deployment") by asking clarifying
questions when something needed is missing, and answers general
"how does the engine work"-style questions about the module.

The LLM backend is the AppBuilder module (ab) — same as help_assistant.py.
This route only relays: it holds no LLM logic of its own, just the running
conversation the client echoes back each turn, a system prompt scoped to
"what a buildable simulation spec needs" (per the add-simulation skill this
platform's build tooling — sim-builder — already follows), and a small
hub-side tool loop (mirroring help_assistant.py's) so the model can look up
the ACTUAL source of an existing simulation when asked to base a new/varied
one on it, instead of guessing at behavior it can't see.

HARD SCOPE BOUNDARY, enforced two ways: (1) retrieval — the only docs ever
loaded into context are a fixed whitelist of Simulations-module docs
(_CS_DOCS), and the only source code ever reachable is the ``clients/`` tree
(``linux``, ``windows``, ``lib``, ``t3``, ``tests``) of the canonical ``cs``
repo (read-only, via the tool loop below) — mTLS, Azure, core hub systems,
and every other module/repo are structurally unreachable, there is nothing
to retrieve.
(2) prompt — the system prompt explicitly instructs the model to decline and
redirect any off-topic question rather than answer from its general
training. Neither alone is airtight (an LLM can still say something wrong),
but together they keep this assistant from being a general-purpose hub Q&A
the way help_assistant.py deliberately is.

Unlike help_assistant.py (single question in, single answer out, no history),
this is a REAL back-and-forth: the client accumulates the message list itself
and POSTs the whole thing each turn (the same "client owns history" contract
any OpenAI/Anthropic-style chat API uses) — the hub keeps no session state
across POSTs. Within a single POST, though, the hub DOES run a short
tool-calling loop (mirroring help_assistant.py's shape) so the model can
read_sim_source/list_available_sims before giving its final answer.

Once the user is satisfied the conversation has gathered enough, they submit
through the EXISTING feature-request pipeline (/api/bug-report, type=feature,
admin-approval-gated) — this route never files or writes anything itself,
including the source-reading tools below, which are strictly read-only HTTP
GETs against GitHub's Contents API. Keeping code-writing access out of a chat
bot's hands is a deliberate boundary, not a gap: the actual build still goes
through a human approval + the same sim-builder/add-simulation tooling used
today.

HARD REQUIREMENT: only usable when ab is connected — /api/sim-assistant/available
reports that, mirroring /api/help/available.
"""
import base64
import json
import re

from api import HTTPException, Request, logger, os

# ── existing-sim source reading (read-only, hub-side tool loop) ─────────────
# The hub has no local checkout of the `cs` repo (its code runs on
# spoke-managed client VMs, never on the hub's own filesystem) — so "read the
# actual sim code" means a live, read-only fetch from the canonical repo's
# GitHub Contents API, the same no-local-clone pattern
# simulations/github_config_client.py already uses for tenant config. This is
# intentionally its own tiny client, not a shared import — that module is
# tenant-scoped (per-tenant token/repo/branch); this one is a single fixed,
# public, read-only target.
_GITHUB_API = "https://api.github.com"
_CS_REPO_OWNER = "lbockenstedt"
_CS_REPO_NAME = "cs"
_CS_REPO_BRANCH = "main"

# Hard scope boundary: sim_name is validated against this pattern BEFORE it
# ever touches a path, so read_sim_source can only ever address a file
# directly under clients/linux/ or clients/windows/ in the canonical cs
# repo — no path traversal, no reaching outside those two directories,
# regardless of what the model sends.
_SIM_NAME_RE = re.compile(r"^[a-z0-9_]{2,40}$")

# Orchestrator/shared-library files that live alongside the real sims but
# aren't themselves a sim a user would name/copy — excluded from
# list_available_sims so the model doesn't suggest copying platform
# plumbing. (read_sim_source still allows reading them by name — a user or
# the model may legitimately want to see e.g. network_common.sh for
# context — this list is a discovery-UX filter, not a security boundary;
# the directory restriction above is the actual boundary.)
_CS_INFRA_FILES = {
    "agent", "apt_update", "common", "connect_1x", "connect_psk",
    "connect_wired_1x", "ini-parser", "install_wifi_drivers",
    "network_common", "recovery", "simulation", "startup", "update",
}


async def _github_get_contents(path):
    """GET one Contents-API path from the canonical cs repo. Returns the raw
    httpx Response so callers branch on status_code (404 vs 200 vs error).
    A thin, directly-monkeypatchable seam for tests — no local client/token
    plumbing to fake."""
    import httpx
    async with httpx.AsyncClient(timeout=15.0) as client:
        return await client.get(
            f"{_GITHUB_API}/repos/{_CS_REPO_OWNER}/{_CS_REPO_NAME}/contents/{path}",
            params={"ref": _CS_REPO_BRANCH},
            headers={"Accept": "application/vnd.github+json"})


async def _tool_list_available_sims(_args):
    """The names of existing sims (Linux/Windows script pairs), so the model
    can pick a real name instead of guessing before calling read_sim_source."""
    try:
        resp = await _github_get_contents("clients/linux")
    except Exception as e:  # noqa: BLE001
        return {"error": f"could not list sims: {e}"}
    if resp.status_code != 200:
        return {"error": f"GitHub returned {resp.status_code} listing sims"}
    try:
        entries = resp.json()
    except Exception:  # noqa: BLE001
        return {"error": "could not parse sim listing"}
    if not isinstance(entries, list):
        return {"error": "unexpected sim listing shape"}
    names = sorted({
        e["name"][:-3] for e in entries
        if isinstance(e, dict) and e.get("type") == "file"
        and str(e.get("name", "")).endswith(".sh")
        and e["name"][:-3] not in _CS_INFRA_FILES
    })
    return {"sims": names}


async def _tool_read_sim_source(args):
    """Read an EXISTING sim's real source (Linux .sh and/or Windows .ps1),
    read-only, so the model can base a new/varied sim on real behavior
    instead of guessing. sim_name is regex-validated before it ever reaches
    a path — see _SIM_NAME_RE above."""
    sim_name = str(args.get("sim_name") or "").strip().lower()
    platform = str(args.get("platform") or "both").strip().lower()
    if not _SIM_NAME_RE.match(sim_name):
        return {"error": "invalid sim_name — use the exact name from "
                         "list_available_sims (lowercase, letters/digits/underscore)"}
    plats = {"linux": ["linux"], "windows": ["windows"],
            "both": ["linux", "windows"]}.get(platform, ["linux", "windows"])
    out = {}
    for plat in plats:
        ext = "sh" if plat == "linux" else "ps1"
        path = f"clients/{plat}/{sim_name}.{ext}"
        try:
            resp = await _github_get_contents(path)
        except Exception as e:  # noqa: BLE001
            out[plat] = f"(fetch error: {e})"
            continue
        if resp.status_code == 404:
            out[plat] = "(not found)"
            continue
        if resp.status_code != 200:
            out[plat] = f"(GitHub returned {resp.status_code})"
            continue
        try:
            node = resp.json()
            b64 = (node.get("content") or "").replace("\n", "")
            out[plat] = base64.b64decode(b64).decode("utf-8", "replace")[:12000]
        except Exception:  # noqa: BLE001
            out[plat] = "(could not decode file)"
    return out


# ── general codebase browse/read (read-only, hub-side tool loop) ────────────
# read_sim_source above is the fast path for the exact "copy this sim" flow,
# but it can only ever see a sim's {name}.sh / {name}.ps1 — and those are
# usually thin wrappers: they `source` shared libs (common.sh, ini-parser.sh,
# network_common.sh) and `exec` a companion Python sender (collab.py,
# collab_pcap.py, dhcp_fire.py, dns_flood_test.py, cloud_nac_onboard.py, …)
# where the actual behavior lives. To ANSWER questions about how the sim code
# really works — not just scaffold a copy — the model needs to read those
# companion files too. These two tools give it a read-only browse+read of the
# whole clients/ tree. The scope boundary is unchanged in spirit: still only
# the canonical cs repo, still only under clients/ — _safe_cs_path blocks
# absolute paths, traversal, and anything outside clients/ before the value
# ever becomes a Contents-API path.
_CS_SEG_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def _safe_cs_path(path):
    """Normalize a repo-relative path and confirm it stays inside the cs
    repo's clients/ tree. Returns the cleaned path, ``"clients"`` for the
    root, or None if it escapes the boundary (absolute, traversal, or outside
    clients/). This is the actual security boundary for the browse/read tools
    below — every path is validated here before it reaches _github_get_contents."""
    p = str(path or "").strip().strip("/")
    if not p or p == "clients":
        return "clients"
    if not p.startswith("clients/"):
        return None
    segs = p.split("/")
    if any(s in (".", "..") or not _CS_SEG_RE.match(s) for s in segs):
        return None
    return p


async def _tool_list_cs_dir(args):
    """List a directory anywhere under the cs repo's clients/ tree, so the
    model can discover the companion files (the .py senders, shared libs,
    config templates) a sim's .sh/.ps1 wrapper actually sources or execs."""
    path = _safe_cs_path(args.get("path") or "clients")
    if path is None:
        return {"error": "invalid path — must be a directory under clients/"}
    try:
        resp = await _github_get_contents(path)
    except Exception as e:  # noqa: BLE001
        return {"error": f"could not list {path}: {e}"}
    if resp.status_code == 404:
        return {"error": f"no such directory: {path}"}
    if resp.status_code != 200:
        return {"error": f"GitHub returned {resp.status_code} listing {path}"}
    try:
        entries = resp.json()
    except Exception:  # noqa: BLE001
        return {"error": "could not parse listing"}
    if not isinstance(entries, list):
        return {"error": f"{path} is a file, not a directory — use read_cs_file"}
    items = [{"name": e.get("name"), "type": e.get("type")}
             for e in entries if isinstance(e, dict) and e.get("name")]
    items.sort(key=lambda x: (x.get("type") != "dir", x.get("name") or ""))
    return {"path": path, "entries": items}


async def _tool_read_cs_file(args):
    """Read any single file under the cs repo's clients/ tree, read-only —
    the general counterpart to read_sim_source, for the companion .py/.conf
    files and shared libs where the real sim behavior lives. Path is validated
    by _safe_cs_path before it ever becomes a path."""
    path = _safe_cs_path(args.get("path"))
    if path is None or path == "clients":
        return {"error": "invalid path — give a file under clients/, "
                         "e.g. clients/linux/collab.py"}
    try:
        resp = await _github_get_contents(path)
    except Exception as e:  # noqa: BLE001
        return {"error": f"fetch error: {e}"}
    if resp.status_code == 404:
        return {"error": f"not found: {path}"}
    if resp.status_code != 200:
        return {"error": f"GitHub returned {resp.status_code}"}
    try:
        node = resp.json()
    except Exception:  # noqa: BLE001
        return {"error": "could not parse response"}
    if isinstance(node, list):
        return {"error": f"{path} is a directory — use list_cs_dir"}
    try:
        b64 = (node.get("content") or "").replace("\n", "")
        return {"path": path,
                "content": base64.b64decode(b64).decode("utf-8", "replace")[:16000]}
    except Exception:  # noqa: BLE001
        return {"error": "could not decode file"}


_SIM_TOOLS = [
    {"type": "function", "function": {
        "name": "list_available_sims",
        "description": "List the names of existing client simulations (Linux/Windows script "
                       "pairs) already implemented on this platform. Call this before "
                       "read_sim_source whenever you don't already know the exact sim name.",
        "parameters": {"type": "object", "properties": {}},
    }},
    {"type": "function", "function": {
        "name": "read_sim_source",
        "description": "Read the real implementation source of an EXISTING simulation, by "
                       "name — e.g. to base a new or per-deployment-varied sim on it (like a "
                       "'dns_fail_lrb' variant of 'dns_fail' for one specific deployment). "
                       "Returns the Linux .sh and/or Windows .ps1 source, read-only.",
        "parameters": {"type": "object",
                       "properties": {
                           "sim_name": {"type": "string",
                                       "description": "Exact sim name, e.g. 'dns_fail', 'collab'"},
                           "platform": {"type": "string", "enum": ["linux", "windows", "both"]},
                       },
                       "required": ["sim_name"]},
    }},
    {"type": "function", "function": {
        "name": "list_cs_dir",
        "description": "List a directory in the client-simulation codebase (the cs repo's "
                       "clients/ tree: linux/, windows/, lib/, t3/, tests/). Use this to "
                       "discover the companion files a sim depends on — the .py senders, the "
                       "shared libs (common.sh, ini-parser.sh, network_common.sh), and the "
                       "config templates a sim's .sh/.ps1 wrapper sources or execs. Pass a "
                       "path like 'clients/linux' or 'clients/lib'; omit path to list "
                       "clients/ itself.",
        "parameters": {"type": "object",
                       "properties": {
                           "path": {"type": "string",
                                   "description": "Directory under clients/, e.g. 'clients/linux'"},
                       }},
    }},
    {"type": "function", "function": {
        "name": "read_cs_file",
        "description": "Read any single file in the client-simulation codebase, read-only — "
                       "the general counterpart to read_sim_source. Use this for the "
                       "companion files where a sim's real behavior actually lives (e.g. "
                       "clients/linux/collab.py, clients/linux/dhcp_fire.py) and shared libs "
                       "(clients/lib/common.sh), which a bare .sh/.ps1 wrapper only sources "
                       "or execs. Prefer reading the real code over guessing. Path must be "
                       "under clients/.",
        "parameters": {"type": "object",
                       "properties": {
                           "path": {"type": "string",
                                   "description": "File path under clients/, e.g. "
                                                  "'clients/linux/collab.py'"},
                       },
                       "required": ["path"]},
    }},
]


async def _exec_sim_tool(name, args):
    if name == "list_available_sims":
        return await _tool_list_available_sims(args)
    if name == "read_sim_source":
        return await _tool_read_sim_source(args)
    if name == "list_cs_dir":
        return await _tool_list_cs_dir(args)
    if name == "read_cs_file":
        return await _tool_read_cs_file(args)
    return {"error": f"unknown tool: {name}"}


def register(app, hub, ctx):

    _DOCS_DIR = next(
        (d for d in (
            os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../docs")),
            os.path.abspath(os.path.join(os.path.dirname(__file__), "../../docs")),
        ) if os.path.isdir(d)),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../docs")))

    def _ab_agent():
        """The connected ab agent's spoke_id, or None. Mirrors
        help_assistant.py's _ab_agent — kept as its own small copy so this
        route has no import-time dependency on help_assistant.py."""
        conns = getattr(hub, "active_connections", {}) or {}
        if hub._primary_key("ab") in conns:
            return "ab"
        for sid in conns:
            if "ab" in str(sid).lower():
                return sid
        return None

    def _read_doc(name, cap=6000):
        try:
            with open(os.path.join(_DOCS_DIR, name + ".md"), encoding="utf-8") as f:
                return f.read()[:cap]
        except Exception as e:  # noqa: BLE001
            logger.warning("sim_assistant: could not read doc %s: %s", name, e)
            return ""

    # Hard scope boundary #1 (retrieval): the ONLY docs this assistant can ever
    # load into context are these — the Simulations (cs) module and its
    # directly-related product twins/subsystems. mTLS, Azure, other modules
    # (NAC, DNS, DHCP, IPAM, firewall, console, LDAP, etc.) and core hub
    # systems are structurally never in reach, regardless of what's asked —
    # there's nothing to retrieve. Mirrors help_assistant.py's _select_docs
    # RAG-lite (keyword overlap), just over a fixed whitelist instead of the
    # full doc corpus.
    _CS_DOCS = ("cs", "alert-generation", "dongle-quarantine",
               "iot-device-catalog-quota", "central-on-prem", "mist")

    def _select_cs_docs(question, k=3):
        words = {w for w in ''.join(c.lower() if c.isalnum() else ' '
                                    for c in question).split() if len(w) > 2}
        docs = {n: _read_doc(n) for n in _CS_DOCS}
        scored = []
        for name, text in docs.items():
            if not text:
                continue
            tl = text.lower()
            score = sum(tl.count(w) for w in words) + 5 * sum(w in name.lower() for w in words)
            scored.append((score, name))
        scored.sort(reverse=True)
        picked = [n for s, n in scored if s > 0][:k]
        if not picked:
            picked = ["cs"]  # always-relevant fallback — the module's own doc
        return {n: docs[n] for n in picked}

    def _system_prompt(question):
        picked_docs = _select_cs_docs(question)
        doc_ctx = "\n\n".join(f"=== DOC: {n} ===\n{t}" for n, t in picked_docs.items())
        return (
            "You are the Lab Manager (LM) Simulation Build Assistant, embedded in the "
            "Simulations module.\n\n"
            "HARD SCOPE BOUNDARY: you may ONLY discuss the Simulations (cs) module and "
            "directly related topics — client simulations, the sim-quota/alert-"
            "generation engine, dongle/hardware provisioning for sim clients, VM Server "
            "(the sim client VM infrastructure), and the Central / Central On-Prem / "
            "Mist product twins. Questions like 'how does the quota engine work' or "
            "'what's the difference between T1/T2/T3' are exactly on-topic. If asked "
            "about ANYTHING else — mTLS, certificates, Azure, core hub systems, other "
            "modules (NAC/ClearPass, DNS, DHCP, IPAM/NetBox, firewall, console, LDAP, "
            "hypervisor/Proxmox management outside sim VMs, etc.) — politely decline and "
            "redirect the user back to Simulations-module topics. Do not answer, do not "
            "speculate, do not offer to help with it even briefly — just redirect.\n\n"
            "Within that scope, you have three jobs:\n"
            "1. CONVERSATION to help the user scope a NEW client simulation (e.g. a "
            "custom script they paste in, or a variant of an existing sim type) — ask "
            "ONE focused clarifying question at a time whenever something needed is "
            "missing or ambiguous. Do NOT dump a long checklist up front — have a "
            "natural back-and-forth, like a teammate scoping the work with them.\n"
            "2. General Q&A about how the Simulations module, its engine, AND the actual "
            "client-sim code work. Beyond the reference docs below, you can READ THE REAL "
            "SOURCE to answer accurately: browse the codebase with list_cs_dir and read "
            "any file with read_cs_file. A sim's .sh/.ps1 is usually just a thin wrapper "
            "that sources shared libs (common.sh, ini-parser.sh) and execs a companion "
            "Python sender (e.g. collab.py, dhcp_fire.py, dns_flood_test.py) where the real "
            "behavior lives — so when a question is about how a specific sim or mechanism "
            "actually behaves, READ the relevant files (including those companions) instead "
            "of answering from memory or guessing.\n"
            "3. COPYING/VARYING an existing sim for a specific deployment (e.g. the user "
            "wants a 'dns_fail_lrb' variant of 'dns_fail' with a tweaked target/threshold "
            "for one site) — use list_available_sims to find the real name, then "
            "read_sim_source to read its ACTUAL Linux/Windows source before proposing "
            "anything (and read_cs_file for any companion .py/shared-lib it depends on). "
            "Never guess at existing sim behavior — always read it first. "
            "Present the proposed new/changed script content directly in the chat; you "
            "cannot write files or commit anything yourself.\n\n"
            "What a complete, buildable simulation spec needs (per this platform's "
            "add-simulation build process):\n"
            "- A short, unique sim name/id (snake_case, matching existing naming style "
            "like dns_fail, dhcp_fail, collab — a per-deployment variant typically suffixes "
            "the base name, e.g. dns_fail_lrb)\n"
            "- What it actually does / simulates, in plain terms\n"
            "- The behavior itself — for a brand-new sim, ask the user to paste the script "
            "content (or describe the logic) directly into the chat; for a variant of an "
            "existing sim, read it yourself with read_sim_source instead of asking\n"
            "- Target platform(s): Linux (.sh), Windows (.ps1), or both. BOTH is the "
            "norm on this platform — Windows/Linux parity is an invariant, a new sim "
            "lands on both unless there's a specific reason for one only\n"
            "- Whether it should trip a specific Aruba Central alert — if so, WHICH "
            "alert type, so the quota/alert-generation machinery can be wired up\n"
            "- Any config knobs it needs (a rate, an interval, a target host, etc.)\n\n"
            "Once you have enough for a complete spec, summarize it clearly in your "
            "reply (including any proposed script content) and tell the user they can "
            "click 'File as Feature Request' when they're satisfied — you never file "
            "anything yourself; a human always reviews and submits.\n\n"
            "Reference material (how simulations actually work on this platform):\n\n"
            + doc_ctx
        )

    @app.get("/api/sim-assistant/available")
    async def sim_assistant_available():
        """Whether the simulation build assistant is usable (ab connected)."""
        return {"available": _ab_agent() is not None}

    @app.post("/api/sim-assistant/chat")
    async def sim_assistant_chat(request: Request):
        agent = _ab_agent()
        if not agent:
            raise HTTPException(status_code=409,
                                detail="Simulation assistant unavailable — the AppBuilder "
                                       "LLM agent is not connected.")
        try:
            body = await request.json()
        except Exception:
            body = {}
        # Full running transcript, echoed back by the client each turn — the
        # hub keeps no session state. Must be a non-empty list of {role,
        # content} dicts (the frontend appends the new user turn before
        # POSTing, same shape the assistant turns it gets back are in).
        history = body.get("messages")
        if not isinstance(history, list) or not history:
            raise HTTPException(status_code=400, detail="messages is required")
        messages = [{"role": m.get("role"), "content": m.get("content")}
                   for m in history
                   if isinstance(m, dict) and m.get("role") in ("user", "assistant")
                   and isinstance(m.get("content"), str) and m.get("content").strip()]
        if not messages:
            raise HTTPException(status_code=400, detail="messages is empty/invalid")

        # Doc selection uses every user turn so far (not just the latest) —
        # a short "yes" reply mid-conversation shouldn't lose the doc context
        # an earlier, more descriptive turn already established.
        user_text = " ".join(m["content"] for m in messages if m["role"] == "user")
        system = _system_prompt(user_text)

        # Tool-calling loop (mirrors help_assistant.py's shape): the model may
        # call list_available_sims/read_sim_source before giving its final
        # answer. Runs entirely within this one POST — tool calls/results are
        # NOT echoed back to the client's own history (it only round-trips
        # user/assistant content), so each POST starts the loop fresh; that's
        # fine since a prior turn's answer already incorporated whatever it read.
        turn_messages = list(messages)
        answer = ""
        for _ in range(5):
            try:
                res = await hub.request_response(
                    agent, "HELP_ASK",
                    {"messages": turn_messages, "tools": _SIM_TOOLS, "system": system},
                    timeout=90.0)
            except Exception as e:  # noqa: BLE001
                logger.warning("sim_assistant chat relay failed: %s", e)
                raise HTTPException(status_code=502, detail=f"Simulation assistant error: {e}")
            data = res.get("payload", {}).get("data", res) if isinstance(res, dict) else {}
            if not isinstance(data, dict) or data.get("status") != "SUCCESS":
                raise HTTPException(status_code=502,
                                    detail=(data or {}).get("message") or "Simulation assistant error")
            assistant = data.get("assistant") or {}
            tool_calls = assistant.get("tool_calls") or []
            text = assistant.get("content") or ""
            if not tool_calls:
                answer = text
                break
            turn_messages.append({"role": "assistant", "content": text, "tool_calls": tool_calls})
            for tc in tool_calls:
                fn = tc.get("function") or {}
                name = fn.get("name") or tc.get("name")
                raw = fn.get("arguments") if fn else tc.get("arguments")
                try:
                    args = json.loads(raw) if isinstance(raw, str) else (raw or {})
                except Exception:
                    args = {}
                out = await _exec_sim_tool(name, args)
                turn_messages.append({"role": "tool", "tool_call_id": tc.get("id"),
                                      "name": name, "content": json.dumps(out)[:12000]})
        else:
            answer = answer or ("I wasn't able to finish looking up the existing sim source "
                                "in time — try asking again, or narrow down which sim you mean.")

        if not answer.strip():
            answer = ("I didn't get a usable response from the current LLM provider. "
                      "Try again, or switch the AppBuilder provider in Settings.")
        return {"answer": answer}
