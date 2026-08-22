"""Simulation Build Assistant — a multi-turn chat, embedded in the
Simulations module, that helps a user scope a NEW client simulation
(e.g. "I want to build a simulation that runs this script") by asking
clarifying questions when something needed is missing, and answers general
"how does the engine work"-style questions about the module.

The LLM backend is the AppBuilder module (ab) — same as help_assistant.py.
This route only relays: it holds no LLM logic of its own, just the running
conversation the client echoes back each turn and a system prompt scoped to
"what a buildable simulation spec needs" (per the add-simulation skill this
platform's build tooling — sim-builder — already follows).

HARD SCOPE BOUNDARY, enforced two ways: (1) retrieval — the only docs ever
loaded into context are a fixed whitelist of Simulations-module docs
(_CS_DOCS); mTLS, Azure, core hub systems, and every other module are
structurally unreachable, there is nothing to retrieve. (2) prompt — the
system prompt explicitly instructs the model to decline and redirect any
off-topic question rather than answer from its general training. Neither
alone is airtight (an LLM can still say something wrong), but together they
keep this assistant from being a general-purpose hub Q&A the way
help_assistant.py deliberately is.

Unlike help_assistant.py (single question in, single answer out, no history),
this is a REAL back-and-forth: the client accumulates the message list itself
and POSTs the whole thing each turn (the same "client owns history" contract
any OpenAI/Anthropic-style chat API uses) — the hub keeps no session state.

Once the user is satisfied the conversation has gathered enough, they submit
through the EXISTING feature-request pipeline (/api/bug-report, type=feature,
admin-approval-gated) — this route never files anything itself. Keeping code-
writing access out of a chat bot's hands is a deliberate boundary, not a gap:
the actual build still goes through a human approval + the same sim-builder/
add-simulation tooling used today.

HARD REQUIREMENT: only usable when ab is connected — /api/sim-assistant/available
reports that, mirroring /api/help/available.
"""
from api import HTTPException, Request, logger, os


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
            "Within that scope, you have two jobs:\n"
            "1. CONVERSATION to help the user scope a NEW client simulation (e.g. a "
            "custom script they paste in, or a variant of an existing sim type) — ask "
            "ONE focused clarifying question at a time whenever something needed is "
            "missing or ambiguous. Do NOT dump a long checklist up front — have a "
            "natural back-and-forth, like a teammate scoping the work with them.\n"
            "2. General Q&A about how the Simulations module and its engine work, using "
            "the reference material below.\n\n"
            "What a complete, buildable simulation spec needs (per this platform's "
            "add-simulation build process):\n"
            "- A short, unique sim name/id (snake_case, matching existing naming style "
            "like dns_fail, dhcp_fail, collab)\n"
            "- What it actually does / simulates, in plain terms\n"
            "- The behavior itself — ask the user to paste the script content (or "
            "describe the logic) directly into the chat\n"
            "- Target platform(s): Linux (.sh), Windows (.ps1), or both. BOTH is the "
            "norm on this platform — Windows/Linux parity is an invariant, a new sim "
            "lands on both unless there's a specific reason for one only\n"
            "- Whether it should trip a specific Aruba Central alert — if so, WHICH "
            "alert type, so the quota/alert-generation machinery can be wired up\n"
            "- Any config knobs it needs (a rate, an interval, a target host, etc.)\n\n"
            "Once you have enough for a complete spec, summarize it clearly in your "
            "reply and tell the user they can click 'File as Feature Request' when "
            "they're satisfied — you never file anything yourself; a human always "
            "reviews and submits.\n\n"
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
        try:
            res = await hub.request_response(
                agent, "HELP_ASK",
                {"messages": messages, "tools": None, "system": _system_prompt(user_text)},
                timeout=90.0)
        except Exception as e:  # noqa: BLE001
            logger.warning("sim_assistant chat relay failed: %s", e)
            raise HTTPException(status_code=502, detail=f"Simulation assistant error: {e}")
        data = res.get("payload", {}).get("data", res) if isinstance(res, dict) else {}
        if not isinstance(data, dict) or data.get("status") != "SUCCESS":
            raise HTTPException(status_code=502,
                                detail=(data or {}).get("message") or "Simulation assistant error")
        answer = (data.get("assistant") or {}).get("content") or ""
        if not answer.strip():
            answer = ("I didn't get a usable response from the current LLM provider. "
                      "Try again, or switch the AppBuilder provider in Settings.")
        return {"answer": answer}
