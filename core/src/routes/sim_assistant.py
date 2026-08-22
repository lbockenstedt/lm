"""Simulation Build Assistant — a multi-turn chat, embedded in the
Simulations module, that helps a user scope a NEW client simulation
(e.g. "I want to build a simulation that runs this script") by asking
clarifying questions when something needed is missing.

The LLM backend is the AppBuilder module (ab) — same as help_assistant.py.
This route only relays: it holds no LLM logic of its own, just the running
conversation the client echoes back each turn and a system prompt scoped to
"what a buildable simulation spec needs" (per the add-simulation skill this
platform's build tooling — sim-builder — already follows).

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

    def _system_prompt():
        cs_doc = _read_doc("cs")
        alert_doc = _read_doc("alert-generation")
        return (
            "You are the Lab Manager (LM) Simulation Build Assistant, embedded in the "
            "Simulations module. Your job is a CONVERSATION: help the user scope a new "
            "client-side traffic/failure simulation (e.g. a custom script they paste in, "
            "or a variant of an existing sim type) by asking ONE focused clarifying "
            "question at a time whenever something needed is missing or ambiguous. Do "
            "NOT dump a long checklist up front — have a natural back-and-forth, like a "
            "teammate scoping the work with them.\n\n"
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
            "=== DOC: cs ===\n" + cs_doc + "\n\n"
            "=== DOC: alert-generation ===\n" + alert_doc
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

        try:
            res = await hub.request_response(
                agent, "HELP_ASK",
                {"messages": messages, "tools": None, "system": _system_prompt()},
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
