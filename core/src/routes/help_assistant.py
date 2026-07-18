"""Help assistant — LLM-driven docs Q&A + live-state answers.

The LLM backend is the BugFixer module (it owns the multi-provider LLM layer).
This route only orchestrates: it selects relevant docs (RAG-lite over the ~19
canonical lm/docs files), defines hub-side tools, and runs the agentic loop by
relaying each model turn to the connected bugfixer agent via the HELP_ASK
command (bugfixer runs one call_llm turn, returns {content, tool_calls}).

HARD REQUIREMENT: the feature is only usable when bugfixer is connected —
``/api/help/available`` reports that, and the WebUI hides the "Ask" affordance
otherwise. Routes live under ``/api/help/*`` so the access-control middleware
gates them (valid session required) like every other ``/api/`` route.
"""
from api import HTTPException, Request, logger, os, json, asyncio


def register(app, hub, ctx):

    _DOCS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../docs"))

    def _bugfixer_agent():
        """The connected bugfixer agent's spoke_id, or None. bugfixer registers
        as spoke_id 'bugfixer' (config HUB_AGENT_ID); match that, else any
        connected id containing 'bugfixer'."""
        conns = getattr(hub, "active_connections", {}) or {}
        if hub._primary_key("bugfixer") in conns:
            return "bugfixer"
        for sid in conns:
            if "bugfixer" in str(sid).lower():
                return sid
        return None

    # ── doc corpus (RAG-lite) ────────────────────────────────────────────────
    def _load_docs():
        docs = {}
        try:
            for fn in sorted(os.listdir(_DOCS_DIR)):
                if fn.endswith(".md"):
                    with open(os.path.join(_DOCS_DIR, fn), encoding="utf-8") as f:
                        docs[fn[:-3]] = f.read()
        except Exception as e:  # noqa: BLE001
            logger.warning("help: could not read docs dir: %s", e)
        return docs

    def _select_docs(question, docs, k=4):
        """Pick the k most relevant docs by keyword overlap (name-hits weighted).
        Corpus is tiny (~120KB) so no embeddings are needed."""
        words = {w for w in ''.join(c.lower() if c.isalnum() else ' '
                                    for c in question).split() if len(w) > 2}
        scored = []
        for name, text in docs.items():
            tl = text.lower()
            score = sum(tl.count(w) for w in words) + 5 * sum(w in name.lower() for w in words)
            scored.append((score, name))
        scored.sort(reverse=True)
        picked = [n for s, n in scored if s > 0][:k]
        if not picked:  # fallback to the overview docs
            picked = [n for n in ("README", "architecture-topology", "lm-hub") if n in docs][:2]
        return picked

    # ── Phase 2 tools (executed hub-side) ────────────────────────────────────
    def _tool_spokes_status(_args):
        """Every known spoke/agent + connected/approved/type — answers
        'what's connected' / 'why is my <x> spoke offline'."""
        known = hub.state.system_state.get("known_modules", []) or []
        meta = hub.state.system_state.get("module_metadata", {}) or {}
        conns = getattr(hub, "active_connections", {}) or {}
        out = []
        for sid in known:
            out.append({
                "spoke_id": sid,
                "connected": hub._primary_key(sid) in conns,
                "approved": hub.approved_modules.get(hub._primary_key(sid), False),
                "module_type": hub.spoke_module_types.get(hub._primary_key(sid))
                or (meta.get(sid, {}) or {}).get("module_type"),
            })
        return {"spokes": out, "connected_count": sum(1 for s in out if s["connected"])}

    async def _tool_search_devices(args):
        """Fan a query to every searchable spoke type (mirrors /api/search's
        core, minus tenant scoping — the assistant runs with hub-wide view)."""
        q = str(args.get("query") or "").strip()
        if not q:
            return {"error": "query required"}
        payload = {"q": q, "tenant": "default"}

        async def _call(spoke, cmd):
            if not spoke:
                return []
            try:
                r = await hub.request_response(spoke, cmd, payload)
                d = r.get("payload", {}).get("data", r) if isinstance(r, dict) else r
                return d.get("results", []) if isinstance(d, dict) else []
            except Exception as e:  # noqa: BLE001
                return [{"source": cmd, "type": "error", "name": str(e)}]

        pairs = [
            (hub.get_spoke_by_type("ipam"), "NETBOX_SEARCH"),
            (hub.get_hypervisor_spoke(), "SEARCH_VMS"),
            (hub.get_spoke_by_type("nac"), "SEARCH_SESSIONS"),
            (hub.get_spoke_by_type("directory"), "SEARCH_USERS"),
            (hub.get_spoke_by_type("firewall"), "SEARCH_DHCP"),
        ]
        results = await asyncio.gather(*[_call(s, c) for s, c in pairs])
        merged = [item for sub in results for item in sub]
        return {"query": q, "total": len(merged), "results": merged[:50]}

    _TOOLS = [
        {"type": "function", "function": {
            "name": "get_spokes_status",
            "description": "List all spokes/agents with connected/approved status and "
                           "module type. Use for questions about what is connected or "
                           "why a spoke/agent is offline.",
            "parameters": {"type": "object", "properties": {}},
        }},
        {"type": "function", "function": {
            "name": "search_devices",
            "description": "Search the whole lab for devices/VMs/DHCP leases/users/"
                           "sessions by name, IP, or MAC. Use for questions about a "
                           "specific machine or where something lives.",
            "parameters": {"type": "object",
                           "properties": {"query": {"type": "string"}},
                           "required": ["query"]},
        }},
    ]

    async def _exec_tool(name, args):
        if name == "get_spokes_status":
            return _tool_spokes_status(args)
        if name == "search_devices":
            return await _tool_search_devices(args)
        return {"error": f"unknown tool: {name}"}

    # ── routes ───────────────────────────────────────────────────────────────
    @app.get("/api/help/available")
    async def help_available():
        """Whether the LLM help assistant is usable (bugfixer connected)."""
        return {"available": _bugfixer_agent() is not None}

    @app.post("/api/help/ask")
    async def help_ask(request: Request):
        agent = _bugfixer_agent()
        if not agent:
            raise HTTPException(status_code=409,
                                detail="Help assistant unavailable — the BugFixer LLM "
                                       "agent is not connected.")
        try:
            body = await request.json()
        except Exception:
            body = {}
        question = str(body.get("question") or "").strip()
        if not question:
            raise HTTPException(status_code=400, detail="question is required")

        docs = _load_docs()
        picked = _select_docs(question, docs)
        doc_ctx = "\n\n".join(f"### DOC: {n}\n{docs[n]}" for n in picked)
        system = (
            "You are the Lab Manager (LM) help assistant. Answer the user's question "
            "using ONLY the documentation below and any live data returned by the tools. "
            "Cite the doc name(s) you used inline as [doc:<name>]. Call get_spokes_status "
            "or search_devices when the question is about the live system. If the answer "
            "isn't in the docs or live data, say so plainly. Be concise and concrete.\n\n"
            "=== DOCUMENTATION ===\n" + doc_ctx
        )
        messages = [{"role": "user", "content": question}]
        used_tools = []
        answer = ""
        for _ in range(5):
            try:
                res = await hub.request_response(
                    agent, "HELP_ASK",
                    {"messages": messages, "tools": _TOOLS, "system": system},
                    timeout=90.0)
            except Exception as e:  # noqa: BLE001
                logger.warning("help_ask relay failed: %s", e)
                raise HTTPException(status_code=502, detail=f"Help assistant error: {e}")
            data = res.get("payload", {}).get("data", res) if isinstance(res, dict) else {}
            if not isinstance(data, dict) or data.get("status") != "SUCCESS":
                raise HTTPException(status_code=502,
                                    detail=(data or {}).get("message") or "Help assistant error")
            assistant = data.get("assistant") or {}
            tool_calls = assistant.get("tool_calls") or []
            text = assistant.get("content") or ""
            if not tool_calls:
                answer = text
                break
            # Echo the assistant turn, then execute + append each tool result.
            messages.append({"role": "assistant", "content": text, "tool_calls": tool_calls})
            for tc in tool_calls:
                fn = tc.get("function") or {}
                name = fn.get("name") or tc.get("name")
                raw = fn.get("arguments") if fn else tc.get("arguments")
                try:
                    args = json.loads(raw) if isinstance(raw, str) else (raw or {})
                except Exception:
                    args = {}
                used_tools.append(name)
                out = await _exec_tool(name, args)
                messages.append({"role": "tool", "tool_call_id": tc.get("id"),
                                 "name": name, "content": json.dumps(out)[:8000]})
        else:
            answer = answer or ("The assistant reached the tool-iteration limit "
                                "without a final answer.")

        citations = [n for n in picked if f"[doc:{n}]" in answer] or picked[:2]
        return {"answer": answer, "citations": citations,
                "used_docs": picked, "used_tools": sorted(set(used_tools))}
