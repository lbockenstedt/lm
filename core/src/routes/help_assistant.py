"""Help assistant — LLM-driven docs Q&A + live-state answers.

The LLM backend is the AppBuilder module (it owns the multi-provider LLM layer).
This route only orchestrates: it selects relevant docs (RAG-lite over the ~19
canonical lm/docs files), defines hub-side tools, and runs the agentic loop by
relaying each model turn to the connected ab agent via the HELP_ASK
command (ab runs one call_llm turn, returns {content, tool_calls}).

HARD REQUIREMENT: the feature is only usable when ab is connected —
``/api/help/available`` reports that, and the WebUI hides the "Ask" affordance
otherwise. Routes live under ``/api/help/*`` so the access-control middleware
gates them (valid session required) like every other ``/api/`` route.
"""
from api import HTTPException, Request, logger, os, json, asyncio, access


def register(app, hub, ctx):

    _session_user = ctx._session_user
    _is_admin = ctx._is_admin

    _DOCS_DIR = next(
        (d for d in (
            os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../docs")),
            os.path.abspath(os.path.join(os.path.dirname(__file__), "../../docs")),
        ) if os.path.isdir(d)),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../docs")))

    # Repo root for the source-code search tool (the dir CONTAINING docs/).
    _REPO_ROOT = os.path.dirname(_DOCS_DIR)
    # Also search sibling repos when they're checked out next to this one (the
    # simulations live in the ``cs`` repo, VM plumbing in ``pxmx``) so a "what
    # does simulation X do" answer can quote the ACTUAL sim code. Best-effort:
    # in a production hub deploy only the local repo is usually present, and the
    # missing roots are simply skipped.
    _SRC_ROOTS = [_REPO_ROOT]
    for _sib in ("cs", "pxmx"):
        _sp = os.path.join(os.path.dirname(_REPO_ROOT), _sib)
        if os.path.isdir(_sp) and os.path.abspath(_sp) != os.path.abspath(_REPO_ROOT):
            _SRC_ROOTS.append(os.path.abspath(_sp))
    # Text source we let the assistant grep. Kept to human-authored code/config;
    # binaries, vendored deps, caches, worktrees and anything that looks like a
    # secret file are skipped so nothing sensitive leaks into an answer.
    _SRC_EXTS = {".py", ".js", ".ts", ".tsx", ".sh", ".ps1", ".md", ".html",
                 ".css", ".yaml", ".yml", ".json", ".toml", ".cfg", ".ini"}
    _SRC_SKIP_DIRS = {".git", "venv", ".venv", "node_modules", "__pycache__",
                      ".pytest_cache", ".mypy_cache", "dist", "build", ".claude",
                      ".idea", ".vscode", "site-packages", "coverage", "htmlcov"}
    _SRC_SKIP_FILE_HINTS = (".env", "secret", "credential", ".key", ".pem",
                            ".crt", ".p12", ".pfx", "id_rsa", ".pyc")
    _SRC_MAX_BYTES = 4_000_000        # main.js is ~2MB — keep it searchable
    _SRC_MAX_MATCHES = 14
    _SRC_MAX_FILES = 6000
    _SRC_SNIPPET_CTX = 4              # lines of context above/below a hit

    def _ab_agent():
        """The connected ab agent's spoke_id, or None. ab registers
        as spoke_id 'ab' (config HUB_AGENT_ID); match that, else any
        connected id containing 'ab'."""
        conns = getattr(hub, "active_connections", {}) or {}
        if hub._primary_key("ab") in conns:
            return "ab"
        for sid in conns:
            if "ab" in str(sid).lower():
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

    # ── Phase 2 tools (executed hub-side, scoped to the CALLER) ──────────────
    def _tool_spokes_status(_args, request):
        """Every known spoke/agent + connected/approved/type — answers
        'what's connected' / 'why is my <x> spoke offline'. Tenant-scoped: an
        admin sees the whole fleet; a non-admin sees only spokes bound to their
        own tenant(s) (+ shared), so opening Ask AI to every user can't reveal
        another tenant's infrastructure."""
        sess = _session_user(request)
        is_admin = _is_admin(sess)
        known = hub.state.system_state.get("known_modules", []) or []
        meta = hub.state.system_state.get("module_metadata", {}) or {}
        conns = getattr(hub, "active_connections", {}) or {}
        out = []
        for sid in known:
            if not is_admin:
                tid = hub.state.get_spoke_tenant(sid) or ""
                if not access.spoke_visible_to_session(sess, tid):
                    continue
            out.append({
                "spoke_id": sid,
                "connected": hub._primary_key(sid) in conns,
                "approved": hub.approved_modules.get(hub._primary_key(sid), False),
                "module_type": hub.spoke_module_types.get(hub._primary_key(sid))
                or (meta.get(sid, {}) or {}).get("module_type"),
            })
        return {"spokes": out, "connected_count": sum(1 for s in out if s["connected"])}

    async def _tool_search_devices(args, request):
        """Search the lab for devices/VMs/leases/users/sessions. Delegates to
        the shared, tenant-scoped /api/search handler (cross_system_search) with
        the CALLER's own request, so a non-admin only ever sees their tenant's
        resources — never a hub-wide view. Falls back to a hub-wide fan-out only
        for admins if the shared handler isn't wired up."""
        q = str(args.get("query") or "").strip()
        if not q:
            return {"error": "query required"}

        scoped = getattr(app.state, "cross_system_search", None)
        if scoped is not None:
            try:
                env = await scoped(request, q=q, tenant=None)
                results = (env or {}).get("results", []) if isinstance(env, dict) else []
                return {"query": q, "total": len(results), "results": results[:50]}
            except HTTPException:
                raise
            except Exception as e:  # noqa: BLE001
                return {"query": q, "total": 0, "results": [],
                        "error": f"search failed: {e}"}

        # Fallback (shared handler unavailable): admins only, hub-wide.
        if not _is_admin(_session_user(request)):
            return {"query": q, "total": 0, "results": []}
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

    def _query_terms(q):
        return [w for w in ''.join(c.lower() if c.isalnum() else ' ' for c in q).split()
                if len(w) > 2]

    def _snippets(text, terms, query, max_snips=3, ctx=160):
        """Up to ``max_snips`` context windows around the first matches of the
        full query (preferred) or its individual terms — collapsed to one line."""
        tl = text.lower()
        needles = [query.lower()] if query and query.lower() in tl else \
                  [t for t in terms if t in tl]
        out, seen = [], []
        for nd in needles:
            start = 0
            while len(out) < max_snips:
                i = tl.find(nd, start)
                if i < 0:
                    break
                if not any(abs(i - p) < ctx for p in seen):
                    seen.append(i)
                    a, b = max(0, i - ctx), min(len(text), i + len(nd) + ctx)
                    snip = ' '.join(text[a:b].split())
                    out.append(("…" if a > 0 else "") + snip + ("…" if b < len(text) else ""))
                start = i + len(nd)
            if len(out) >= max_snips:
                break
        return out

    def _tool_search_docs(args):
        """Full-text search across the ENTIRE doc corpus (not just the 4 docs
        pre-selected into the prompt) — lets the model pull a relevant doc the
        keyword pre-selection missed (e.g. a Proxmox question → docs/pxmx.md)."""
        q = str(args.get("query") or "").strip()
        if not q:
            return {"error": "query required"}
        terms = _query_terms(q)
        docs = _load_docs()
        results = []
        for name, text in docs.items():
            tl = text.lower()
            score = (tl.count(q.lower()) * 3) + sum(tl.count(t) for t in terms) \
                + 5 * sum(t in name.lower() for t in terms)
            if score <= 0:
                continue
            results.append({"doc": name, "score": score,
                            "snippets": _snippets(text, terms, q)})
        results.sort(key=lambda r: r["score"], reverse=True)
        return {"query": q, "total": len(results), "results": results[:6]}

    def _tool_search_source(args):
        """Grep the platform SOURCE TREE (this repo + sibling repos like the
        ``cs`` simulations repo; secrets/vendored deps excluded) for a literal
        string or set of words — answers 'where/how is X implemented', 'what
        does simulation Y do', install-command questions, etc. Returns file:line
        hits WITH a short multi-line code snippet so the answer can quote the
        actual implementation. File paths are prefixed with the repo name."""
        q = str(args.get("query") or "").strip()
        if not q:
            return {"error": "query required"}
        ql = q.lower()
        terms = _query_terms(q)
        matches, scanned, done = [], 0, False
        for base in _SRC_ROOTS:
            if done:
                break
            label = os.path.basename(base)
            for root, dirs, files in os.walk(base):
                dirs[:] = [d for d in dirs
                           if d not in _SRC_SKIP_DIRS and not d.startswith(".")]
                for fn in files:
                    if os.path.splitext(fn)[1].lower() not in _SRC_EXTS:
                        continue
                    low = fn.lower()
                    if any(h in low for h in _SRC_SKIP_FILE_HINTS):
                        continue
                    fp = os.path.join(root, fn)
                    try:
                        if os.path.getsize(fp) > _SRC_MAX_BYTES:
                            continue
                        with open(fp, encoding="utf-8", errors="ignore") as f:
                            lines = f.readlines()
                    except Exception:  # noqa: BLE001
                        continue
                    scanned += 1
                    rel = f"{label}/{os.path.relpath(fp, base)}"
                    last = -999
                    for ln, line in enumerate(lines, 1):
                        ll = line.lower()
                        if not (ql in ll or (terms and all(t in ll for t in terms))):
                            continue
                        if ln - last < _SRC_SNIPPET_CTX:   # collapse adjacent hits
                            continue
                        last = ln
                        a = max(0, ln - 1 - _SRC_SNIPPET_CTX)
                        b = min(len(lines), ln + _SRC_SNIPPET_CTX)
                        snippet = ''.join(lines[a:b]).rstrip("\n")[:600]
                        matches.append({"file": rel, "line": ln, "snippet": snippet})
                        if len(matches) >= _SRC_MAX_MATCHES:
                            break
                    if len(matches) >= _SRC_MAX_MATCHES or scanned >= _SRC_MAX_FILES:
                        done = True
                        break
                if done:
                    break
        return {"query": q, "total": len(matches),
                "files_scanned": scanned, "results": matches}

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
        {"type": "function", "function": {
            "name": "search_docs",
            "description": "Full-text search across the ENTIRE documentation corpus "
                           "(all docs, not just the few in the prompt). Use this when "
                           "the documentation shown doesn't cover the question — e.g. "
                           "install/setup commands, a feature or role (Proxmox/pxmx, "
                           "DHCP, SSO...). Returns matching doc names + snippets.",
            "parameters": {"type": "object",
                           "properties": {"query": {"type": "string"}},
                           "required": ["query"]},
        }},
        {"type": "function", "function": {
            "name": "search_source",
            "description": "Search the platform SOURCE CODE + config (this repo plus "
                           "sibling repos like the cs simulations repo) for a string or "
                           "words. Use for 'how/where is X implemented', 'what does "
                           "simulation Y do', exact command flags, env var names, or when "
                           "docs don't answer. Returns file:line hits with a short "
                           "multi-line CODE SNIPPET you can quote back to the user.",
            "parameters": {"type": "object",
                           "properties": {"query": {"type": "string"}},
                           "required": ["query"]},
        }},
    ]

    async def _exec_tool(name, args, request):
        if name == "get_spokes_status":
            return _tool_spokes_status(args, request)
        if name == "search_devices":
            return await _tool_search_devices(args, request)
        if name == "search_docs":
            return _tool_search_docs(args)
        if name == "search_source":
            return _tool_search_source(args)
        return {"error": f"unknown tool: {name}"}

    # ── routes ───────────────────────────────────────────────────────────────
    @app.get("/api/help/available")
    async def help_available():
        """Whether the LLM help assistant is usable (ab connected)."""
        return {"available": _ab_agent() is not None}

    @app.post("/api/help/ask")
    async def help_ask(request: Request):
        agent = _ab_agent()
        if not agent:
            raise HTTPException(status_code=409,
                                detail="Help assistant unavailable — the AppBuilder LLM "
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
            "using the documentation below, the wider docs/source (via tools), and any "
            "live data the tools return. Cite the doc name(s) you used inline as "
            "[doc:<name>]. Tool guidance: call get_spokes_status or search_devices for "
            "questions about the LIVE system; call search_docs to search the FULL "
            "documentation when the docs shown here don't cover the question; call "
            "search_source to look in the SOURCE CODE / config (install commands, flags, "
            "env vars, how a feature works). Do NOT give up just because search_devices "
            "returns 0 results — a question about a feature, setup, or install is a "
            "documentation/source question, so try search_docs and search_source before "
            "concluding. When the user asks what a SIMULATION or feature DOES, first "
            "explain it in plain, non-technical language (what it simulates, why, what "
            "the user sees), THEN show a few short CODE SNIPPETS from search_source as "
            "fenced code blocks, each labeled with its `file:line`, so the user can go "
            "look at the actual implementation. Be efficient with tools: a couple of "
            "focused searches is enough — once you have the relevant docs/code, STOP "
            "calling tools and write the answer. If, after checking docs, source, and "
            "live data, the answer genuinely isn't there, say so plainly. Be concise "
            "and concrete.\n\n"
            "=== DOCUMENTATION ===\n" + doc_ctx
        )
        messages = [{"role": "user", "content": question}]
        used_tools = []
        answer = ""
        for _ in range(8):
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
                out = await _exec_tool(name, args, request)
                messages.append({"role": "tool", "tool_call_id": tc.get("id"),
                                 "name": name, "content": json.dumps(out)[:8000]})
        else:
            # Hit the tool-call budget without a text answer (the model kept
            # searching). Don't give up — force ONE final turn with tools
            # DISABLED so it must synthesize an answer from everything the tools
            # already returned (all of it is in `messages`).
            logger.info("help_ask: tool budget reached (%d calls) — forcing a "
                        "tool-free synthesis turn", len(used_tools))
            try:
                res = await hub.request_response(
                    agent, "HELP_ASK",
                    {"messages": messages + [{"role": "user", "content": (
                        "Stop searching and answer my question NOW using the "
                        "documentation, code snippets, and data you already gathered "
                        "above. Quote the most relevant code with its file:line. If "
                        "something is still unknown, explain what you DO know and note "
                        "the gap.")}],
                     "tools": None, "system": system},
                    timeout=90.0)
                data = res.get("payload", {}).get("data", res) if isinstance(res, dict) else {}
                if isinstance(data, dict) and data.get("status") == "SUCCESS":
                    answer = (data.get("assistant") or {}).get("content") or answer
            except Exception as e:  # noqa: BLE001
                logger.warning("help_ask forced-synthesis turn failed: %s", e)
            if not answer:
                answer = ("I gathered documentation and code for this but couldn't "
                          "compose a final answer. Please try rephrasing, or ask about "
                          "a narrower part of it.")

        def _degenerate(a):
            # Some local models emit a broken/empty function call instead of a real
            # tool call or a text answer — the literal token leaks through as
            # content. Two known shapes:
            #   1) glm-style: bare "tool_calls" (optionally wrapped in `*[]{}"'`).
            #   2) Qwen2.5(-coder)-style: XML tags, e.g. "<tool_call>\n{...}\n
            #      </tool_call>" — its NATIVE function-call format when Ollama's
            #      structured tool_calls parsing doesn't fully capture the turn.
            #      `<`/`>` aren't in the strip() charset, so shape 1's prefix check
            #      never matched this and it leaked straight to the user as the
            #      literal answer text.
            # Treat both as "no answer": strict prefix match after stripping
            # common wrapper punctuation (angle brackets included), PLUS a bounded
            # substring check for a short response — a genuine long answer is very
            # unlikely to contain this token at all, so the substring check can't
            # reasonably false-positive on real prose.
            s = (a or "").strip().lower().strip("`*[]{}<>\"' ")
            if not s or s.startswith("tool_call"):
                return True
            return len(s) < 80 and "tool_call" in s

        if _degenerate(answer):
            # Fall back to ONE plain-text turn with tools DISABLED so the user still
            # gets a doc-grounded answer instead of the raw "tool_calls" token.
            logger.info("help_ask: degenerate tool-loop answer (%r) — retrying tool-free",
                        answer[:40])
            try:
                res = await hub.request_response(
                    agent, "HELP_ASK",
                    {"messages": [{"role": "user", "content": question}], "tools": None,
                     "system": system + "\n\nAnswer directly in plain text using the "
                                        "documentation above. Do NOT call tools."},
                    timeout=90.0)
                data = res.get("payload", {}).get("data", res) if isinstance(res, dict) else {}
                if isinstance(data, dict) and data.get("status") == "SUCCESS":
                    answer = (data.get("assistant") or {}).get("content") or answer
            except Exception as e:  # noqa: BLE001
                logger.warning("help_ask tool-free fallback failed: %s", e)
            if _degenerate(answer):
                answer = ("I couldn't get a usable answer from the current LLM provider "
                          "(it didn't return a proper response). Try again, or switch the "
                          "AppBuilder provider in Settings.")

        citations = [n for n in picked if f"[doc:{n}]" in answer] or picked[:2]
        return {"answer": answer, "citations": citations,
                "used_docs": picked, "used_tools": sorted(set(used_tools))}
