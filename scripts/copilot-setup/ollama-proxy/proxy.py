#!/usr/bin/env python3
"""Tiny pass-through proxy in front of Ollama's OpenAI-compatible API.

Copilot CLI sends reasoning_effort="medium" to local models (or omits it,
which Ollama treats as thinking on). Thinking costs hundreds of hidden tokens
per step: a local-coder edit took 6 min instead of 70 s, and longer jobs
stalled for 45+ min. This proxy forces reasoning_effort="none" on every chat
call so our local models always run with thinking off.
Stdlib only. Listens on 127.0.0.1:11435, forwards to 127.0.0.1:11434.

Spreading load: models listed in POOLS can also run on other Ollama hosts
(the same model alias must exist there). Each agent conversation is pinned to
one host, keyed on its first two messages, so Ollama's prompt cache keeps
working across turns. A new conversation goes to the host with the fewest
conversations active in the last 10 minutes (ties go to the first host
listed, the fastest). If a remote host can't be reached, the request falls
back to the local Ollama.

llama.cpp: requests under /llamacpp/ (the "llamacpp" provider in
providers.json) go to the llama-server router on 127.0.0.1:18080 that
setup-llm.sh installs in ~/llm, with the prefix removed. Thinking is turned
off there too, also through chat_template_kwargs, which is what llama-server's
chat templates read (Qwen's enable_thinking, DeepSeek's thinking).
"""
import ast
import hashlib
import http.client
import json
import os
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

UPSTREAM = ("127.0.0.1", 11434)
LISTEN = ("127.0.0.1", int(os.environ.get("PROXY_PORT", "11435")))
LOG = os.environ.get("PROXY_LOG")  # optional: log request keys for debugging

# Model -> hosts that serve it, fastest first, read from pools.json beside this
# file so lab hosts stay out of the code, e.g.
#   {"qwen3.8-27b-64k": [["192.0.2.10", 11434], ["127.0.0.1", 11434]]}
# A pooled model goes to the least busy host. With no file nothing is pooled and
# every call goes to the local Ollama. Measured Nov 2026: a second GPU Mac read
# prompts at 274 tok/s vs ~110 on this Mac; a CPU-only host (18 tok/s) is far
# too slow for a ~20k-token agent prompt, so don't pool one.
def _load_pools():
    """Model -> [(host, port)] from pools.json next to this script, or {}."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pools.json")
    try:
        with open(path) as f:
            return {m: [tuple(h) for h in hosts] for m, hosts in json.load(f).items()}
    except FileNotFoundError:
        return {}


POOLS = _load_pools()
LLAMACPP = ("127.0.0.1", 18080)  # llama-server router for the big streamed models (~/llm)
ACTIVE_S = 600
_pins = {}  # conversation key -> (host, last seen)
_lock = threading.Lock()

# Statistics: one JSON line per chat call, in a monthly file, so failure rates and
# their causes can be analysed later (see ~/.copilot/local-stats/localstat.py).
STATS_DIR = os.path.expanduser(os.environ.get("LOCAL_STATS_DIR", "~/.copilot/local-stats"))
CAPTURE_MAX = 4 * 1024 * 1024  # response bytes kept for analysis; the client still gets everything
EDIT_TOOLS = ("edit", "create", "apply_patch", "write")
TOOL_ERROR_HINTS = ("error", "failed", "no match", "not found", "multiple matches", "invalid", "denied")
_stats_lock = threading.Lock()


def conv_key(req):
    """Identify an agent conversation by its first two messages (stable across its turns)."""
    msgs = req.get("messages") or []
    return hashlib.sha1(json.dumps(msgs[:2], sort_keys=True).encode()).hexdigest()


def pick_upstream(req):
    """Return the host for this request: the conversation's pinned host, or the least busy one."""
    hosts = POOLS.get(str(req.get("model", "")))
    if not hosts:
        return UPSTREAM
    key = conv_key(req)
    now = time.time()
    with _lock:
        # Forget conversations idle for longer than ACTIVE_S.
        for k in [k for k, (_, seen) in _pins.items() if now - seen > ACTIVE_S]:
            del _pins[k]
        host = _pins.get(key, (None, 0))[0]
        if host is None:
            busy = {h: 0 for h in hosts}
            for h, _ in _pins.values():
                if h in busy:
                    busy[h] += 1
            host = min(hosts, key=lambda h: busy[h])
            print(f"new conversation {key[:8]} -> {host[0]} (busy {busy})", file=sys.stderr, flush=True)
        _pins[key] = (host, now)
    return host


def _text(content):
    """Flatten an OpenAI message content (string or list of parts) to text."""
    if isinstance(content, list):
        return " ".join(str(p.get("text", "")) for p in content if isinstance(p, dict))
    return str(content or "")


def describe_request(req):
    """Summarise a chat request for the stats log: agent, turn, prompt size, prior tool errors."""
    msgs = req.get("messages") or []
    tools = [str((t.get("function") or {}).get("name", "")) for t in req.get("tools") or []]
    model = str(req.get("model", ""))
    # Agent: each local agent's prompt carries an "[agent:<name>]" marker; the
    # tool/model guess below only covers agent files written before the marker.
    marker = re.search(r"\[agent:([a-z0-9-]+)\]", " ".join(_text(m.get("content")) for m in msgs if m.get("role") == "system"))
    if marker:
        agent = marker.group(1)
    elif not tools:
        agent = "direct"
    elif any(t.startswith(EDIT_TOOLS) for t in tools):
        agent = "local-coder"
    elif model.startswith("gemma"):
        agent = "local-summarizer"
    else:
        agent = "local-scout"
    meta = {"model": model, "agent": agent, "conv": conv_key(req)[:10],
            "turn": sum(1 for m in msgs if m.get("role") == "assistant"),
            "msgs": len(msgs), "prompt_chars": sum(len(_text(m.get("content"))) for m in msgs),
            "n_tools": len(tools), "temperature": req.get("temperature"), "stream": bool(req.get("stream"))}
    if meta["turn"] == 0:
        user = [m for m in msgs if m.get("role") == "user"]
        meta["task"] = _text(user[-1].get("content"))[:400] if user else ""
    # Results of the tool calls made last turn: count the ones that failed (e.g. edit with no match).
    errs = []
    for m in reversed(msgs):
        if m.get("role") != "tool":
            break
        t = _text(m.get("content"))
        if any(h in t[:200].lower() for h in TOOL_ERROR_HINTS):
            errs.append(t[:160])
    meta["prev_tool_errors"] = len(errs)
    if errs:
        meta["prev_tool_error_text"] = errs
    return meta


def parse_response(raw):
    """Extract text, tool calls, finish reason and usage from an SSE stream or a JSON reply."""
    text, calls, finish, usage = "", {}, None, None
    # A plain JSON reply is one chunk; an SSE stream is one chunk per data line.
    chunks = []
    if raw.lstrip().startswith(b"{"):
        chunks = [json.loads(raw)]
    else:
        for line in raw.decode("utf-8", "replace").splitlines():
            if line.startswith("data: ") and line != "data: [DONE]":
                try:
                    chunks.append(json.loads(line[6:]))
                except ValueError:
                    pass
    # Join the chunks: text and tool-call fragments are appended in order.
    for c in chunks:
        usage = c.get("usage") or usage
        for ch in c.get("choices") or []:
            d = ch.get("delta") or ch.get("message") or {}
            text += d.get("content") or ""
            finish = ch.get("finish_reason") or finish
            for i, tc in enumerate(d.get("tool_calls") or []):
                slot = calls.setdefault(tc.get("index", i), {"name": "", "args": ""})
                f = tc.get("function") or {}
                slot["name"] += f.get("name") or ""
                slot["args"] += f.get("arguments") or ""
    return text, [calls[k] for k in sorted(calls)], finish, usage


def indent_drift(old, new):
    """Count new lines that match an old line except for a one-space indent shift.

    That is the signature of the MLX runner bug (a stray space before some
    indented lines); odd indents alone are normal in Python continuation lines."""
    old_ind = {}
    for ln in old.splitlines():
        if ln.strip():
            old_ind.setdefault(ln.strip(), set()).add(len(ln) - len(ln.lstrip(" ")))
    n = 0
    for ln in new.splitlines():
        ind = len(ln) - len(ln.lstrip(" "))
        seen = old_ind.get(ln.strip())
        if seen and ind not in seen and any(abs(ind - i) == 1 for i in seen):
            n += 1
    return n


def code_checks(name, args):
    """Return (indent_drift, py_syntax_error) for one edit-type tool call on a .py file."""
    if not (name.startswith(EDIT_TOOLS) and isinstance(args, dict) and str(args.get("path", "")).endswith(".py")):
        return 0, False
    drift = indent_drift(args.get("old_str") or "", args.get("new_str") or "")
    full = next((args[k] for k in ("file_text", "content") if isinstance(args.get(k), str)), None)
    if full is None:
        return drift, False
    try:
        ast.parse(full)
        return drift, False
    except SyntaxError:
        return drift, True


def log_call(meta, status, raw, t0, ttft, error):
    """Append one call record to the monthly stats file; never raises."""
    try:
        rec = dict(meta, ts=time.strftime("%Y-%m-%dT%H:%M:%S"), status=status, error=error,
                   duration_s=round(time.time() - t0, 2), ttft_s=round(ttft - t0, 2) if ttft else None)
        if raw:
            text, calls, finish, usage = parse_response(bytes(raw))
            bad_args, drift, syntax = 0, 0, 0
            for c in calls:
                try:
                    args = json.loads(c["args"] or "{}")
                except ValueError:
                    bad_args += 1
                    continue
                d, s = code_checks(c["name"], args)
                drift, syntax = drift + d, syntax + int(s)
            rec.update(finish=finish, out_chars=len(text), tool_calls=[c["name"] for c in calls],
                       bad_tool_args=bad_args, indent_drift=drift, py_syntax_error=syntax,
                       think_leak="<think>" in text, empty=status == 200 and not text.strip() and not calls,
                       truncated=len(raw) >= CAPTURE_MAX)
            if usage:
                rec.update(prompt_tokens=usage.get("prompt_tokens"), completion_tokens=usage.get("completion_tokens"))
            if not calls and text:
                rec["reply_head"] = text[:300]
        os.makedirs(STATS_DIR, exist_ok=True)
        path = os.path.join(STATS_DIR, time.strftime("calls-%Y-%m.jsonl"))
        with _stats_lock, open(path, "a") as f:
            f.write(json.dumps(rec) + "\n")
    except Exception as e:  # stats must never break a request
        print(f"stats log failed: {e}", file=sys.stderr, flush=True)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _forward(self):
        """Relay one request upstream (Ollama, a pool member or llama.cpp) and log it."""
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        upstream, path = UPSTREAM, self.path
        llamacpp = path.startswith("/llamacpp/")
        if llamacpp:
            upstream, path = LLAMACPP, path[len("/llamacpp"):]
        meta, t0 = None, time.time()
        if self.path.endswith("/chat/completions") and body:
            req = json.loads(body)
            try:
                meta = describe_request(req)
            except Exception as e:
                print(f"stats describe failed: {e}", file=sys.stderr, flush=True)
            if LOG:
                with open(LOG, "a") as f:
                    f.write(json.dumps({k: v for k, v in req.items() if k not in ("messages", "tools")}) + "\n")
            req["reasoning_effort"] = "none"
            # Copilot sends temperature 1; gemma was less reliable there (bench: 6.17 vs 6.5/7 at 0.7).
            if str(req.get("model", "")).startswith("gemma"):
                req["temperature"] = min(req.get("temperature", 0.7), 0.7)
                req["top_p"] = 0.8
            if llamacpp:
                req["chat_template_kwargs"] = {"enable_thinking": False, "thinking": False}
            body = json.dumps(req).encode()
            if not llamacpp:
                upstream = pick_upstream(req)
        headers = {k: v for k, v in self.headers.items() if k.lower() not in ("host", "content-length", "connection")}
        headers["Content-Length"] = str(len(body))
        if meta:
            meta["host"] = upstream[0]
        raw, ttft, status, error = bytearray(), None, None, None
        try:
            try:
                up = http.client.HTTPConnection(*upstream, timeout=1800)
                up.request(self.command, path, body=body if body else None, headers=headers)
            except OSError as e:
                # Remote host down: serve this request locally instead. Ollama
                # doesn't have the llama.cpp models, so those fail here.
                if llamacpp:
                    raise
                print(f"upstream {upstream[0]} failed ({e}); using local", file=sys.stderr, flush=True)
                if meta:
                    meta.update(host=UPSTREAM[0], fallback_from=upstream[0])
                up = http.client.HTTPConnection(*UPSTREAM, timeout=1800)
                up.request(self.command, self.path, body=body if body else None, headers=headers)
            resp = up.getresponse()
            status = resp.status
            self.send_response(resp.status)
            for k, v in resp.getheaders():
                if k.lower() not in ("content-length", "transfer-encoding", "connection"):
                    self.send_header(k, v)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            while True:
                chunk = resp.read1(65536)
                if not chunk:
                    break
                if meta is not None:
                    ttft = ttft or time.time()
                    if len(raw) < CAPTURE_MAX:
                        raw.extend(chunk[:CAPTURE_MAX - len(raw)])
                self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
                self.wfile.flush()
            self.wfile.write(b"0\r\n\r\n")
            up.close()
        except Exception as e:
            error = f"{type(e).__name__}: {e}"[:300]
            raise
        finally:
            if meta is not None:
                log_call(meta, status, raw, t0, ttft, error)

    do_GET = do_POST = do_DELETE = _forward

    def log_message(self, *args):
        """Silence the per-request access log; calls are logged to JSON Lines instead."""
        pass


if __name__ == "__main__":
    print(f"ollama-proxy on {LISTEN[0]}:{LISTEN[1]} -> {UPSTREAM[0]}:{UPSTREAM[1]}", file=sys.stderr, flush=True)
    ThreadingHTTPServer(LISTEN, Handler).serve_forever()
