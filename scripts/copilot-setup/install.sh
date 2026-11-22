#!/usr/bin/env bash
# install.sh: optional Copilot CLI setup for the fleet. Safe to re-run.
#
# Optional. A session in a fleet repo already reads the rules, agents, skills and
# spend gate from the repo: AGENTS.md, .github/copilot-instructions.md,
# .github/agents, .claude/skills and the gate hook (.github/hooks/fleet-hooks.json,
# once the folder is trusted). This script adds what a repo cannot:
#   (default) links in the fleet folder, so a session started in the fleet folder
#     itself (not inside a repo) sees the same rules, agents and Copilot
#     instructions; plus settings.json (coordinator model and effort from
#     model-policy.json, and lm's skills folder). Other keys already there
#     (allowed URLs, ...) are kept.
#   --gate: the daily AI spend gate (fleet rule 1.10) as a user-wide hook, so it
#     also covers sessions outside fleet repos. Once a day's cloud spend reaches
#     gate_usd ($100, .github/ai-budget.json) the agent stops; a person reopens it
#     with `ai_budget.py continue [USD]`.
#   --local: the local-model setup (agents, providers.json, the thinking-off proxy,
#     and local-models.md as ~/.copilot/instructions/local-models.instructions.md).
#   --models: also pull the Ollama models.
#   Models and effort come from lm/.github/model-policy.json, so re-run this after
#   the policy changes.
#
#   bash install.sh                     links and settings
#   bash install.sh --gate              also the user-wide spend gate
#   bash install.sh --local             also the local-model setup (needs Ollama; see README.md)
#   bash install.sh --local --models    also pull the Ollama models (about 50 GB)
#
# Run it from a checkout of lm that stays put (not a temporary worktree): the gate
# hook and settings point at files copied into ~/.copilot, and the skills folder
# is read from this checkout.
# A file that would change is first copied to <file>.bak-<timestamp>.
# ~/.copilot/ollama-proxy/pools.json (hosts that share a model) is per machine
# and never written here; see README.md.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
LM=$(cd "$HERE/../.." && pwd)
FLEET=$(dirname "$LM")
C="${COPILOT_HOME:-$HOME/.copilot}"
POLICY="$LM/.github/model-policy.json"
STAMP=$(date +%Y%m%d%H%M%S)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
GATE=0 LOCAL=0 MODELS=0
for arg in "$@"; do
  case "$arg" in
    --gate) GATE=1 ;;
    --local) LOCAL=1 ;;
    --models) LOCAL=1 MODELS=1 ;;
    *) echo "Unknown option: $arg (use --gate, --local, --models)"; exit 2 ;;
  esac
done

# put SRC DEST: copy a file, keeping a backup of a different existing one.
put() {
  mkdir -p "$(dirname "$2")"
  if [ -f "$2" ] && ! cmp -s "$1" "$2"; then cp "$2" "$2.bak-$STAMP"; echo "backed up $2"; fi
  cp "$1" "$2"
}

# 1. The spend gate (--gate only): script and numbers copied in, hook file moved in
#    whole so the CLI never reads half a file.
if [ "$GATE" = 1 ]; then
PY="$C/ai-budget/hooks/ai_budget.py"
put "$LM/.github/hooks/ai_budget.py" "$PY"
put "$LM/.github/ai-budget.json" "$C/ai-budget/ai-budget.json"
cat > "$TMP/hook.json" <<EOF
{
  "version": 1,
  "hooks": {
    "sessionStart": [{"type": "command", "bash": "python3 $PY context || true", "timeoutSec": 10}],
    "subagentStart": [{"type": "command", "bash": "python3 $PY context || true", "timeoutSec": 10}],
    "preToolUse": [{"type": "command", "bash": "python3 $PY check || true", "timeoutSec": 10}]
  }
}
EOF
python3 -m json.tool "$TMP/hook.json" > /dev/null
put "$TMP/hook.json" "$C/hooks/ai-budget.json"
fi

# 2. settings.json: set only the keys this setup owns
mkdir -p "$C"
[ -f "$C/settings.json" ] && cp "$C/settings.json" "$C/settings.json.bak-$STAMP"
python3 - "$C/settings.json" "$LM/.claude/skills" "$POLICY" <<'EOF'
import json, os, sys
path, skills, policy = sys.argv[1:]
pol = json.load(open(policy))
cfg = json.load(open(path)) if os.path.exists(path) else {}
cfg["model"] = pol["coordinator"]["model"]
cfg["effortLevel"] = pol["effort"]
dirs = cfg.get("skillDirectories") or []
if skills not in [os.path.expanduser(d) for d in dirs]:
    dirs.append(skills)
cfg["skillDirectories"] = dirs
json.dump(cfg, open(path, "w"), indent=2)
print("settings.json: model %s, effort %s, skills %s" % (cfg["model"], cfg["effortLevel"], skills))
EOF

# 3. Fleet-wide links, so every repo under the fleet folder sees lm's rules
[ -e "$FLEET/AGENTS.md" ] || ln -s lm/.github/fleet-rules.md "$FLEET/AGENTS.md"
mkdir -p "$FLEET/.github"
[ -e "$FLEET/.github/agents" ] || ln -s ../lm/.github/agents "$FLEET/.github/agents"
[ -e "$FLEET/.github/copilot-instructions.md" ] || ln -s ../lm/.github/copilot-instructions.md "$FLEET/.github/copilot-instructions.md"

# Old copies from the previous installer: reported only, never deleted.
OLD="$C/copilot-instructions.md"
if [ -f "$OLD" ] && grep -qxF '# Copilot rules for the Lab Manager fleet (all repos)' "$OLD"; then
  echo "note: $OLD holds an old installed copy of the fleet rules; they now load from the repo, so remove that file (or its fleet section)"
fi
for a in "$C/agents/cloud-coder.agent.md" "$C/agents/cloud-coder-plus.agent.md"; do
  if [ -f "$a" ]; then echo "note: $a is an old installed copy; the agent now loads from the repo's .github/agents, so remove it"; fi
done

# 4. Optional local models: agents, provider list, proxy, rules, statistics
if [ "$LOCAL" = 1 ]; then
  for a in "$HERE"/agents-local/*.agent.md; do put "$a" "$C/agents/$(basename "$a")"; done
  put "$HERE/providers.json" "$C/providers.json"
  put "$HERE/local-models.md" "$C/instructions/local-models.instructions.md"
  put "$HERE/ollama-proxy/proxy.py" "$C/ollama-proxy/proxy.py"
  if [ "$(uname -s)" != Darwin ]; then
    echo "Not macOS: start the proxy yourself: python3 $C/ollama-proxy/proxy.py &"
  elif launchctl list | grep -q 'ollama-proxy'; then
    # Already running (this or an older label): it reloads proxy.py on restart.
    echo "proxy: already running; restart it to load a changed proxy.py"
  else
    P="$HOME/Library/LaunchAgents/com.copilot.ollama-proxy.plist"
    cat > "$P" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.copilot.ollama-proxy</string>
  <key>ProgramArguments</key>
  <array><string>/usr/bin/python3</string><string>$C/ollama-proxy/proxy.py</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>$C/ollama-proxy/proxy.log</string>
</dict>
</plist>
EOF
    launchctl load "$P"
    echo "proxy: launchd agent com.copilot.ollama-proxy loaded"
  fi
fi
if [ "$MODELS" = 1 ]; then
  command -v ollama > /dev/null || { echo "Install Ollama first: https://ollama.com"; exit 1; }
  # base model -> the 64k-context alias the local agents name
  for pair in qwen3.6-35b-coding-64k=qwen3.6:35b-a3b-coding qwen3.8-27b-64k=qwen3.8:27b-mlx gemma4-12b-64k=gemma4:12b; do
    alias=${pair%%=*}; base=${pair#*=}
    ollama show "$alias" > /dev/null 2>&1 && continue
    ollama pull "$base"
    printf 'FROM %s\nPARAMETER num_ctx 65536\n' "$base" | ollama create "$alias" -f -
  done
fi

if [ "$GATE" = 1 ]; then python3 "$PY" status; else python3 "$LM/.github/hooks/ai_budget.py" status; fi
echo "Done. Restart Copilot CLI to load the changes."
