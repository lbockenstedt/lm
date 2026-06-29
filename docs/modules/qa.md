# QA Module Guide

The `qa/` package is the LM QA harness — a mock spoke (`QASpokeMock`) used to exercise the Hub's mutual authentication and command routing end-to-end without a real managed host.

## 1. Capabilities
- **Auth round-trip testing** — performs the full HMAC-SHA256 challenge/response handshake against the Hub.
- **Command routing testing** — sends sample commands and asserts the Hub routes + responds correctly.
- **Config via `.env`** — reads `HUB_URL`, spoke ID, and secrets from a local `.env` for repeatable runs.

## 2. Usage
Run from the `qa/` directory (after `pip install -r requirements.txt`):

```
python src/qa_tester.py
```

Configure `HUB_URL`, `SPOKE_ID`, `SPOKE_SECRET` (and `HUB_SECRET` if needed) in a `.env` next to the script, or export them in the environment.

## 3. Technical implementation (`qa/src/`)
| Path | Role |
|------|------|
| `qa_tester.py` | `QASpokeMock` — the mock spoke lifecycle (connect, auth, command, assert). |

This is a test harness, not a production spoke — it does not register as a permanent managed node and is not deployed via an install script.