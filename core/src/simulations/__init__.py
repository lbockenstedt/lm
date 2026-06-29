"""LM hub Simulations module — serves the ported Client-Sim (solutions-hpe)
operator UI under ``/sim`` and its read/action API under ``/sim/api``.

Data source: ``hub.simulations_cache[spoke_id]`` — the latest ``CS_TELEMETRY``
frame pushed by the combined Client-Sim spoke over the LM websocket.

Submodules:
- ``broadcaster`` — tenant-scoped browser broadcast over ``/sim/ws``.
- ``service``     — pure read functions (dashboard/clients/simulations/proxmox/
  central/config) shaping cached telemetry into the cs webui-hub API contract.
- ``store``       — slim per-tenant cs-specific config persistence (overrides,
  usb vidpids, processing mode, ...). Fleshed out by Phase 4 actions.
- ``routes``      — registers ``/sim/api/*`` + ``/sim/ws`` on the FastAPI app,
  reusing lm/core's closure-route + auth-helper convention.
"""