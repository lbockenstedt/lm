"""The shared spoke-not-connected 503 emits ONE generic, module-agnostic
message.

A missing spoke is the same condition for every module, so the WebUI should
never show a module-branded string (was e.g. "No CPPM spoke connected",
"Client-Sim spoke not connected"). ``api.spoke_or_503`` / ``get_spoke_or_503``
are the shared tail behind ~all module 503 preambles; this pins that the
``label`` argument (kept for readability/logging) never leaks into the 503
``detail`` — it is always the generic "No spoke connected".
"""
import pytest

from fastapi import HTTPException

import api


def test_spoke_or_503_raises_generic_when_empty():
    with pytest.raises(HTTPException) as ei:
        api.spoke_or_503("", "CPPM")
    assert ei.value.status_code == 503
    assert ei.value.detail == "No spoke connected"


def test_spoke_or_503_message_ignores_label():
    """Different module labels must all yield the identical generic detail."""
    details = set()
    for label in ("CPPM", "Client-Sim", "NetBox", "Console", "DNS"):
        with pytest.raises(HTTPException) as ei:
            api.spoke_or_503(None, label)
        details.add(ei.value.detail)
    assert details == {"No spoke connected"}


def test_spoke_or_503_passes_through_a_live_spoke():
    assert api.spoke_or_503("cppm-1", "CPPM") == "cppm-1"


class _Hub:
    def __init__(self, sid):
        self._sid = sid

    def get_spoke_by_type(self, module_type):
        return self._sid


def test_get_spoke_or_503_generic_when_none_connected():
    with pytest.raises(HTTPException) as ei:
        api.get_spoke_or_503(_Hub(None), "nac", "Security / NAC")
    assert ei.value.status_code == 503
    assert ei.value.detail == "No spoke connected"


def test_get_spoke_or_503_returns_connected_spoke():
    assert api.get_spoke_or_503(_Hub("nac-1"), "nac", "Security / NAC") == "nac-1"
