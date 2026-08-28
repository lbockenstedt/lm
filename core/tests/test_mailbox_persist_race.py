"""Mailbox persist is offloaded to a thread and fired on every
ack/push/retry/flush, so concurrent saves used to share ONE fixed
``mailbox.json.tmp``: the first ``os.replace`` consumed it and the second
failed with ENOENT, silently losing that persist (and, across a hub restart,
a queued approval). ``_save`` now uses a mkstemp-unique temp per write. Hammer
it concurrently and assert zero failures / zero leftover temps."""
import os
import tempfile
import threading

# No security.encryption stub: this module used to assign one into sys.modules
# at import time and never remove it, so every test module collected afterwards
# saw the stub instead of the real package. The conftest already exports a
# throwaway LM_FERNET_KEY, which is the only reason the stub existed, so the
# real module imports fine.
from messaging.mailbox import Mailbox


def _bare_mailbox(path):
    mb = Mailbox.__new__(Mailbox)
    mb._path = path
    mb.pending_ack = {}
    mb.spoke_queues = {}
    return mb


def test_concurrent_saves_no_enoent_race():
    d = tempfile.mkdtemp()
    mb = _bare_mailbox(os.path.join(d, "mailbox.json"))
    errs = []

    def hammer():
        for _ in range(150):
            try:
                mb._save()
            except Exception as e:  # noqa: BLE001
                errs.append(e)

    threads = [threading.Thread(target=hammer) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errs == [], f"_save raced under concurrency: {errs[:3]}"
    leftover = [f for f in os.listdir(d) if f.endswith(".tmp")]
    assert leftover == [], f"leftover temp files: {leftover}"
    assert os.path.exists(mb._path)
