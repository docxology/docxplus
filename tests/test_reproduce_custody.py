"""Real production bubblewrap boundaries; no replacement/disabled sandbox path."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from docxplus import reproduce
from docxplus.reproduce import ReproSpec

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="requires real Linux PID/proc namespaces")


def _namespace_members(identity: str) -> list[tuple[int, str]]:
    """Observe namespace custody from the outer procfs as (pid, state) pairs.

    A killed descendant can remain a zombie in the namespace until whichever
    reaper adopted it collects it; a zombie holds no execution or file access.
    """
    members = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            if os.readlink(entry / "ns/pid") == identity:
                status = (entry / "status").read_text()
                state = next(line.split()[1] for line in status.splitlines()
                             if line.startswith("State:"))
                members.append((int(entry.name), state))
        except (FileNotFoundError, ProcessLookupError, PermissionError, StopIteration):
            continue
    return members


@pytest.mark.parametrize("new_session", [False, True])
@pytest.mark.parametrize("timeout", [False, True])
def test_production_backend_joins_descendant_namespace(tmp_path, new_session, timeout):
    """DEL3: success and timeout retain ordinary and setsid descendant custody."""
    project = tmp_path / "project"
    project.mkdir()
    child = "from pathlib import Path; import time; time.sleep(5); Path('late').write_text('escaped')"
    # The leader records the namespace before spawning, so the identity is
    # available even when the run itself is killed by its deadline.
    command = (
        "import os,subprocess,sys,time; from pathlib import Path\n"
        "Path('custody.json').write_text(os.readlink('/proc/self/ns/pid'))\n"
        f"subprocess.Popen([sys.executable,'-c',{child!r}],start_new_session={new_session!r})\n"
        "Path('result').write_text('computed')\n"
        + ("time.sleep(30)\n" if timeout else "")
    )
    spec = ReproSpec([sys.executable, "-c", command], ["result"], timeout=2 if timeout else 10)
    if timeout:
        with pytest.raises(reproduce.ReproError):
            reproduce.run_and_digest(project, spec)
    else:
        reproduce.run_and_digest(project, spec)
    identity = (project / "custody.json").read_text()
    assert identity != os.readlink("/proc/self/ns/pid")
    members = _namespace_members(identity)
    assert [member for member in members if member[1] != "Z"] == [], (
        f"live processes remain in the owned namespace: {members}"
    )
    # Liveness is asserted here; the dedicated
    # test_successful_reproduction_does_not_leave_a_writing_descendant proves the
    # killed descendant cannot keep writing after the leader exits.


def test_missing_pidfd_support_refuses_before_execution(tmp_path, monkeypatch):
    """Without pidfd the namespace leader cannot be owned, so nothing may run."""
    def unavailable(*args, **kwargs):
        raise OSError(38, "Function not implemented")

    monkeypatch.setattr(reproduce.os, "pidfd_open", unavailable)
    project = tmp_path / "project"
    project.mkdir()
    with pytest.raises(reproduce.ReproError, match="pidfd"):
        reproduce.run_and_digest(
            project,
            ReproSpec([sys.executable, "-c", "open('result','w').write('ran')"],
                      ["result"], timeout=10),
        )
    assert not (project / "result").exists()


def test_production_backend_blocks_ancestor_proc_roots_fds_and_signaling(tmp_path):
    """DEL2: a real same-UID ancestor helper cannot lend its writable mount/fd view."""
    project = tmp_path / "project"
    project.mkdir()
    canary = tmp_path / "outer-canary"
    ready = tmp_path / "outer-ready"
    signaled = tmp_path / "outer-signaled"
    canary.write_text("untouched")
    helper = (
        "import json,os,signal,sys,time; from pathlib import Path\n"
        "fd=os.open(sys.argv[1],os.O_RDWR)\n"
        "signal.signal(signal.SIGUSR1,lambda *_: Path(sys.argv[3]).write_text('signaled'))\n"
        "Path(sys.argv[2]).write_text(json.dumps({'fd':fd}))\n"
        "time.sleep(60)\n"
    )
    victim = subprocess.Popen(
        [sys.executable, "-c", helper, str(canary), str(ready), str(signaled)],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 5
        while not ready.exists() and victim.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        assert ready.exists(), "real outer helper did not start"
        fd = json.loads(ready.read_text())["fd"]
        targets = [str(canary), f"/proc/{victim.pid}/root{canary}", f"/proc/{victim.pid}/fd/{fd}"]
        command = (
            "import json,os,signal,socket; from pathlib import Path\n"
            "denied=[]\n"
            f"for target in {targets!r}:\n"
            "    try:\n"
            "        with open(target,'w') as stream: stream.write('escaped')\n"
            "    except OSError: denied.append(True)\n"
            "    else: denied.append(False)\n"
            f"try: os.kill({victim.pid},signal.SIGUSR1)\n"
            "except OSError: signal_denied=True\n"
            "else: signal_denied=False\n"
            "sock=socket.socket(); sock.settimeout(0.2)\n"
            "try: sock.connect(('1.1.1.1',53))\n"
            "except OSError: network_denied=True\n"
            "else: network_denied=False\n"
            "finally: sock.close()\n"
            "scratch=Path(os.environ['TMPDIR'])/'scratch-positive'; scratch.write_text('allowed')\n"
            "Path('result').write_text(json.dumps({'denied':denied,'signal_denied':signal_denied,"
            "'network_denied':network_denied,'pid':os.readlink('/proc/self/ns/pid'),"
            "'net':os.readlink('/proc/self/ns/net'),'scratch':scratch.read_text()}))\n"
        )
        reproduce.run_and_digest(project, ReproSpec([sys.executable, "-c", command], ["result"], timeout=10))
        result = json.loads((project / "result").read_text())
        assert result["pid"] != os.readlink("/proc/self/ns/pid")
        assert result["net"] != os.readlink("/proc/self/ns/net")
        assert result["denied"] == [True, True, True]
        assert result["signal_denied"] and result["network_denied"]
        assert result["scratch"] == "allowed"
        assert canary.read_text() == "untouched"
        assert not signaled.exists()
        assert victim.poll() is None
    finally:
        if victim.poll() is None:
            victim.kill()
        victim.wait()


