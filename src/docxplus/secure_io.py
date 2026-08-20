"""Writing files that must not be world-readable.

A container format whose purpose is protecting payloads should not hand its own
secrets to every account on the machine, and this one did: ``keygen`` wrote Ed25519
and X25519 *private* keys with whatever the process umask allowed — 0644 under the
common default — and the same was true of Shamir shares and of plaintext recovered
by ``extract --out``. Any local user could read the signing identity of every
document the operator had ever produced.

Two properties matter and neither is achieved by writing the file and then calling
``chmod``. That order leaves a window in which the bytes exist at the permissive
mode, which is exactly the window a watcher on a shared machine waits for. The file
is therefore created at 0600 by ``os.open``, before any content is written.

The second property is refusal to clobber. Overwriting a signing key destroys an
identity with no recovery and no warning, so key and share writes are exclusive
creates. Recovered plaintext is different — re-extracting to the same path is
ordinary use — so that caller opts into replacement explicitly.
"""

from __future__ import annotations

import os
from pathlib import Path

#: Owner read/write only. The mode a private key has on every system that takes
#: key handling seriously; OpenSSH refuses to use one that is looser.
SECRET_MODE = 0o600


class SecretExistsError(FileExistsError):
    """Raised rather than overwrite existing key or share material."""


def write_secret(path: str | Path, data: bytes | str, *, overwrite: bool = False) -> Path:
    """Write ``data`` to ``path``, owner-readable only, never through a wider mode.

    ``overwrite`` defaults to False so that key and share material cannot be
    destroyed by a repeated command. Pass True only where replacing the file is the
    caller's evident intent, such as re-extracting a payload.
    """
    path = Path(path)
    payload = data.encode("utf-8") if isinstance(data, str) else data

    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if overwrite else os.O_EXCL)
    try:
        handle = os.open(path, flags, SECRET_MODE)
    except FileExistsError:
        raise SecretExistsError(
            f"refusing to overwrite existing secret material at {path}. "
            "Move or delete it first if replacing it is really what you want."
        ) from None
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(payload)
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    # An existing file reopened with O_TRUNC keeps its old mode, so tighten it.
    if overwrite:
        os.chmod(path, SECRET_MODE)
    return path


def is_secret_mode(path: str | Path) -> bool:
    """True when ``path`` is readable and writable by its owner and nobody else."""
    return (Path(path).stat().st_mode & 0o777) == SECRET_MODE


__all__ = [
    "SECRET_MODE",
    "SecretExistsError",
    "is_secret_mode",
    "write_secret",
]

