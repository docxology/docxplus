"""Release parser review: bound metadata and reject disguised compression."""

import hashlib
import io
import stat
import tarfile

import pytest

from scripts import validate_release as release

PAYLOAD = b"release artifact\x00\xff\n"


def _archive(path, mode, *, metadata=None):
    with tarfile.open(path, mode, format=tarfile.PAX_FORMAT) as archive:
        member = tarfile.TarInfo("artifact.bin")
        member.mode = 0o755
        member.size = len(PAYLOAD)
        if metadata is not None:
            member.pax_headers = metadata
        archive.addfile(member, io.BytesIO(PAYLOAD))
    return path


def test_release_archive_preserves_bytes_and_seals_extracted_permissions(tmp_path):
    """Actual gzip/PAX data is hashed and extracted without executable permissions."""
    archive = _archive(tmp_path / "artifacts.tar.gz", "w:gz")
    destination = tmp_path / "extracted"
    receipt = release.extract_archive(archive, destination, limit=1024, count_limit=4)
    artifact = destination / "artifact.bin"
    assert artifact.read_bytes() == PAYLOAD
    assert stat.S_IMODE(artifact.stat().st_mode) == 0o600
    assert receipt["files"]["artifact.bin"]["sha256"] == hashlib.sha256(PAYLOAD).hexdigest()


def test_release_archive_rejects_oversized_pax_before_parsing(tmp_path):
    """Tiny compressed input must not allocate an unbounded ignored PAX comment."""
    archive = _archive(
        tmp_path / "metadata.tar.gz", "w:gz", metadata={"comment": "x" * (2 * 1024**2)}
    )
    destination = tmp_path / "extracted"
    with pytest.raises(release.Refusal):
        release.extract_archive(archive, destination, limit=1024, count_limit=4)
    assert not (destination / "artifact.bin").exists()


def test_release_archive_rejects_bzip2_disguised_as_gzip(tmp_path):
    """The declared tar.gz export protocol must not select an alternate decoder."""
    archive = _archive(tmp_path / "artifacts.tar.gz", "w:bz2")
    destination = tmp_path / "extracted"
    with pytest.raises(release.Refusal):
        release.extract_archive(archive, destination, limit=1024, count_limit=4)
    assert not (destination / "artifact.bin").exists()
