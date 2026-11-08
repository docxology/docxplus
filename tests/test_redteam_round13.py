"""Regressions for the round-13 review: first principles, security, nation-state.

Round 12 attacked the format. This round attacked the things around it — how the
tool treats its own outputs, what an observer learns without breaking anything, and
which claims the design makes that it has no mechanism to keep.

The findings do not share a mechanism, but they share an omission: each is a place
where the threat model stopped at the boundary of the file. A container format that
protects payloads and then writes the signing key world-readable has not protected
anything; an envelope that hides recipient identities and publishes their number has
answered half a question.
"""

from __future__ import annotations

import io
import json
import stat
import zipfile

import pytest

from docxplus import crypto
from docxplus.container import ContainerError, DocxPlusBuilder, DocxPlusReader
from docxplus.manifest import SIGNATURE_ALGORITHM, Manifest
from docxplus.secure_io import SecretExistsError, is_secret_mode, write_secret

# -- Finding 1: the tool's own secrets were world-readable --------------------


def test_secret_material_is_written_owner_only(tmp_path):
    """0644 on a private key is a finding regardless of how it got there."""
    path = write_secret(tmp_path / "signing.key", b"not really a key")
    assert is_secret_mode(path), oct(path.stat().st_mode & 0o777)
    assert not (path.stat().st_mode & (stat.S_IRGRP | stat.S_IROTH))


def test_existing_secret_material_is_not_silently_replaced(tmp_path):
    """Overwriting a signing key destroys an identity with no recovery."""
    path = write_secret(tmp_path / "k", b"original")
    with pytest.raises(SecretExistsError):
        write_secret(path, b"replacement")
    assert path.read_bytes() == b"original"


def test_recovered_plaintext_may_be_replaced_but_stays_owner_only(tmp_path):
    """Re-extracting to the same path is ordinary use; a loose mode never is."""
    path = write_secret(tmp_path / "out.bin", b"first")
    write_secret(path, b"second", overwrite=True)
    assert path.read_bytes() == b"second"
    assert is_secret_mode(path)


def test_plaintext_replacement_never_modifies_an_existing_inode(tmp_path):
    """An open public inode or hardlink must never receive newly recovered secrets."""
    path = tmp_path / "recovered"
    path.write_bytes(b"previous public data")
    path.chmod(0o644)
    with path.open("rb") as previous:
        write_secret(path, b"new private plaintext", overwrite=True)
        assert previous.read() == b"previous public data"
    assert path.read_bytes() == b"new private plaintext"
    assert is_secret_mode(path)


def test_plaintext_replacement_does_not_follow_a_symlink(tmp_path):
    """Replacing an extraction destination must not overwrite its symlink target."""
    target = tmp_path / "unrelated"
    target.write_bytes(b"preserve this")
    path = tmp_path / "recovered"
    path.symlink_to(target)
    write_secret(path, b"private plaintext", overwrite=True)
    assert target.read_bytes() == b"preserve this"
    assert not path.is_symlink()
    assert path.read_bytes() == b"private plaintext"
    assert is_secret_mode(path)


def test_failed_plaintext_replacement_preserves_existing_destination(tmp_path):
    """A serialization failure must leave prior recovered data intact."""
    path = tmp_path / "recovered"
    path.write_bytes(b"preserve this")
    with pytest.raises(TypeError):
        write_secret(path, object(), overwrite=True)
    assert path.read_bytes() == b"preserve this"
    assert set(tmp_path.iterdir()) == {path}


def test_plaintext_replacement_detaches_a_hardlink(tmp_path):
    """Replacement changes only the selected directory entry, not aliases."""
    import os

    target = tmp_path / "original"
    target.write_bytes(b"public previous bytes")
    recovered = tmp_path / "recovered"
    os.link(target, recovered)
    write_secret(recovered, b"private replacement", overwrite=True)
    assert target.read_bytes() == b"public previous bytes"
    assert recovered.read_bytes() == b"private replacement"
    assert is_secret_mode(recovered)


def test_a_failed_write_leaves_no_partial_secret(tmp_path):
    class Unserialisable:
        pass

    with pytest.raises(TypeError):
        write_secret(tmp_path / "x", Unserialisable())  # type: ignore[arg-type]
    assert not (tmp_path / "x").exists()


# -- Finding 2: the envelope leaked the recipient count -----------------------


def _module_size(blob: bytes) -> int:
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        return json.loads(archive.read("intelligence/manifest.json"))["modules"][0]["size"]


def _sealed_to(count: int, *, padding: int = 0) -> tuple[bytes, list[bytes]]:
    keys = [crypto.generate_recipient_key() for _ in range(count)]
    builder = DocxPlusBuilder(paragraphs=["cover"], title="t")
    builder.add_module(
        "m", "package_part", b"X" * 64, payload_type="bytes",
        recipients=[public for _, public in keys], recipient_padding=padding,
    )
    return builder.build(), [private for private, _ in keys]


def test_without_padding_the_recipient_count_is_recoverable():
    """Pinned as the documented default, not as an aspiration.

    The manifest deliberately records neither recipient identities nor their
    number, and the envelope length gives the number away at a fixed cost per slot.
    Stating the leak is the honest position while the default stays unpadded.
    """
    sizes = [_module_size(_sealed_to(n)[0]) for n in (1, 2, 3, 4)]
    deltas = {sizes[i + 1] - sizes[i] for i in range(3)}
    assert len(deltas) == 1 and deltas.pop() > 0, (
        "the per-recipient cost is no longer uniform; the leak analysis in "
        "docs/security-model.md needs redoing rather than deleting"
    )


def test_padding_makes_the_recipient_count_unrecoverable_from_length():
    assert len({_module_size(_sealed_to(n, padding=8)[0]) for n in (1, 2, 3, 4)}) == 1


def test_every_real_recipient_still_opens_a_padded_envelope():
    """Padding must cost nothing but bytes."""
    blob, privates = _sealed_to(3, padding=8)
    reader = DocxPlusReader.from_bytes(blob)
    for private in privates:
        assert reader.extract("m", private_key=private) == b"X" * 64


def test_a_padded_slot_is_undecryptable_by_anyone():
    """The private half of a padding key is never bound to a name.

    A padded slot is a real X25519 wrap, indistinguishable from a recipient's, and
    nobody holds the key — the same shape as the chaff frame in the password
    lineage. An outsider gets nothing from it.
    """
    blob, _ = _sealed_to(1, padding=8)
    outsider, _ = crypto.generate_recipient_key()
    with pytest.raises(ContainerError):
        DocxPlusReader.from_bytes(blob).extract("m", private_key=outsider)


def test_padding_may_only_add_slots():
    _, public = crypto.generate_recipient_key()
    _, other = crypto.generate_recipient_key()
    with pytest.raises(ValueError):
        crypto.seal_multi(b"x", [public, other], pad_to=1)


def test_padding_does_not_place_real_recipients_first():
    """Appending decoys would order every real slot before every padded one.

    Position would then reconstruct exactly the count the padding exists to hide,
    so the slots are shuffled with a CSPRNG. Detected here by observing that the
    slot a single real recipient occupies is not always index zero.
    """
    positions = set()
    for _ in range(24):
        private, public = crypto.generate_recipient_key()
        envelope = crypto.seal_multi(b"payload", [public], aad=b"m", pad_to=6)
        body_len = int.from_bytes(envelope[4:8], "big")
        cursor = 8 + body_len + 2
        for index in range(6):
            ephemeral = envelope[cursor:cursor + 32]
            wrap_len = int.from_bytes(envelope[cursor + 32:cursor + 34], "big")
            wrapped = envelope[cursor + 34:cursor + 34 + wrap_len]
            cursor += 34 + wrap_len
            try:
                crypto._unwrap_key(ephemeral, wrapped, private)
                positions.add(index)
                break
            except Exception:  # noqa: BLE001, S112 — trial-decryption of padded slots raises InvalidTag/ValueError; skip and try the next slot
                continue
    assert len(positions) > 1, f"real recipient always landed at {positions}"


# -- Finding 3: the declared algorithm was recorded and never read ------------


def _signed_manifest_dict() -> dict:
    private_key, _ = crypto.generate_signing_key()
    builder = DocxPlusBuilder(paragraphs=["c"], title="t")
    builder.add_module("m", "package_part", b"x", payload_type="bytes")
    builder.sign(private_key)
    with zipfile.ZipFile(io.BytesIO(builder.build())) as archive:
        return json.loads(archive.read("intelligence/manifest.json"))


def test_an_honest_manifest_still_verifies():
    doc = _signed_manifest_dict()
    assert doc["signature"]["algorithm"] == SIGNATURE_ALGORITHM
    assert Manifest.from_bytes(json.dumps(doc).encode()).verify_signature()


def test_a_manifest_declaring_an_algorithm_we_do_not_implement_is_refused():
    """The field was decorative: a manifest could claim RSA and verify as Ed25519."""
    doc = _signed_manifest_dict()
    doc["signature"]["algorithm"] = "rsa-4096"
    assert not Manifest.from_bytes(json.dumps(doc).encode()).verify_signature()



def test_replacement_failure_before_publication_preserves_the_old_file(tmp_path):
    """A read-only directory stops staging; the previous secret is untouched."""
    path = write_secret(tmp_path / "recovered", b"previous")
    tmp_path.chmod(0o500)
    try:
        with pytest.raises(PermissionError):
            write_secret(path, b"replacement", overwrite=True)
    finally:
        tmp_path.chmod(0o700)
    assert path.read_bytes() == b"previous"
    assert set(tmp_path.iterdir()) == {path}


def test_replacement_failure_at_publication_removes_the_staged_temporary(tmp_path):
    """os.replace onto a directory fails; the private staging file is removed."""
    destination = tmp_path / "recovered"
    destination.mkdir()
    with pytest.raises((IsADirectoryError, NotADirectoryError)):
        write_secret(destination, b"replacement", overwrite=True)
    assert destination.is_dir()
    assert set(tmp_path.iterdir()) == {destination}
