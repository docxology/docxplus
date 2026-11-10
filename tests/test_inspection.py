"""Non-decoding inspection crosses serialized package and filesystem boundaries."""
from __future__ import annotations

import json

import pytest

from docxplus import crypto
from docxplus.container import DocxPlusBuilder
from docxplus.inspection import (
    inspect_document,
    read_document_file,
    validate_inspection_policy,
)
from docxplus.manifest import MANIFEST_PART
from docxplus.odt import new_base_odt
from docxplus.odt_container import OdtPlusBuilder, read_document_package
from docxplus.wordml import new_base_document

_PRIVATE = bytes(range(32))
_PUBLIC = crypto.signing_public_key(_PRIVATE)
_OTHER = crypto.signing_public_key(bytes(range(1, 33)))


def _builder(profile: str):
    builder = (DocxPlusBuilder(paragraphs=['before']) if profile == 'docx'
               else OdtPlusBuilder(paragraphs=['before']))
    if profile == 'docx':
        return builder.add_module('m', 'package_part', b'packed payload')
    return builder.add_module('m', b'packed payload')


@pytest.mark.parametrize('profile', ['docx', 'odt'])
def test_ordinary_documents_have_no_fabricated_intelligence_or_authenticity(profile):
    """A readable ordinary office file is not a signed intelligence container."""
    data = (new_base_document(['ordinary']) if profile == 'docx' else new_base_odt()).to_bytes()
    result = inspect_document(data)
    assert result.ok and result.profile == profile
    assert result.reader is None and not result.manifest_present
    assert result.report['intelligence']['declaration_valid'] is None
    assert result.report['signature']['authentic'] is None
    assert result.report['payloads_verified'] is False
    pinned = inspect_document(data, expected_public_key=_PUBLIC)
    assert not pinned.ok and pinned.report['signature']['authentic'] is False


@pytest.mark.parametrize('profile', ['docx', 'odt'])
def test_pinned_authenticity_is_distinct_from_self_consistency(profile):
    """An embedded signer never becomes the caller's trusted identity."""
    data = _builder(profile).sign(_PRIVATE).build()
    unpinned = inspect_document(data)
    assert unpinned.ok and unpinned.report['signature']['self_consistent']
    assert unpinned.report['signature']['authentic'] is None
    trusted = inspect_document(data, expected_public_key=_PUBLIC)
    assert trusted.ok and trusted.report['signature']['authentic'] is True
    outsider = inspect_document(data, expected_public_key=_OTHER)
    assert not outsider.ok
    assert outsider.report['signature']['status'] == 'untrusted-signer'
    assert outsider.report['signature']['self_consistent'] is True
    assert outsider.report['signature']['authentic'] is False


@pytest.mark.parametrize('profile', ['docx', 'odt'])
def test_surface_tamper_cannot_hide_behind_valid_manifest_signature(profile):
    """Current package bytes, not just a valid signature value, bind provenance."""
    package = read_document_package(_builder(profile).sign(_PRIVATE).build())
    part = 'word/document.xml' if profile == 'docx' else 'content.xml'
    package.parts[part] = package.parts[part].replace(b'before', b'after')
    result = inspect_document(package.to_bytes(), expected_public_key=_PUBLIC)
    assert result.report['signature']['status'] == 'valid'
    assert result.report['signature']['self_consistent'] is False
    assert result.report['signature']['authentic'] is False
    assert not result.ok


@pytest.mark.parametrize('profile', ['docx', 'odt'])
def test_original_serialized_merkle_root_is_not_normalized_away(profile):
    """Canonical manifest reconstruction must not repair tampered evidence."""
    package = read_document_package(_builder(profile).sign(_PRIVATE).build())
    manifest = json.loads(package.parts[MANIFEST_PART])
    manifest['merkle_root'] = '0' * 64
    package.parts[MANIFEST_PART] = json.dumps(manifest).encode()
    result = inspect_document(package.to_bytes(), expected_public_key=_PUBLIC)
    assert not result.ok
    assert result.report['intelligence']['declaration_valid'] is False
    assert result.report['signature']['authentic'] is False


@pytest.mark.parametrize('profile', ['docx', 'odt'])
def test_malformed_manifest_preserves_admitted_package_and_structure(profile):
    """Batch consumers can still scan threats when intelligence parsing fails."""
    package = read_document_package(_builder(profile).build())
    package.parts[MANIFEST_PART] = b'{"broken":true}'
    result = inspect_document(package.to_bytes())
    assert result.package is not None and result.reader is None
    assert result.report['structure']['ok']
    assert result.report['intelligence']['errors']
    assert not result.ok


@pytest.mark.parametrize('profile', ['docx', 'odt'])
def test_every_declared_cosignature_must_validate(profile):
    """Invalid detached declarations cannot disappear from a successful report."""
    data = _builder(profile).sign(_PRIVATE).add_cosigner(bytes(range(1, 33))).build()
    valid = inspect_document(data, expected_public_key=_PUBLIC, require_cosigners=[_OTHER])
    assert valid.ok and valid.report['signature']['required_cosigners_verified'] is True
    package = read_document_package(data)
    manifest = json.loads(package.parts[MANIFEST_PART])
    manifest['cosignatures'][0]['value'] = '00' * 64
    package.parts[MANIFEST_PART] = json.dumps(manifest).encode()
    invalid = inspect_document(package.to_bytes(), expected_public_key=_PUBLIC)
    assert not invalid.ok
    assert invalid.report['signature']['cosigners'][0]['valid'] is False


@pytest.mark.parametrize('profile', ['docx', 'odt'])
def test_hybrid_pin_requires_both_public_components(profile):
    """A hybrid manifest cannot authenticate under its classical key prefix."""
    key = crypto.generate_hybrid_signing_key()
    data = _builder(profile).sign(key.private_bytes).build()
    assert inspect_document(data, expected_public_key=key.public_bytes).ok
    classical_only = inspect_document(data, expected_public_key=key.public_bytes[:32])
    assert not classical_only.ok and classical_only.report['signature']['authentic'] is False


@pytest.mark.parametrize('profile', ['docx', 'odt'])
def test_inspection_report_is_a_snapshot_of_mutable_reader_metadata(profile):
    """Later caller mutation of a reader cannot rewrite the earlier audit row."""
    result = inspect_document(_builder(profile).build())
    original = result.report['intelligence']['modules'][0]['location'].copy()
    result.reader.manifest.records[0].location['part'] = 'changed-after-inspection'
    assert result.report['intelligence']['modules'][0]['location'] == original


@pytest.mark.parametrize('value', [True, False, 0, -1, 1.5, '3'])
def test_document_file_budget_is_strict_before_open(tmp_path, value):
    """Invalid budgets cannot turn into accidental unlimited filesystem reads."""
    with pytest.raises(ValueError):
        read_document_file(tmp_path / 'missing', max_bytes=value)


def test_document_file_exact_limit_and_nonregular_inputs(tmp_path):
    """File admission is byte-bounded and refuses directories without reading them."""
    source = tmp_path / 'input'
    source.write_bytes(b'abc')
    assert read_document_file(source, max_bytes=3) == b'abc'
    with pytest.raises(ValueError):
        read_document_file(source, max_bytes=2)
    with pytest.raises(ValueError):
        read_document_file(tmp_path)


def test_document_file_refuses_leaf_and_ancestor_symlinks(tmp_path):
    """No-follow admission applies to the whole supplied path, not just its leaf."""
    source = tmp_path / 'source'
    source.write_bytes(b'sentinel')
    leaf = tmp_path / 'leaf'
    leaf.symlink_to(source)
    ancestor = tmp_path / 'linked-parent'
    ancestor.symlink_to(tmp_path, target_is_directory=True)
    for path in (leaf, ancestor / 'source'):
        with pytest.raises(OSError):
            read_document_file(path)
    assert source.read_bytes() == b'sentinel'


@pytest.mark.parametrize('expected,cosigners', [(None, [_OTHER]), (_PUBLIC, [_OTHER, _OTHER]), (b'', []), (_PUBLIC, [b''])])
def test_invalid_pin_policy_is_not_a_per_document_failure(expected, cosigners):
    """Caller trust-policy errors must fail before a batch can mask them."""
    with pytest.raises(ValueError):
        validate_inspection_policy(expected, cosigners)


def test_bad_package_is_an_explicit_failed_inspection():
    """Unparseable data cannot fabricate a profile, reader or clean report."""
    result = inspect_document(b'not a ZIP package')
    assert not result.ok and result.package is None and result.profile is None
    assert result.report['structure']['opc_errors']


@pytest.mark.parametrize('profile', ['docx', 'odt'])
def test_signing_identity_uses_complete_key_bytes_not_hex_spelling(profile):
    """Equivalent public-key encodings cannot reject the same pinned identity."""
    package = read_document_package(_builder(profile).sign(_PRIVATE).build())
    manifest = json.loads(package.parts[MANIFEST_PART])
    manifest['signature']['public_key'] = manifest['signature']['public_key'].upper()
    package.parts[MANIFEST_PART] = json.dumps(manifest).encode()
    result = inspect_document(package.to_bytes(), expected_public_key=_PUBLIC,
                              require_cosigners=[_PUBLIC])
    assert result.ok and result.report['signature']['required_cosigners_verified'] is True
    assert result.reader.verify_cosigners([_PUBLIC])
    assert not result.reader.verify_cosigners([_OTHER])


@pytest.mark.parametrize('blob,error', [(None, RuntimeError), (b'', ValueError)])
def test_direct_odt_reader_does_not_synthesize_missing_or_empty_declared_manifest(blob, error):
    """Malformed intelligence authority cannot become an ordinary empty reader."""
    original = inspect_document(OdtPlusBuilder().build()).reader
    package = original.package
    if blob is None:
        del package.parts[MANIFEST_PART]
    else:
        package.parts[MANIFEST_PART] = blob
    with pytest.raises(error):
        type(original).from_package(package)
    assert not inspect_document(package.to_bytes()).ok


def test_nonregular_rejections_preserve_capacity_for_following_file_reads(tmp_path):
    """Repeated intake refusals cannot exhaust the process's file descriptors."""
    import subprocess
    import sys

    (tmp_path / 'good').write_bytes(b'following regular read')
    program = """
import resource,sys
from pathlib import Path
from docxplus.inspection import read_document_file
root=Path(sys.argv[1])
_,hard=resource.getrlimit(resource.RLIMIT_NOFILE)
resource.setrlimit(resource.RLIMIT_NOFILE,(64,hard))
for _ in range(256):
    try:read_document_file(root)
    except (OSError,ValueError):pass
print(read_document_file(root/'good').hex())
"""
    child = subprocess.run(
        [sys.executable, '-B', '-c', program, str(tmp_path)],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, check=True, timeout=20,
    )
    assert bytes.fromhex(child.stdout.strip()) == b'following regular read'
