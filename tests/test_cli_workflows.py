"""Real CLI outcomes for cross-profile audit, comparison and private export."""
from __future__ import annotations

import json
import subprocess
import sys

import pytest

from docxplus import crypto
from docxplus.container import DocxPlusBuilder
from docxplus.manifest import MANIFEST_PART
from docxplus.odt_container import OdtPlusBuilder, read_document_package

_PRIVATE = bytes(range(32))
_PUBLIC = crypto.signing_public_key(_PRIVATE)


def _document(profile, payload=b'original', password=None):
    if profile == 'docx':
        builder = DocxPlusBuilder().add_module('review', 'package_part', payload, password=password)
    else:
        builder = OdtPlusBuilder().add_module('review', payload, password=password)
    return builder.sign(_PRIVATE).build()


def _cli(*args):
    return subprocess.run([sys.executable, '-m', 'docxplus.cli', *(str(arg) for arg in args)],
                          capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=30,
                          check=False)


@pytest.mark.parametrize('profile', ['docx', 'odt'])
def test_cli_audit_preserves_distinct_successful_peers_around_a_bad_file(tmp_path, profile):
    """One unreadable input must not discard other authenticated file results."""
    first = tmp_path / f'first.{profile}'
    second = tmp_path / f'second.{profile}'
    missing = tmp_path / 'missing'
    key = tmp_path / 'author.pub'
    key.write_text(_PUBLIC.hex())
    first.write_bytes(_document(profile))
    second.write_bytes(_document(profile, b'second peer'))
    result = _cli('audit', first, missing, second, '--expected-key', key)
    assert result.returncode == 1, result.stderr
    report = json.loads(result.stdout)
    assert report['ok'] is False
    assert [row['path'] for row in report['results']] == [str(first), str(missing), str(second)]
    assert [row['ok'] for row in report['results']] == [True, False, True]
    assert report['results'][0]['inspection']['signature']['authentic'] is True
    assert report['results'][2]['inspection']['signature']['authentic'] is True
    assert report['results'][1]['errors']


@pytest.mark.parametrize('profile', ['docx', 'odt'])
def test_cli_comparison_distinguishes_differences_from_invalid_input(tmp_path, profile):
    """Exit 1 means valid differences; exit 2 must not bless tampered declarations."""
    before = tmp_path / 'before.data'
    after = tmp_path / 'after.data'
    before.write_bytes(_document(profile))
    after.write_bytes(_document(profile, b'changed'))
    changed = _cli('compare', before, after)
    assert changed.returncode == 1, changed.stderr
    report = json.loads(changed.stdout)
    assert report['ok'] is True and report['equal'] is False
    assert [row['slot'] for row in report['modules']['changed']] == ['review']
    package = read_document_package(after.read_bytes())
    manifest = json.loads(package.parts[MANIFEST_PART])
    manifest['merkle_root'] = '0' * 64
    package.parts[MANIFEST_PART] = json.dumps(manifest).encode()
    after.write_bytes(package.to_bytes())
    invalid = _cli('compare', before, after)
    assert invalid.returncode == 2, invalid.stderr
    invalid_report = json.loads(invalid.stdout)
    assert invalid_report['ok'] is False and invalid_report['equal'] is None


@pytest.mark.parametrize('profile', ['docx', 'odt'])
def test_cli_export_uses_credentials_and_preserves_occupied_destinations(tmp_path, profile):
    """Recovered plaintext is exact; a second export cannot replace the first tree."""
    source = tmp_path / 'source.data'
    source.write_bytes(_document(profile, b'protected payload', password='known password'))
    refused = tmp_path / 'refused'
    wrong = _cli('export', source, refused, '--password', 'wrong password')
    assert wrong.returncode == 2
    assert not refused.exists()
    destination = tmp_path / 'recovered'
    result = _cli('export', source, destination, '--password', 'known password')
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    row = report['index']['modules'][0]
    assert row['slot'] == 'review'
    recovered = destination / row['file']
    assert recovered.read_bytes() == b'protected payload'
    existing_index = (destination / 'index.json').read_bytes()
    repeated = _cli('export', source, destination, '--password', 'known password')
    assert repeated.returncode == 2
    assert recovered.read_bytes() == b'protected payload'
    assert (destination / 'index.json').read_bytes() == existing_index
