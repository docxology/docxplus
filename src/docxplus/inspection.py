"""Non-decoding package inspection shared by audit, comparison and export.

Selected structural/declaration checks are not full standards conformance. A
pinned signature authenticates its signed package commitment, not independently
verified plaintext, decoded media, execution or scientific claims.
"""
from __future__ import annotations

import copy
import os
import stat
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from . import crypto
from .container import DocxPlusReader, _compute_surface_digest, _key_matches
from .manifest import MANIFEST_PART
from .odt import OdtPackage
from .odt_container import OdtPlusReader, compute_odt_surface_digest, read_document_package
from .opc import OpcPackage
from .payloads import _open_directory
from .validate import (
    _MALFORMED_INPUT,
    ValidationReport,
    _check_intelligence,
    _check_odf,
    _check_odt_intelligence,
    _check_opc,
    check_opc_signature_coverage,
)

MAX_DOCUMENT_BYTES = 64 * 1024 * 1024


@dataclass
class Inspection:
    """Retain parsed input and an independent snapshot of selected check results."""

    profile: str | None
    package: OpcPackage | OdtPackage | None
    reader: DocxPlusReader | OdtPlusReader | None
    manifest_present: bool
    report: dict

    @property
    def ok(self) -> bool:
        """Whether the selected checks and any explicitly requested pins passed."""
        return bool(self.report['ok'])


def validate_inspection_policy(
    expected_public_key: bytes | None, require_cosigners: Sequence[bytes],
) -> tuple[bytes, ...]:
    """Validate complete signing identities; no embedded key becomes a trust pin."""
    if expected_public_key is not None:
        if not isinstance(expected_public_key, bytes):
            raise TypeError('expected_public_key must be complete public-key bytes')
        crypto.signing_algorithm(expected_public_key)
    if isinstance(require_cosigners, (str, bytes, bytearray)):
        raise TypeError('require_cosigners must be a sequence of complete public keys')
    try:
        keys = tuple(require_cosigners)
    except TypeError as exc:
        raise TypeError('require_cosigners must be a sequence of public keys') from exc
    if keys and expected_public_key is None:
        raise ValueError('a required co-signer policy also requires a primary signer pin')
    for key in keys:
        if not isinstance(key, bytes):
            raise TypeError('co-signer pins must be complete public-key bytes')
        crypto.signing_algorithm(key)
    if len(set(keys)) != len(keys):
        raise ValueError('co-signer pins must be unique')
    return keys


def read_document_file(path: str | Path, *, max_bytes: int = MAX_DOCUMENT_BYTES) -> bytes:
    """Read a bounded stable regular file without following leaf/ancestor symlinks.

    Capability-refuse where descriptor-relative no-follow I/O is unavailable.
    This bounds input bytes, not total process memory after package inflation.
    """
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
        raise ValueError('max_bytes must be a positive integer')
    target = Path(path)
    parent = _open_directory(target.parent)
    try:
        descriptor = os.open(
            target.name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_NONBLOCK', 0),
            dir_fd=parent,
        )
    finally:
        os.close(parent)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError('document input must be a regular file')
        if before.st_size > max_bytes:
            raise ValueError('document input exceeds max_bytes')
        with os.fdopen(descriptor, 'rb', closefd=False) as handle:
            data = handle.read(before.st_size + 1)
        after = os.fstat(descriptor)
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if len(data) != before.st_size or any(
            getattr(before, name) != getattr(after, name) for name in fields
        ):
            raise ValueError('document input changed during read')
        return data
    finally:
        os.close(descriptor)


def _diagnostic(error: Exception) -> str:
    return f'{type(error).__name__}: {str(error)[:4096]}'


def inspect_document(
    data: bytes, *, expected_public_key: bytes | None = None,
    require_cosigners: Sequence[bytes] = (),
) -> Inspection:
    """Inspect both profiles without decoding payloads or executing carried code.

    Ordinary documents can pass selected structure checks. Unsigned/unpinned
    documents never become authentic. Declaration validity includes the original
    serialized root and current package surface, not decoded payload consistency.
    Expected input errors remain stage diagnostics; invalid caller policy raises.
    """
    keys = validate_inspection_policy(expected_public_key, require_cosigners)
    structure = ValidationReport()
    signature = {
        'status': 'absent', 'signer': None, 'algorithm': None,
        'self_consistent': False,
        'authentic': None if expected_public_key is None else False,
        'cosigners': [], 'required_cosigners_verified': None if not keys else False,
    }
    intelligence = {'present': False, 'declaration_valid': None, 'modules': [], 'errors': []}
    report = {
        'schema': 'docxplus.inspection.v1', 'profile': None, 'ok': False,
        'structure': structure.to_dict(), 'intelligence': intelligence,
        'signature': signature, 'surface_digest': None,
        'payloads_verified': False, 'errors': [],
    }
    try:
        package = read_document_package(data)
    except _MALFORMED_INPUT as exc:
        message = _diagnostic(exc)
        structure.fail(structure.opc_errors, message)
        report['structure'] = structure.to_dict()
        report['errors'].append(message)
        return Inspection(None, None, None, False, report)
    is_odt = isinstance(package, OdtPackage)
    profile = 'odt' if is_odt else 'docx'
    report['profile'] = profile
    present = MANIFEST_PART in package.parts
    intelligence['present'] = present
    try:
        if is_odt:
            _check_odf(data, package, structure)
        else:
            _check_opc(package, structure)
            check_opc_signature_coverage(package, structure)
    except _MALFORMED_INPUT as exc:
        structure.fail(structure.opc_errors, _diagnostic(exc))
    report['structure'] = structure.to_dict()
    declarations = ValidationReport()
    try:
        if is_odt:
            _check_odt_intelligence(package, declarations, verify_payloads=False)
        else:
            _check_intelligence(package, declarations, verify_payloads=False)
    except _MALFORMED_INPUT as exc:
        declarations.fail(declarations.intelligence_errors, _diagnostic(exc))
    intelligence['errors'].extend(declarations.intelligence_errors)
    try:
        report['surface_digest'] = (
            compute_odt_surface_digest(package) if is_odt else _compute_surface_digest(package)
        )
    except _MALFORMED_INPUT as exc:
        intelligence['errors'].append(_diagnostic(exc))
    reader = None
    if present:
        try:
            reader = (OdtPlusReader.from_package(package) if is_odt
                      else DocxPlusReader.from_package(package))
            manifest = reader.manifest
            intelligence['modules'] = copy.deepcopy([
                record.to_dict() for record in sorted(manifest.records, key=lambda item: item.slot)
            ])
            signature['signer'] = manifest.public_key or None
            signature['algorithm'] = manifest.algorithm
            if not manifest.declares_supported_algorithm():
                intelligence['errors'].append('unsupported primary signing algorithm declaration')
            signed = manifest.is_signed()
            primary_valid = manifest.verify_signature() if signed else False
            signature['status'] = 'unsigned' if not signed else 'valid' if primary_valid else 'invalid'
            if primary_valid and expected_public_key is not None and not _key_matches(
                manifest.public_key, expected_public_key,
            ):
                signature['status'] = 'untrusted-signer'
            surface_matches = report['surface_digest'] == manifest.surface_digest
            co_validity = manifest.verify_cosignatures()
            for declaration in sorted(manifest.cosignatures, key=lambda item: item['public_key']):
                valid = bool(co_validity.get(declaration['public_key'])) and surface_matches
                signature['cosigners'].append({
                    'public_key': declaration['public_key'],
                    'algorithm': declaration['algorithm'], 'valid': valid,
                })
                if not valid:
                    intelligence['errors'].append('declared co-signature is invalid or surface-mismatched')
            signature['self_consistent'] = bool(
                primary_valid and surface_matches and not intelligence['errors']
            )
            if expected_public_key is not None:
                signature['authentic'] = bool(
                    signature['self_consistent'] and signature['status'] == 'valid'
                )
            if keys:
                verified_keys = {
                    bytes.fromhex(item['public_key'])
                    for item in signature['cosigners'] if item['valid']
                }
                if primary_valid and surface_matches:
                    verified_keys.add(bytes.fromhex(manifest.public_key))
                signature['required_cosigners_verified'] = all(key in verified_keys for key in keys)
        except _MALFORMED_INPUT as exc:
            intelligence['errors'].append(_diagnostic(exc))
    if present or intelligence['errors']:
        intelligence['declaration_valid'] = not intelligence['errors']
    report['ok'] = bool(
        structure.ok and not intelligence['errors']
        and (expected_public_key is None or signature['authentic'] is True)
        and (not keys or signature['required_cosigners_verified'] is True)
    )
    return Inspection(profile, package, reader, present, report)


__all__ = [
    'MAX_DOCUMENT_BYTES',
    'Inspection',
    'inspect_document',
    'read_document_file',
    'validate_inspection_policy',
]
