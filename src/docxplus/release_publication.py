"""Deterministic release-asset plans and bounded, descriptor-pinned evidence reads.

Receipt checks establish consistency, not producer authenticity. The publication
adapter must separately authenticate source, evidence, actor and remote responses.
This module neither authorizes publication nor performs any network operation.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from contextlib import ExitStack
from pathlib import Path
from typing import Any

_SCHEMA = "docxplus.release-assets-plan.v1"
_REPOSITORY = "docxology/docxplus"
_MAX_BYTES = 128 * 1024 * 1024
_MAX_RECEIPT_BYTES = 4 * 1024 * 1024
_MAX_CHECKSUM_BYTES = 4096
_CHUNK_BYTES = 1024 * 1024
_VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")
_LOGIN = re.compile(r"[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*")
_COMMIT = re.compile(r"[0-9a-f]{40}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_CHECKSUM = re.compile(r"([0-9a-f]{64}) [ *]([^\r\n]+)")
_PLAN_FIELDS = {
    "schema", "repository", "version", "tag", "actor", "main_commit",
    "main_tree", "release_id", "release", "created_at", "expires_at",
    "assets", "plan_id",
}
_RELEASE_FIELDS = {"id", "tag_name", "name", "body", "prerelease"}


class PublicationError(ValueError):
    """A plan, asset bundle or remote identity violates the publication contract."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise PublicationError(message)


def _integer(value: object) -> bool:
    return type(value) is int


def _positive(value: object) -> bool:
    return _integer(value) and value > 0


def _matches(pattern: re.Pattern[str], value: object) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _text(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        value.encode("utf-8")
    except UnicodeError:
        return False
    return True


def _asset_names(version: str) -> list[str]:
    return sorted([
        f"docxplus-{version}-py3-none-any.whl", f"docxplus-{version}.tar.gz",
        "manuscript.pdf", f"SOURCE-{version}.json", f"VALIDATION-{version}.json",
        "SHA256SUMS",
    ])


def _source_identity(version: object, actor: object, commit: object, tree: object) -> None:
    _require(_matches(_VERSION, version), "version must be stable X.Y.Z")
    _require(isinstance(actor, str) and 1 <= len(actor) <= 39
             and _matches(_LOGIN, actor), "actor must be a GitHub login")
    _require(_matches(_COMMIT, commit), "main_commit must be lowercase hex40")
    _require(_matches(_COMMIT, tree), "main_tree must be lowercase hex40")


def _release_metadata(release: object, tag: str, *, initial: bool = False) -> dict:
    _require(isinstance(release, dict), "release must be an object")
    _require(_RELEASE_FIELDS <= release.keys(), "release metadata is incomplete")
    _require(_positive(release["id"]), "release id must be a positive integer")
    _require(release["tag_name"] == tag, "release tag does not match version")
    _require(_text(release["name"]) and _text(release["body"]),
             "release name and body must be UTF-8 strings")
    _require(release["prerelease"] is False, "prereleases cannot be published")
    if initial:
        _require(release.get("draft") is True, "initial release must be a draft")
    return {key: release[key] for key in sorted(_RELEASE_FIELDS)}


def _canonical(value: dict) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise PublicationError("plan is not canonical JSON") from exc


def _plan_digest(plan: dict) -> str:
    return hashlib.sha256(_canonical({key: value for key, value in plan.items()
                                      if key != "plan_id"})).hexdigest()


def _validated_plan(plan: object, *, now: int | None = None) -> dict:
    _require(isinstance(plan, dict) and set(plan) == _PLAN_FIELDS,
             "plan has unknown or missing fields")
    _require(plan["schema"] == _SCHEMA, "unsupported publication plan schema")
    _require(plan["repository"] == _REPOSITORY, "wrong publication repository")
    _source_identity(plan["version"], plan["actor"], plan["main_commit"], plan["main_tree"])
    tag = f"v{plan['version']}"
    _require(plan["tag"] == tag, "plan tag does not match version")
    _require(isinstance(plan["release"], dict)
             and set(plan["release"]) == _RELEASE_FIELDS, "invalid frozen release fields")
    release = _release_metadata(plan["release"], tag)
    _require(_positive(plan["release_id"]) and plan["release_id"] == release["id"],
             "plan release identity does not match")
    created, expires = plan["created_at"], plan["expires_at"]
    _require(_integer(created) and _integer(expires), "plan times must be integers")
    _require(30 <= expires - created <= 3600, "plan TTL must be 30..3600 seconds")
    if now is not None:
        _require(_integer(now), "now must be an integer")
        _require(created <= now, "plan was created in the future")
        _require(now < expires, "publication plan has expired")
    assets = plan["assets"]
    names = _asset_names(plan["version"])
    _require(isinstance(assets, dict) and set(assets) == set(names),
             "plan must contain exactly the six release assets")
    total = 0
    for name in names:
        row = assets[name]
        _require(isinstance(row, dict) and set(row) == {"bytes", "sha256"},
                 f"invalid plan asset fields: {name}")
        _require(_positive(row["bytes"]) and row["bytes"] <= _MAX_BYTES,
                 f"invalid plan asset byte size: {name}")
        _require(_matches(_DIGEST, row["sha256"]), f"invalid plan asset digest: {name}")
        total += row["bytes"]
    _require(total <= _MAX_BYTES, "plan assets exceed the aggregate byte limit")
    _require(_matches(_DIGEST, plan["plan_id"]), "invalid plan_id")
    _require(plan["plan_id"] == _plan_digest(plan), "publication plan digest mismatch")
    # Return an independent, predictably ordered JSON value, not aliases into caller data.
    result = dict(plan)
    result["release"] = release
    result["assets"] = {name: dict(assets[name]) for name in names}
    return result


def validate_plan(plan: dict, *, now: int) -> dict:
    """Validate the closed schema, digest and explicit time; return an independent plan.

    The digest detects changes, not authorship. Callers must pin the intended plan
    and authenticate remote/source state separately before authorizing publication.
    """
    _require(_integer(now), "now must be an integer")
    return _validated_plan(plan, now=now)


def confirmation_phrase(plan: dict) -> str:
    """Return the exact repository/tag/full-digest confirmation for a coherent plan.

    No clock is read: the adapter must also call ``validate_plan`` with its time.
    """
    checked = _validated_plan(plan)
    return f"publish {_REPOSITORY} {checked['tag']} {checked['plan_id']}"


def _unique_object(pairs: list[tuple[str, Any]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        _require(key not in result, "duplicate receipt JSON key")
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise PublicationError(f"non-JSON numeric constant in receipt: {value}")


def _receipt(data: bytes, name: str) -> dict:
    try:
        result = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object,
                            parse_constant=_invalid_constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise PublicationError(f"invalid JSON receipt: {name}") from exc
    _require(isinstance(result, dict), f"receipt must be a JSON object: {name}")
    return result


def _check_receipts(assets: dict[str, bytes], metadata: dict, version: str,
                    commit: str, tree: str) -> None:
    source = _receipt(assets[f"SOURCE-{version}.json"], "SOURCE")
    validation = _receipt(assets[f"VALIDATION-{version}.json"], "VALIDATION")
    _require(source.get("schema") == "docxplus.release-source.v1",
             "unsupported SOURCE receipt schema")
    _require(validation.get("schema") == "docxplus.release-validation.asset.v1",
             "unsupported VALIDATION receipt schema")
    _require(source.get("version") == version and source.get("commit") == commit
             and source.get("tree") == tree and source.get("branch") == "main"
             and source.get("pushed") is True, "SOURCE receipt does not bind pushed main source")
    digest = source.get("validated_inputs_sha256")
    _require(_matches(_DIGEST, digest), "SOURCE validated input digest is invalid")
    _require(validation.get("version") == version
             and validation.get("source_commit") == commit
             and validation.get("validated_inputs_sha256") == digest,
             "VALIDATION receipt does not bind the same source and validated inputs")
    for section, field in (("host", "ok"), ("results", "ok"),
                           ("lifecycle", "namespace_reaped")):
        _require(isinstance(validation.get(section), dict)
                 and validation[section].get(field) is True,
                 f"VALIDATION receipt requires {section}.{field} true")
    for section in ("host", "lifecycle"):
        _require(validation[section].get("inputs_sha256") == digest,
                 f"VALIDATION {section} does not bind the validated inputs")
    proof = validation.get("distribution_source_proof")
    _require(isinstance(proof, dict) and proof.get("version") == version
             and proof.get("inputs_sha256") == digest,
             "VALIDATION distribution source proof does not bind version and inputs")
    wheel = f"docxplus-{version}-py3-none-any.whl"
    sdist = f"docxplus-{version}.tar.gz"
    _require(proof.get("wheel_sha256") == metadata[wheel]["sha256"]
             and proof.get("sdist_sha256") == metadata[sdist]["sha256"],
             "VALIDATION distribution hashes do not match staged assets")
    collected = validation.get("collected_artifacts")
    _require(isinstance(collected, dict) and isinstance(collected.get("files"), dict),
             "VALIDATION collected artifact inventory is invalid")
    for path, name in ((f"dist/{wheel}", wheel), (f"dist/{sdist}", sdist),
                       ("generated/documents/manuscript.pdf", "manuscript.pdf")):
        entry = collected["files"].get(path)
        _require(isinstance(entry, dict) and _positive(entry.get("bytes"))
                 and entry["bytes"] == metadata[name]["bytes"]
                 and entry.get("sha256") == metadata[name]["sha256"],
                 f"VALIDATION collected artifact does not match staged asset: {name}")
    generated = source.get("validated_generated_artifacts")
    pdf_digest = metadata["manuscript.pdf"]["sha256"]
    _require(isinstance(generated, dict)
             and generated.get("manuscript_pdf_sha256") == pdf_digest,
             "SOURCE manuscript hash does not match staged PDF")
    visual_review = proof.get("visual_review")
    _require(isinstance(visual_review, dict)
             and visual_review.get("pdf_sha256") == pdf_digest,
             "VALIDATION visual review hash does not match staged PDF")


def _check_checksums(assets: dict[str, bytes], metadata: dict) -> None:
    try:
        text = assets["SHA256SUMS"].decode("ascii")
    except UnicodeError as exc:
        raise PublicationError("SHA256SUMS must be ASCII") from exc
    _require(not any(separator in text for separator in ("\v", "\f", "\x1c", "\x1d", "\x1e")),
             "SHA256SUMS contains unsupported line separators")
    text = text.replace("\r\n", "\n")
    _require("\r" not in text, "SHA256SUMS contains a bare CR")
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    expected = set(assets) - {"SHA256SUMS"}
    found: dict[str, str] = {}
    for line in lines:
        match = _CHECKSUM.fullmatch(line)
        _require(match is not None, "malformed SHA256SUMS line")
        digest, name = match.groups()
        _require(name in expected and name not in found,
                 "SHA256SUMS contains an unknown or duplicate filename")
        _require(digest == metadata[name]["sha256"], f"SHA256SUMS digest mismatch: {name}")
        found[name] = digest
    _require(set(found) == expected, "SHA256SUMS must list exactly the other five assets")


def _fingerprint(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _directory_names(descriptor: int, expected: set[str]) -> None:
    names: set[str] = set()
    with os.scandir(descriptor) as entries:
        for entry in entries:
            _require(entry.name in expected and entry.name not in names,
                     "asset directory contains an unexpected entry")
            names.add(entry.name)
    _require(names == expected, "asset directory must contain exactly the six assets")


def _read_bundle(asset_dir: Path, version: str, commit: str, tree: str) -> tuple[dict, dict]:
    """Pin all directories/files through final content and identity checks."""
    _require(isinstance(asset_dir, Path), "asset_dir must be a Path")
    _require(all(hasattr(os, flag) for flag in ("O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK"))
             and os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd
             and os.stat in os.supports_follow_symlinks and os.scandir in os.supports_fd,
             "descriptor-relative no-follow file reads are unavailable")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    names = _asset_names(version)
    limits = {f"SOURCE-{version}.json": _MAX_RECEIPT_BYTES,
              f"VALIDATION-{version}.json": _MAX_RECEIPT_BYTES,
              "SHA256SUMS": _MAX_CHECKSUM_BYTES}
    assets: dict[str, bytes] = {}
    metadata: dict = {}
    try:
        with ExitStack() as opened:
            root = os.open(asset_dir.anchor if asset_dir.is_absolute() else ".", directory_flags)
            opened.callback(os.close, root)
            directories = [(root, os.fstat(root))]
            links: list[tuple[int, str, int]] = []
            parent = root
            parts = asset_dir.parts[1:] if asset_dir.is_absolute() else asset_dir.parts
            for part in parts:
                child = os.open(part, directory_flags, dir_fd=parent)
                opened.callback(os.close, child)
                directories.append((child, os.fstat(child)))
                links.append((parent, part, child))
                parent = child
            directory = parent
            _directory_names(directory, set(names))
            files: list[tuple[str, int, os.stat_result]] = []
            total = 0
            for name in names:
                before = os.stat(name, dir_fd=directory, follow_symlinks=False)
                _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
                         f"asset must be a regular single-link file: {name}")
                _require(0 < before.st_size <= limits.get(name, _MAX_BYTES),
                         f"asset exceeds positive byte bound: {name}")
                total += before.st_size
                _require(total <= _MAX_BYTES, "assets exceed the aggregate byte limit")
                descriptor = os.open(name, file_flags, dir_fd=directory)
                opened.callback(os.close, descriptor)
                _require(_fingerprint(os.fstat(descriptor)) == _fingerprint(before),
                         f"asset changed while being opened: {name}")
                files.append((name, descriptor, before))
            for name, descriptor, before in files:
                blocks: list[bytes] = []
                count = 0
                digest = hashlib.sha256()
                while True:
                    block = os.read(descriptor, min(_CHUNK_BYTES, before.st_size - count + 1))
                    if not block:
                        break
                    count += len(block)
                    _require(count <= before.st_size, f"asset grew while being read: {name}")
                    digest.update(block)
                    blocks.append(block)
                _require(count == before.st_size, f"asset shrank while being read: {name}")
                assets[name] = b"".join(blocks)
                metadata[name] = {"bytes": count, "sha256": digest.hexdigest()}
            _check_checksums(assets, metadata)
            _check_receipts(assets, metadata, version, commit, tree)
            _directory_names(directory, set(names))
            # All descriptors remain open until after hashes and receipts are checked.
            for name, descriptor, before in files:
                _require(_fingerprint(os.fstat(descriptor)) == _fingerprint(before)
                         and _fingerprint(os.stat(name, dir_fd=directory, follow_symlinks=False))
                         == _fingerprint(before), f"asset identity changed during collection: {name}")
            for descriptor, before in directories:
                _require(_fingerprint(os.fstat(descriptor)) == _fingerprint(before),
                         "asset directory changed during collection")
            for parent, name, child in links:
                _require(_fingerprint(os.stat(name, dir_fd=parent, follow_symlinks=False))
                         == _fingerprint(os.fstat(child)), "asset directory component was replaced")
    except OSError as exc:
        raise PublicationError("cannot safely read release asset directory") from exc
    return assets, metadata


def create_plan(asset_dir: Path, *, version: str, actor: str, main_commit: str,
                main_tree: str, release: dict, now: int, ttl_seconds: int = 600) -> dict:
    """Bind exactly six local assets, coherent receipts and one draft to a digest.

    All time and remote identities are explicit inputs. Receipt syntax and hashes
    prove consistency only; the adapter must authenticate their producer/source.
    """
    _source_identity(version, actor, main_commit, main_tree)
    _require(_integer(now), "now must be an integer")
    _require(_integer(ttl_seconds) and 30 <= ttl_seconds <= 3600,
             "TTL must be an integer in 30..3600 seconds")
    tag = f"v{version}"
    frozen = _release_metadata(release, tag, initial=True)
    _, metadata = _read_bundle(asset_dir, version, main_commit, main_tree)
    plan = {
        "schema": _SCHEMA, "repository": _REPOSITORY, "version": version,
        "tag": tag, "actor": actor, "main_commit": main_commit, "main_tree": main_tree,
        "release_id": frozen["id"], "release": frozen, "created_at": now,
        "expires_at": now + ttl_seconds, "assets": metadata,
    }
    plan["plan_id"] = _plan_digest(plan)
    return validate_plan(plan, now=now)


def read_assets(plan: dict, asset_dir: Path) -> dict[str, bytes]:
    """Read pinned files and receipts again; return only bytes matching the plan.

    The adapter must validate expiry with its explicit time separately; no clock
    is consulted here and receipt consistency does not authenticate a producer.
    """
    checked = _validated_plan(plan)
    assets, metadata = _read_bundle(asset_dir, checked["version"], checked["main_commit"],
                                    checked["main_tree"])
    _require(metadata == checked["assets"], "local assets no longer match publication plan")
    return assets


def verify_remote_identity(plan: dict, *, actor: str, main_commit: str,
                           main_tree: str, tag_commit: str, release: dict) -> None:
    """Require fresh identities and frozen metadata to match a coherent plan.

    A matching draft or already-published release is accepted for reconciliation.
    Remote responses must be authenticated by the adapter, which checks expiry.
    """
    checked = _validated_plan(plan)
    _source_identity(checked["version"], actor, main_commit, main_tree)
    _require(actor == checked["actor"], "remote actor changed")
    _require(main_commit == checked["main_commit"] and main_tree == checked["main_tree"],
             "remote main source identity changed")
    _require(_matches(_COMMIT, tag_commit) and tag_commit == checked["main_commit"],
             "tag does not resolve to the planned main commit")
    frozen = _release_metadata(release, checked["tag"])
    _require(type(release.get("draft")) is bool, "remote release draft flag must be boolean")
    _require(frozen == checked["release"] and frozen["id"] == checked["release_id"],
             "remote release identity or frozen metadata changed")


def missing_assets(plan: dict, remote_assets: list[dict]) -> list[str]:
    """Return sorted missing names, refusing every conflicting or unknown remote asset.

    Digests must come from the adapter's bounded downloads, not remote digest
    claims. Matching existing assets are retained; nothing is deleted/overwritten.
    """
    checked = _validated_plan(plan)
    _require(isinstance(remote_assets, list), "remote assets must be a list")
    seen_names: set[str] = set()
    seen_ids: set[int] = set()
    for row in remote_assets:
        _require(isinstance(row, dict) and set(row) == {"id", "name", "bytes", "sha256"},
                 "invalid normalized remote asset fields")
        _require(_positive(row["id"]) and row["id"] not in seen_ids,
                 "invalid or duplicate remote asset id")
        name = row["name"]
        _require(isinstance(name, str) and name in checked["assets"] and name not in seen_names,
                 "unexpected or duplicate remote asset name")
        _require(_positive(row["bytes"]) and _matches(_DIGEST, row["sha256"]),
                 "invalid remote asset byte size or digest")
        _require({"bytes": row["bytes"], "sha256": row["sha256"]} == checked["assets"][name],
                 f"remote asset conflicts with plan: {name}")
        seen_names.add(name)
        seen_ids.add(row["id"])
    return sorted(set(checked["assets"]) - seen_names)
