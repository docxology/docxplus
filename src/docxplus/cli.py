#!/usr/bin/env python3
"""``docxplus`` — build, inspect, extract, validate intelligent documents.

Thin orchestrator over ``src/``. Highlights::

    docxplus build out.docx --text "Report" \
        --module brief:custom_xml:brief.json --payload-type json
    docxplus build out.docx --project source:./myrepo --password s3cret
    docxplus build out.docx --module m:package_part:x.bin \
        --recipient <hex> --recipient <hex>          # multi-recipient
    docxplus build out.docx --module m:package_part:x.bin --threshold 3:5 --shares-dir shares/
    docxplus graph out.docx                          # module tree
    docxplus extract out.docx m --private-key key.hex --out m.bin
    docxplus keygen key.hex --type ed25519|x25519
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
import tempfile
from pathlib import Path

from . import crypto, payloads, shamir
from .container import ContainerError, DocxPlusBuilder, DocxPlusReader
from .fileext import document_paths, preflight_document, write_document
from .reproduce import ReproError
from .secure_io import SecretExistsError, write_secret
from .validate import validate_bytes

#: ODF channel ids the CLI may select with ``SLOT:CHANNEL:FILE``. This tuple only
#: disambiguates the older ``SLOT:FILE`` form; the builder still validates the id.
ODT_CLI_CHANNELS = ("odt_package_part", "odt_metadata", "stego_media")


def _read_key(filename: str, label: str) -> bytes:
    path = Path(filename)
    if not path.is_file():
        raise ValueError(f"{label} file not found: {filename!r}")
    try:
        return bytes.fromhex(path.read_text(encoding="utf-8").strip())
    except (ValueError, UnicodeError) as exc:
        raise ValueError(f"invalid hex {label} in {filename!r}: {exc}") from exc


def _preflight_file(path: Path, *, exclusive: bool) -> None:
    if exclusive and (path.exists() or path.is_symlink()):
        raise SecretExistsError(f"refusing to overwrite existing secret material at {path}")
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError(f"output is not a regular file: {path}")
    for parent in path.parents:
        if parent.exists() and not parent.is_dir():
            raise ValueError(f"output parent is not a directory: {parent}")


def _distinct_outputs(outputs: list[Path], inputs: list[Path] | tuple[Path, ...] = ()) -> None:
    """Refuse pathname, ancestor and existing-inode collisions before publication."""
    resolved = [p.resolve() for p in outputs]
    for i, path in enumerate(outputs):
        for j, other in enumerate(outputs[:i]):
            if (resolved[i] == resolved[j] or resolved[i] in resolved[j].parents
                    or resolved[j] in resolved[i].parents
                    or (path.exists() and other.exists() and path.samefile(other))):
                raise ValueError(f"output paths collide: {path} and {other}")
        for source in inputs:
            if (resolved[i] == source.resolve()
                    or (source.is_dir() and source.resolve() in resolved[i].parents)
                    or (path.exists() and source.exists() and path.samefile(source))):
                raise ValueError(f"output collides with input: {path} and {source}")


def _stage_secrets(files: list[tuple[Path, bytes | str]]) -> list[tuple[Path, Path]]:
    """Complete private sibling staging before any related output is published."""
    staged = []
    try:
        for target, content in files:
            target.parent.mkdir(parents=True, exist_ok=True)
            directory = Path(tempfile.mkdtemp(prefix=f".{target.name}.", dir=target.parent))
            temporary = directory / "content"
            staged.append((temporary, target))
            write_secret(temporary, content)
        return staged
    except BaseException:
        for temporary, _ in staged:
            temporary.unlink(missing_ok=True)
            temporary.parent.rmdir()
        raise


def _publish_secrets(staged: list[tuple[Path, Path]]) -> None:
    # Each no-clobber directory-entry publication is atomic, not the whole set.
    published = []
    try:
        for temporary, target in staged:
            os.link(temporary, target)
            published.append((temporary, target))
    except BaseException:
        for temporary, target in reversed(published):
            if target.exists() and not target.is_symlink() and target.samefile(temporary):
                target.unlink()
        raise


def _payload_file(path: Path, payload_type: str) -> object:
    if payload_type == "project":
        raise ValueError("--payload-type project is not a file codec; use build --project SLOT:DIR")
    if payload_type == "docxplus":
        raise ValueError("--payload-type docxplus requires the add_nested builder API")
    if payload_type not in ("bytes", "text", "json"):
        raise ValueError(f"unsupported CLI payload type: {payload_type!r}")
    raw = path.read_bytes()
    if payload_type == "text":
        return raw.decode("utf-8")
    if payload_type == "json":
        def reject_constant(value: str) -> None:
            raise ValueError(f"invalid JSON constant: {value}")

        def finite_float(value: str) -> float:
            number = float(value)
            if not math.isfinite(number):
                raise ValueError(f"JSON number is outside the supported finite range: {value}")
            return number

        return json.loads(raw.decode("utf-8"), parse_constant=reject_constant,
                          parse_float=finite_float)
    return raw


def _build(args: argparse.Namespace, *, odt: bool = False) -> int:
    if odt:
        from .odt_container import OdtPlusBuilder

        builder = OdtPlusBuilder(paragraphs=[args.text], title=args.title)
    else:
        builder = DocxPlusBuilder(paragraphs=[args.text], title=args.title)
    recipients = [bytes.fromhex(h) for h in (args.recipient or [])]
    threshold = None
    if args.threshold is not None:
        try:
            k, n = (int(x) for x in args.threshold.split(":"))
        except ValueError as exc:
            raise ValueError("--threshold requires K:N") from exc
        if not 1 <= k <= n <= shamir.MAX_X:
            raise ValueError(f"--threshold requires 1 <= K <= N <= {shamir.MAX_X}")
        threshold = (k, n)
    if sum((args.password is not None, bool(recipients), threshold is not None)) > 1:
        raise ValueError("choose at most one of --password/--recipient/--threshold")
    if args.pad_recipients and not recipients:
        raise ValueError("--pad-recipients requires --recipient")
    if args.pad_recipients < 0:
        raise ValueError("--pad-recipients cannot be negative")
    if args.pad_recipients and args.pad_recipients < len(recipients):
        raise ValueError("--pad-recipients cannot discard recipients")
    if args.shares_dir and threshold is None:
        raise ValueError("--shares-dir requires --threshold")
    seal = {"kdf": args.kdf}
    if args.password is not None:
        seal["password"] = args.password
    elif recipients:
        seal.update(recipients=recipients, recipient_padding=args.pad_recipients)
    elif threshold is not None:
        seal["threshold"] = threshold

    # Parse every input and validate every signing identity before publication.
    inputs = []
    slots = []
    modules = []
    for spec in args.module or []:
        parts = spec.split(":", 2)
        if odt:
            # Historical SLOT:FILE stays valid, including a colon in the path.
            # SLOT:CHANNEL:FILE is recognised only when the middle field is a
            # known ODF transport, so `slot:dir/file` cannot be misparsed.
            if len(parts) == 3 and parts[1] in ODT_CLI_CHANNELS:
                slot, channel, src = parts
            elif len(parts) >= 2:
                slot, channel, src = parts[0], "odt_package_part", spec.split(":", 1)[1]
            else:
                raise ValueError(
                    f"invalid --module format {spec!r}; expected SLOT[:CHANNEL]:FILE"
                )
        else:
            if len(parts) != 3:
                raise ValueError(
                    f"invalid --module format {spec!r}; expected SLOT:CHANNEL:FILE"
                )
            slot, channel, src = parts
        path = Path(src)
        if not path.is_file():
            raise ValueError(f"module file not found: {src!r}")
        inputs.append(path)
        slots.append(slot)
        modules.append((slot, channel, _payload_file(path, args.payload_type)))
    projects = []
    for spec in args.project or []:
        parts = spec.split(":", 1)
        if len(parts) != 2:
            raise ValueError(f"invalid --project format {spec!r}; expected SLOT:DIR")
        slot, source = parts
        if not Path(source).is_dir():
            raise ValueError(f"project directory not found: {source!r}")
        inputs.append(Path(source))
        slots.append(slot)
        projects.append((slot, source))
    if len(set(slots)) != len(slots) or any(not slot for slot in slots):
        raise ValueError("module slots must be nonempty and unique")
    signing = _read_key(args.signing_key, "signing key") if args.signing_key else None
    cosigners = [_read_key(p, "cosigner key") for p in args.cosign or []]
    for key in ([signing] if signing is not None else []) + cosigners:
        crypto.signing_public_key(key)
    for filename in [args.signing_key, *(args.cosign or [])]:
        if filename:
            inputs.extend([Path(filename), Path(filename + ".pub")])

    documents = document_paths(args.output)
    shares = []
    if threshold is not None:
        for slot in slots:
            if slot in (".", "..") or "/" in slot or "\\" in slot or "\x00" in slot:
                raise ValueError("threshold slots must be safe share filename components")
            shares.extend(Path(args.shares_dir or "shares") / f"{slot}.share{i}.bin"
                          for i in range(1, threshold[1] + 1))
    _distinct_outputs(documents + shares, inputs)
    preflight_document(args.output)
    for path in shares:
        _preflight_file(path, exclusive=True)

    for slot, channel, obj in modules:
        if odt:
            builder.add_module(slot, obj, payload_type=args.payload_type,
                               channel_id=channel, **seal)
        else:
            builder.add_module(slot, channel, obj, payload_type=args.payload_type, **seal)
    for slot, source in projects:
        builder.add_project(slot, source, reproduce=args.attest or None,
                            max_uncompressed=args.max_uncompressed, **seal)
    if signing is not None:
        builder.sign(signing)
    for key in cosigners:
        builder.add_cosigner(key)
    data = builder.build()  # validates recipient key families before any output write
    share_files = [
        (Path(args.shares_dir or "shares") / f"{slot}.share{i}.bin", share)
        for slot, values in builder.threshold_shares.items()
        for i, share in enumerate(values, 1)
    ]
    staged = _stage_secrets(share_files)
    try:
        written = write_document(data, args.output)
        _publish_secrets(staged)
    finally:
        for temporary, _ in staged:
            temporary.unlink(missing_ok=True)
            temporary.parent.rmdir()
    print(f"wrote {' and '.join(str(w) for w in written)}"
          + (f" plus {len(share_files)} shares" if share_files else ""))
    return 0


def _cmd_build(args: argparse.Namespace) -> int:
    return _build(args)


def _cmd_inspect(args: argparse.Namespace) -> int:
    reader = DocxPlusReader.from_bytes(Path(args.docx).read_bytes())
    print(json.dumps({
        "modules": [r.to_dict() for r in reader.manifest.records],
        "merkle_root": reader.merkle_root(),
        "signature": reader.signature_status(),
        "version": reader.manifest.version,
    }, indent=2))
    return 0


def _cmd_graph(args: argparse.Namespace) -> int:
    reader = DocxPlusReader.from_bytes(Path(args.docx).read_bytes())
    print(f"{Path(args.docx).name}  [signature: {reader.signature_status()}]")
    print(f"  merkle_root: {reader.merkle_root()[:16]}…" if reader.merkle_root() else "  (no modules)")
    for r in reader.manifest.records:
        mode = r.sealing.get("mode", "plain")
        print(f"  • {r.slot}  type={r.payload_type}  channel={r.channel}  seal={mode}  {r.size}B")
    return 0


def _extraction_credentials(args: argparse.Namespace) -> dict:
    creds = {}
    if args.password is not None:
        creds["password"] = args.password
    if args.private_key:
        creds["private_key"] = _read_key(args.private_key, "private key")
    if args.share:
        creds["shares"] = [Path(p).read_bytes() for p in args.share]
    return creds


def _extraction_inputs(args: argparse.Namespace, document: str) -> list[Path]:
    return [*document_paths(document), *(Path(p) for p in args.share or []),
            *([Path(args.private_key), Path(args.private_key + ".pub")] if args.private_key else [])]


def _preflight_extraction(args: argparse.Namespace, document: str) -> None:
    if args.out:
        target = Path(args.out)
        _distinct_outputs([target], _extraction_inputs(args, document))
        _preflight_file(target, exclusive=False)


def _cmd_extract(args: argparse.Namespace) -> int:
    try:
        reader = DocxPlusReader.from_bytes(Path(args.docx).read_bytes())
    except Exception as exc:  # noqa: BLE001 — CLI boundary: report any failure cleanly
        sys.stderr.write(f"error: failed to open document {args.docx!r}: {exc}\n")
        return 1
    _preflight_extraction(args, args.docx)
    creds = _extraction_credentials(args)
    try:
        data = reader.extract(args.slot, **creds)
    except Exception as exc:  # noqa: BLE001 — CLI boundary: report any failure cleanly
        sys.stderr.write(f"error: extraction failed: {exc}\n")
        return 1
    if args.out:
        write_secret(args.out, data, overwrite=True)
        print(f"wrote {args.out} ({len(data)} bytes, mode 0600)")
    else:
        sys.stdout.buffer.write(data)
    return 0


def _cmd_unpack_project(args: argparse.Namespace) -> int:
    from .odt_container import open_document

    _distinct_outputs([Path(args.dest)], _extraction_inputs(args, args.docx))
    reader = open_document(Path(args.docx).read_bytes())
    creds = _extraction_credentials(args)
    dest = reader.extract_project(args.slot, args.dest,
                                  max_uncompressed=args.max_uncompressed, **creds)
    print(f"extracted project to {dest}")
    return 0


def _cmd_verify_reproduction(args: argparse.Namespace) -> int:
    from .odt_container import open_document

    reader = open_document(Path(args.docx).read_bytes())
    expected = _read_key(args.expected_key, "expected key") if args.expected_key else None
    info = reader.verify_reproduction(args.slot, expected_public_key=expected)
    if expected is None:
        info["_warning"] = (
            f"signer {(reader.signer() or '')[:16]}… is self-asserted; "
            "self-consistency is not authenticity; pass --expected-key to authenticate"
        )
    print(json.dumps(info, indent=2))
    status = "verified" if expected is not None else "self_consistent"
    return 0 if info.get("attested") and info.get(status) else 1


def _cmd_reproduce(args: argparse.Namespace) -> int:
    if not args.allow_execution:
        sys.stderr.write(
            "reproduce EXECUTES code carried by the document. Re-run with "
            "--allow-execution, and only in a sandbox you trust.\n"
        )
        return 2
    from .odt_container import open_document

    _distinct_outputs([Path(args.dest)], _extraction_inputs(args, args.docx))
    reader = open_document(Path(args.docx).read_bytes())
    creds = _extraction_credentials(args)
    result = reader.reproduce(args.slot, args.dest, allow_execution=True,
                              max_uncompressed=args.max_uncompressed, **creds)
    print(json.dumps(result, indent=2))
    return 0 if result["match"] else 1


def _cmd_verify_transparency(args: argparse.Namespace) -> int:
    """Verify a transparency log's chain, its signed tree head, and inclusion proofs.

    Exit status is the whole point of this command, so it fails closed: any
    requested check that does not pass returns nonzero, and an unanchored log (no
    ``--sth``) is reported as *unauthenticated* however clean its chain is.
    """
    from .provenance import verify_inclusion
    from .transparency import TransparencyLog

    report: dict = {"log": str(args.log)}
    try:
        log = TransparencyLog.from_json(Path(args.log).read_text())
    except (ValueError, KeyError, json.JSONDecodeError) as exc:
        print(json.dumps({**report, "chain_verified": False, "error": str(exc)}, indent=2))
        return 1

    report["entries"] = len(log.entries)
    report["chain_verified"] = log.verify_chain()
    report["merkle_root"] = log.merkle_tree_root()

    ok = report["chain_verified"]

    if args.expected_root:
        pinned = args.expected_root.strip().lower()
        report["root_pinned"] = pinned
        report["root_matches"] = report["merkle_root"] == pinned
        ok = ok and report["root_matches"]

    if args.sth:
        expected_key = (
            bytes.fromhex(Path(args.expected_key).read_text().strip())
            if args.expected_key
            else None
        )
        sth = json.loads(Path(args.sth).read_text())
        verified = log.verify_signed_tree_head(sth, expected_public_key=expected_key)
        report["sth_verified"] = verified
        report["sth_signer"] = str(sth.get("public_key", ""))[:16] + "…"
        ok = ok and verified
        if expected_key is None:
            report["_warning"] = (
                "STH signer is self-asserted; pass --expected-key to authenticate it"
            )
    else:
        report["sth_verified"] = None
        report["_warning"] = (
            "no signed tree head supplied: chain self-consistency was checked, but "
            "the log is UNAUTHENTICATED — a wholly rewritten log would also pass"
        )

    if args.consistent_with:
        old_proof = json.loads(Path(args.consistent_with).read_text())
        consistent = log.verify_consistency(old_proof)
        report["append_only_verified"] = consistent
        report["consistent_with_size"] = old_proof.get("old_size")
        ok = ok and consistent

    if args.emit_proof:
        target = Path(args.emit_proof)
        inputs = [Path(p) for p in
                  (args.log, args.sth, args.expected_key, args.consistent_with) if p]
        _distinct_outputs([target], inputs)
        _preflight_file(target, exclusive=False)
        write_secret(target, json.dumps(log.consistency_proof(), indent=2), overwrite=True)
        report["proof_written"] = args.emit_proof

    if args.prove is not None:
        try:
            proof = log.inclusion_proof(args.prove)
        except KeyError:
            report["inclusion"] = {"index": args.prove, "verified": False, "error": "no such index"}
            ok = False
        else:
            verified = verify_inclusion(proof, report["merkle_root"])
            report["inclusion"] = {
                "index": args.prove,
                "verified": verified,
                "siblings": len(proof["siblings"]),
                "attestation_digest": log.entries[args.prove].attestation_digest,
            }
            ok = ok and verified

    print(json.dumps(report, indent=2))
    return 0 if ok else 1


def _cmd_odt_build(args: argparse.Namespace) -> int:
    """Build ODT using the same authoring and publication policy as DOCX."""
    return _build(args, odt=True)


def _cmd_odt_inspect(args: argparse.Namespace) -> int:
    from .odt_container import OdtPlusReader

    reader = OdtPlusReader.from_bytes(Path(args.odt).read_bytes())
    print(json.dumps({
        "modules": [r.to_dict() for r in reader.manifest.records],
        "merkle_root": reader.merkle_root(),
        "signature": reader.signature_status(),
        "version": reader.manifest.version,
    }, indent=2))
    return 0


def _cmd_odt_extract(args: argparse.Namespace) -> int:
    from .odt_container import OdtPlusReader

    try:
        reader = OdtPlusReader.from_bytes(Path(args.odt).read_bytes())
    except Exception as exc:  # noqa: BLE001 — CLI boundary: report any failure cleanly
        sys.stderr.write(f"error: failed to open ODT document {args.odt!r}: {exc}\n")
        return 1
    _preflight_extraction(args, args.odt)
    creds = _extraction_credentials(args)
    try:
        data = reader.extract(args.slot, **creds)
    except Exception as exc:  # noqa: BLE001 — CLI boundary: report any failure cleanly
        sys.stderr.write(f"error: extraction failed: {exc}\n")
        return 1
    if args.out:
        write_secret(args.out, data, overwrite=True)
        print(f"wrote {args.out} ({len(data)} bytes, mode 0600)")
    else:
        sys.stdout.buffer.write(data)
    return 0


def _cmd_odt_validate(args: argparse.Namespace) -> int:
    from .validate import validate_odt_bytes

    report = validate_odt_bytes(Path(args.odt).read_bytes())
    print(json.dumps(report.to_dict(), indent=2))
    return 0 if report.ok else 1


def _cmd_odt_scan(args: argparse.Namespace) -> int:
    """Threat-scan an untrusted .odt. Executes nothing."""
    from . import intake

    policy = intake.IntakePolicy(strict=args.strict)
    try:
        report, _reader = intake.safe_open_odt(Path(args.odt).read_bytes(), policy=policy)
    except intake.IntakeError as exc:
        print(str(exc))
        return 1
    print(json.dumps(report.to_dict(), indent=2))
    return 0 if report.ok else 1


def _cmd_analyze_carrier(args: argparse.Namespace) -> int:
    """Report pair-equality compatibility, not evidence of payload presence."""
    from . import steg_bridge

    report = steg_bridge.steganalysis_report(Path(args.image), steps=args.steps)
    print(json.dumps(report, indent=2))
    # Sparse/unsupported observations are inconclusive, not a negative result.
    if not report["available"]:
        return 2
    return 1 if report["suspicious"] else 0


def _cmd_transparency_append(args: argparse.Namespace) -> int:
    """Append a reproduction attestation to a transparency log, optionally re-signing.

    `verify-transparency` had no producer in the tool, so a log could be checked
    but never built by it.
    """
    from .transparency import TransparencyLog

    log_path = Path(args.log)
    log = TransparencyLog.from_json(log_path.read_text()) if log_path.exists() else TransparencyLog()

    attestation = json.loads(Path(args.attestation).read_text()) if args.attestation else {}
    metadata = json.loads(args.metadata) if args.metadata else {}
    entry = log.append(attestation, metadata, timestamp=args.timestamp)

    out = {"appended_index": entry.index, "entries": len(log.entries), "root": log.merkle_tree_root()}
    files = [(log_path, log.to_json())]
    inputs = [Path(args.attestation)] if args.attestation else []
    if args.signing_key:
        priv = _read_key(args.signing_key, "signing key")
        crypto.signing_public_key(priv)
        sth = log.signed_tree_head(priv, timestamp=args.timestamp)
        sth_path = Path(args.sth_out or "sth.json")
        files.append((sth_path, json.dumps(sth, indent=2)))
        inputs.extend([Path(args.signing_key), Path(args.signing_key + ".pub")])
        out["sth"] = str(sth_path)
    else:
        out["_warning"] = (
            "no --signing-key: the log is UNANCHORED, and an unanchored chain "
            "proves only self-consistency"
        )
    _distinct_outputs([path for path, _ in files], inputs)
    for path, _ in files:
        _preflight_file(path, exclusive=False)
    staged = _stage_secrets(files)
    try:
        for temporary, target in staged:
            _preflight_file(target, exclusive=False)
            os.replace(temporary, target)
    finally:
        for temporary, _ in staged:
            temporary.unlink(missing_ok=True)
            temporary.parent.rmdir()
    print(json.dumps(out, indent=2))
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    """Verify authenticity: signature, package binding, and co-signer policy.

    This is the command `validate` is not. `validate` answers "is this
    well-formed and internally consistent", which a forger can satisfy; only
    `verify_provenance` checks that the signed surface digest still matches the
    package in hand, and only a pinned key says *whose* signature it is. Without a
    command for it, the strongest check the library offers had no way to be run
    from a shell, and `inspect` printing "valid" was the closest thing on offer.
    """
    from .odt_container import open_document

    data = Path(args.document).read_bytes()
    reader = open_document(data)
    expected = (
        bytes.fromhex(Path(args.expected_key).read_text().strip())
        if args.expected_key else None
    )
    cosigners = [bytes.fromhex(Path(k).read_text().strip()) for k in (args.require_cosigner or [])]

    report = {
        "document": str(args.document),
        "profile": "odt" if type(reader).__name__.startswith("Odt") else "docx",
        "signer": (reader.signer() or "")[:16] + "…" if reader.signer() else None,
        "signature_status": reader.signature_status(expected_public_key=expected),
        "provenance_verified": reader.verify_provenance(expected_public_key=expected),
        "modules": sorted(reader.list_modules()),
    }
    ok = bool(report["provenance_verified"])

    if cosigners:
        report["cosigners_verified"] = reader.verify_cosigners(cosigners)
        ok = ok and report["cosigners_verified"]

    if expected is None:
        report["_warning"] = (
            "no --expected-key: this checks that the package matches what SOME key "
            "signed, which is integrity, not authenticity. A forger can sign their "
            "own document and it reads exactly like this."
        )
        # Integrity alone must not exit 0 as though authenticity had been proved.
        ok = False

    print(json.dumps(report, indent=2))
    return 0 if ok else 1


def _cmd_validate(args: argparse.Namespace) -> int:
    report = validate_bytes(Path(args.docx).read_bytes())
    print(json.dumps(report.to_dict(), indent=2))
    return 0 if report.ok else 1


def _cmd_scan(args: argparse.Namespace) -> int:
    from . import intake

    policy = intake.IntakePolicy(strict=args.strict)
    try:
        report, _reader = intake.safe_open(Path(args.docx).read_bytes(), policy=policy)
    except intake.IntakeError as exc:
        print(str(exc))
        return 1
    print(json.dumps(report.to_dict(), indent=2))
    return 0 if report.ok else 1


def _cmd_keygen(args: argparse.Namespace) -> int:
    private_path = Path(args.output)
    public_path = Path(args.output + ".pub")
    _distinct_outputs([private_path, public_path])
    try:
        for path in (private_path, public_path):
            _preflight_file(path, exclusive=True)
    except SecretExistsError as exc:
        print(str(exc))
        return 1
    if args.type == "x25519":
        priv, pub = crypto.generate_recipient_key()
    elif args.type == "hybrid-recipient":
        kp = crypto.generate_hybrid_recipient_key()
        priv, pub = kp.private_bytes, kp.public_bytes
    elif args.type == "hybrid-signing":
        kp = crypto.generate_hybrid_signing_key()
        priv, pub = kp.private_bytes, kp.public_bytes
    else:
        priv, pub = crypto.generate_signing_key()
    staged = _stage_secrets([(private_path, priv.hex()), (public_path, pub.hex())])
    try:
        _publish_secrets(staged)
    finally:
        for temporary, _ in staged:
            temporary.unlink(missing_ok=True)
            temporary.parent.rmdir()
    print(f"wrote {args.output} (mode 0600) and {args.output}.pub ({args.type})")
    return 0


def _workflow_pins(args: argparse.Namespace) -> tuple[bytes | None, list[bytes]]:
    expected = _read_key(args.expected_key, "expected key") if args.expected_key else None
    cosigners = [_read_key(path, "co-signer key") for path in args.require_cosigner or []]
    return expected, cosigners


def _cmd_audit(args: argparse.Namespace) -> int:
    from .audit import audit_files

    expected, cosigners = _workflow_pins(args)
    report = audit_files(args.documents, expected_public_key=expected,
                        require_cosigners=cosigners, max_bytes=args.max_input_bytes,
                        max_documents=args.max_documents)
    print(json.dumps(report, indent=2))
    return 0 if report["ok"] else 1


def _cmd_compare(args: argparse.Namespace) -> int:
    from .comparison import compare_documents
    from .inspection import read_document_file

    expected, cosigners = _workflow_pins(args)
    report = compare_documents(
        read_document_file(args.left, max_bytes=args.max_input_bytes),
        read_document_file(args.right, max_bytes=args.max_input_bytes),
        expected_public_key=expected, require_cosigners=cosigners,
    )
    print(json.dumps(report, indent=2))
    if not report["ok"]:
        return 2
    return 0 if report["equal"] else 1


def _cmd_export(args: argparse.Namespace) -> int:
    from .export import export_modules
    from .inspection import read_document_file

    expected, cosigners = _workflow_pins(args)
    inputs = [Path(args.document), *(Path(path) for path in args.share or [])]
    inputs.extend(Path(path) for path in [args.private_key, args.expected_key] if path)
    inputs.extend(Path(path) for path in args.require_cosigner or [])
    _distinct_outputs([Path(args.destination)], inputs)
    report = export_modules(
        read_document_file(args.document, max_bytes=args.max_input_bytes), args.destination,
        slots=args.slot, expected_public_key=expected, require_cosigners=cosigners,
        max_bytes=args.max_bytes, max_modules=args.max_modules,
        **_extraction_credentials(args),
    )
    print(json.dumps(report, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="docxplus", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    b = sub.add_parser("build", help="build a docxplus document")
    b.add_argument("output")
    b.add_argument("--text", default="This is an ordinary document.")
    b.add_argument("--title", default="Document")
    b.add_argument("--module", action="append", metavar="SLOT:CHANNEL:FILE")
    b.add_argument("--project", action="append", metavar="SLOT:DIR", help="carry a whole directory")
    b.add_argument("--payload-type", default="bytes")
    b.add_argument("--max-uncompressed", type=int, default=payloads.MAX_PROJECT_UNCOMPRESSED,
                   help="maximum carried project content bytes")
    bp = b.add_mutually_exclusive_group()
    bp.add_argument("--password", help="password-seal all modules and projects")
    b.add_argument("--kdf", choices=["scrypt", "argon2id", "pbkdf2"], default="scrypt",
                       help="password key-derivation function (default: scrypt)")
    bp.add_argument("--recipient", action="append", metavar="HEXPUB",
                    help="X25519 or typed hybrid recipient public key (repeatable)")
    b.add_argument("--pad-recipients", type=int, default=0,
                   help="pad the recipient slot count to N, hiding how many "
                        "recipients there really are")
    bp.add_argument("--threshold", metavar="K:N", help="Shamir k-of-n seal")
    b.add_argument("--shares-dir", help="where to write threshold shares")
    b.add_argument("--signing-key", help="hex Ed25519 or typed hybrid signing key file")
    b.add_argument(
        "--attest", action="store_true",
        help="run each project's .docxplus-reproduce.json recipe and seal the attestation",
    )
    b.add_argument("--cosign", action="append", metavar="KEYFILE",
                   help="hex Ed25519 or typed hybrid co-signer key (repeatable)")
    b.set_defaults(func=_cmd_build)

    i = sub.add_parser("inspect", help="dump the manifest as JSON")
    i.add_argument("docx")
    i.set_defaults(func=_cmd_inspect)

    g = sub.add_parser("graph", help="print the module tree")
    g.add_argument("docx")
    g.set_defaults(func=_cmd_graph)

    e = sub.add_parser("extract", help="extract one module by slot")
    e.add_argument("docx")
    e.add_argument("slot")
    e.add_argument("--out")
    e.add_argument("--password")
    e.add_argument("--private-key", help="hex X25519 or typed hybrid recipient private key file")
    e.add_argument("--share", action="append", metavar="FILE", help="threshold share (repeatable)")
    e.set_defaults(func=_cmd_extract)

    up = sub.add_parser("unpack-project", help="extract a project module to a directory")
    up.add_argument("docx")
    up.add_argument("slot")
    up.add_argument("dest")
    up.add_argument("--password")
    up.add_argument("--private-key", help="hex recipient private key file")
    up.add_argument("--share", action="append", metavar="FILE")
    up.add_argument("--max-uncompressed", type=int, default=payloads.MAX_PROJECT_UNCOMPRESSED,
                    help="maximum extracted project content bytes")
    up.set_defaults(func=_cmd_unpack_project)

    vr = sub.add_parser("verify-reproduction", help="cryptographically verify a repro attestation (no execution)")
    vr.add_argument("docx")
    vr.add_argument("slot")
    vr.add_argument("--expected-key", help="hex Ed25519 or typed hybrid public key file to pin the signer")
    vr.set_defaults(func=_cmd_verify_reproduction)

    rp = sub.add_parser("reproduce", help="OPT-IN: re-run a carried project's attested command in a sandbox")
    rp.add_argument("docx")
    rp.add_argument("slot")
    rp.add_argument("dest")
    rp.add_argument("--password")
    rp.add_argument("--private-key", help="hex recipient private key file")
    rp.add_argument("--share", action="append", metavar="FILE")
    rp.add_argument("--max-uncompressed", type=int, default=payloads.MAX_PROJECT_UNCOMPRESSED,
                    help="maximum extracted project content bytes")
    rp.add_argument("--allow-execution", action="store_true", help="required; executes carried code")
    rp.set_defaults(func=_cmd_reproduce)

    vt = sub.add_parser(
        "verify-transparency",
        help="verify a transparency log's hash chain, signed tree head, and inclusion proofs",
    )
    vt.add_argument("log", help="transparency log JSON (TransparencyLog.to_json output)")
    vt.add_argument("--expected-root", metavar="HEX", help="pin the expected Merkle root")
    vt.add_argument("--sth", metavar="FILE", help="signed tree head JSON to authenticate the log")
    vt.add_argument("--expected-key", help="hex Ed25519 or typed hybrid public key file pinning the STH signer")
    vt.add_argument(
        "--prove", type=int, metavar="INDEX", help="verify the Merkle inclusion proof for an entry"
    )
    vt.add_argument("--consistent-with", metavar="PROOF",
                    help="a consistency proof from an earlier state; fails if this log "
                         "is not an append-only extension of it")
    vt.add_argument("--emit-proof", metavar="FILE",
                    help="write a consistency proof for this log's current state")
    vt.set_defaults(func=_cmd_verify_transparency)

    ob = sub.add_parser("odt-build", help="build an .odt with a signed intelligence layer")
    ob.add_argument("output")
    ob.add_argument("--text", default="This is an ordinary document.")
    ob.add_argument("--title", default="Document")
    ob.add_argument(
        "--module", action="append", metavar="SLOT[:CHANNEL]:FILE",
        help="module payload; CHANNEL defaults to odt_package_part and may be "
             "odt_package_part, odt_metadata or stego_media",
    )
    ob.add_argument("--project", action="append", metavar="SLOT:DIR", help="carry a whole directory")
    ob.add_argument("--attest", action="store_true",
                    help="run each project's reproduction recipe and seal the attestation")
    ob.add_argument("--payload-type", default="bytes")
    ob.add_argument("--max-uncompressed", type=int, default=payloads.MAX_PROJECT_UNCOMPRESSED,
                    help="maximum carried project content bytes")
    op = ob.add_mutually_exclusive_group()
    op.add_argument("--password", help="password-seal all modules and projects")
    ob.add_argument("--kdf", choices=["scrypt", "argon2id", "pbkdf2"], default="scrypt",
                       help="password key-derivation function (default: scrypt)")
    op.add_argument("--recipient", action="append", metavar="HEXPUB")
    ob.add_argument("--pad-recipients", type=int, default=0,
                    help="pad the recipient slot count to N")
    op.add_argument("--threshold", metavar="K:N")
    ob.add_argument("--shares-dir")
    ob.add_argument("--signing-key")
    ob.add_argument("--cosign", action="append", metavar="KEYFILE")
    ob.set_defaults(func=_cmd_odt_build)

    oi = sub.add_parser("odt-inspect", help="dump an .odt intelligence manifest as JSON")
    oi.add_argument("odt")
    oi.set_defaults(func=_cmd_odt_inspect)

    oe = sub.add_parser("odt-extract", help="extract one module from an .odt by slot")
    oe.add_argument("odt")
    oe.add_argument("slot")
    oe.add_argument("--out")
    oe.add_argument("--password")
    oe.add_argument("--private-key")
    oe.add_argument("--share", action="append", metavar="FILE")
    oe.set_defaults(func=_cmd_odt_extract)

    ov = sub.add_parser("odt-validate", help="validate ODF + intelligence conformance")
    ov.add_argument("odt")
    ov.set_defaults(func=_cmd_odt_validate)

    os_ = sub.add_parser("odt-scan", help="hardened untrusted-ODT threat scan (no execution)")
    os_.add_argument("odt")
    os_.add_argument("--strict", action="store_true", help="exit nonzero / refuse on any threat")
    os_.set_defaults(func=_cmd_odt_scan)

    ac = sub.add_parser("analyze-carrier", help="PNG pair-equality compatibility (not payload detection)")
    ac.add_argument("image")
    ac.add_argument("--steps", type=int, default=10, help="prefix-sweep resolution")
    ac.set_defaults(func=_cmd_analyze_carrier)

    ta = sub.add_parser("transparency-append", help="append an attestation to a transparency log")
    ta.add_argument("log", help="log JSON (created when absent)")
    ta.add_argument("--attestation", metavar="FILE", help="attestation JSON to record")
    ta.add_argument("--metadata", metavar="JSON", help="inline JSON metadata for the entry")
    ta.add_argument("--timestamp", type=int, help="explicit timestamp (reproducible builds)")
    ta.add_argument("--signing-key", help="hex Ed25519 or typed hybrid signing key; emits a signed tree head")
    ta.add_argument("--sth-out", help="where to write the signed tree head")
    ta.set_defaults(func=_cmd_transparency_append)

    vf = sub.add_parser(
        "verify",
        help="verify AUTHENTICITY: signature + package binding under a pinned key",
    )
    vf.add_argument("document", help=".docx/.docxplus or .odt/.odtplus (profile is detected)")
    vf.add_argument("--expected-key", help="hex Ed25519 or typed hybrid public key file; required for a 0 exit")
    vf.add_argument("--require-cosigner", action="append", metavar="KEYFILE",
                    help="hex Ed25519 or typed hybrid public key that must also have signed (repeatable)")
    vf.set_defaults(func=_cmd_verify)

    v = sub.add_parser("validate", help="validate OPC + intelligence conformance")
    v.add_argument("docx")
    v.set_defaults(func=_cmd_validate)

    sc = sub.add_parser("scan", help="hardened untrusted-intake threat scan (no execution)")
    sc.add_argument("docx")
    sc.add_argument("--strict", action="store_true", help="exit nonzero / refuse on any threat")
    sc.set_defaults(func=_cmd_scan)

    k = sub.add_parser("keygen", help="generate a signing (ed25519), recipient (x25519), or hybrid key")
    k.add_argument("output")
    k.add_argument(
        "--type",
        choices=["ed25519", "x25519", "hybrid-recipient", "hybrid-signing"],
        default="ed25519",
    )
    k.set_defaults(func=_cmd_keygen)

    from .audit import MAX_AUDIT_DOCUMENTS
    from .export import MAX_EXPORT_BYTES, MAX_EXPORT_MODULES
    from .inspection import MAX_DOCUMENT_BYTES

    au = sub.add_parser("audit", help="batch structural/threat/pinned-identity audit; no payload decoding")
    au.add_argument("documents", nargs="+", help="document files, detected by container bytes")
    au.add_argument("--max-documents", type=int, default=MAX_AUDIT_DOCUMENTS,
                    help="maximum admitted batch size; excess inputs refuse, never truncate")
    au.set_defaults(func=_cmd_audit)

    cp = sub.add_parser("compare", help="compare manifest/package declarations, not plaintext or rendering")
    cp.add_argument("left")
    cp.add_argument("right")
    cp.set_defaults(func=_cmd_compare)

    ex = sub.add_parser("export", help="privately export selected raw payloads into a new directory")
    ex.add_argument("document")
    ex.add_argument("destination")
    ex.add_argument("--slot", action="append", help="selected slot; repeatable, defaults to all")
    ex.add_argument("--password")
    ex.add_argument("--private-key", help="hex recipient private key file")
    ex.add_argument("--share", action="append", metavar="FILE")
    ex.add_argument("--max-bytes", type=int, default=MAX_EXPORT_BYTES,
                    help="maximum combined recovered payload and index bytes")
    ex.add_argument("--max-modules", type=int, default=MAX_EXPORT_MODULES)
    ex.set_defaults(func=_cmd_export)

    for workflow_parser in (au, cp, ex):
        workflow_parser.add_argument("--expected-key", help="complete primary signing public key file")
        workflow_parser.add_argument("--require-cosigner", action="append", metavar="KEYFILE",
                                     help="required complete co-signer identity; needs --expected-key")
        workflow_parser.add_argument("--max-input-bytes", type=int, default=MAX_DOCUMENT_BYTES,
                                     help="bounded regular no-follow file read before ZIP parsing")

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except SecretExistsError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 1
    except (ValueError, TypeError, OSError, ContainerError, ReproError, KeyError, NotImplementedError) as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
