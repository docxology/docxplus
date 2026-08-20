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
import sys
from pathlib import Path



from . import crypto
from .container import DocxPlusBuilder, DocxPlusReader
from .fileext import write_document
from .secure_io import SecretExistsError, write_secret
from .validate import validate_bytes


def _cmd_build(args: argparse.Namespace) -> int:
    builder = DocxPlusBuilder(paragraphs=[args.text], title=args.title)
    recipients = [bytes.fromhex(h) for h in (args.recipient or [])]
    threshold = tuple(int(x) for x in args.threshold.split(":")) if args.threshold else None
    seal = {}
    if args.password:
        seal["password"] = args.password
    elif recipients:
        seal["recipients"] = recipients
        if getattr(args, "pad_recipients", 0):
            seal["recipient_padding"] = args.pad_recipients

    for spec in args.module or []:
        parts = spec.split(":", 2)
        if len(parts) != 3:
            sys.stderr.write(
                f"error: invalid --module format {spec!r}; expected SLOT:CHANNEL:FILE\n"
            )
            return 2
        slot, channel, src = parts
        src_path = Path(src)
        if not src_path.is_file():
            sys.stderr.write(f"error: module file not found: {src!r}\n")
            return 2
        payload = src_path.read_bytes()
        if threshold:
            builder.add_threshold(slot, payload, k=threshold[0], n=threshold[1], channel_id=channel)
        else:
            builder.add_module(slot, channel, payload, payload_type=args.payload_type,
                               kdf=args.kdf, **seal)

    for spec in args.project or []:
        parts = spec.split(":")
        if len(parts) != 2:
            sys.stderr.write(
                f"error: invalid --project format {spec!r}; expected SLOT:DIR\n"
            )
            return 2
        slot, path = parts
        if not Path(path).is_dir():
            sys.stderr.write(f"error: project directory not found: {path!r}\n")
            return 2
        # A project ships its own .docxplus-reproduce.json when --attest is set.
        builder.add_project(slot, path, reproduce=args.attest or None, kdf=args.kdf, **seal)

    if args.signing_key:
        key_path = Path(args.signing_key)
        if not key_path.is_file():
            sys.stderr.write(f"error: signing key file not found: {args.signing_key!r}\n")
            return 2
        try:
            builder.sign(bytes.fromhex(key_path.read_text().strip()))
        except ValueError as exc:
            sys.stderr.write(f"error: invalid hex signing key in {args.signing_key!r}: {exc}\n")
            return 2
    for keyfile in args.cosign or []:
        kf_path = Path(keyfile)
        if not kf_path.is_file():
            sys.stderr.write(f"error: cosigner key file not found: {keyfile!r}\n")
            return 2
        try:
            builder.add_cosigner(bytes.fromhex(kf_path.read_text().strip()))
        except ValueError as exc:
            sys.stderr.write(f"error: invalid hex cosigner key in {keyfile!r}: {exc}\n")
            return 2

    data = builder.build()
    written = write_document(data, args.output)
    if threshold and builder.threshold_shares:
        share_dir = Path(args.shares_dir or "shares")
        share_dir.mkdir(parents=True, exist_ok=True)
        for slot, shares in builder.threshold_shares.items():
            for i, sh in enumerate(shares, 1):
                write_secret(share_dir / f"{slot}.share{i}.bin", sh)
        print(f"wrote {' and '.join(str(w) for w in written)} plus "
              f"{sum(len(s) for s in builder.threshold_shares.values())} shares in {share_dir}")
    else:
        print(f"wrote {' and '.join(str(w) for w in written)}")
    return 0


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


def _cmd_extract(args: argparse.Namespace) -> int:
    try:
        reader = DocxPlusReader.from_bytes(Path(args.docx).read_bytes())
    except Exception as exc:
        sys.stderr.write(f"error: failed to open document {args.docx!r}: {exc}\n")
        return 1
    creds = {}
    if args.password:
        creds["password"] = args.password
    if args.private_key:
        pk_path = Path(args.private_key)
        if not pk_path.is_file():
            sys.stderr.write(f"error: private key file not found: {args.private_key!r}\n")
            return 2
        try:
            creds["private_key"] = bytes.fromhex(pk_path.read_text().strip())
        except ValueError as exc:
            sys.stderr.write(f"error: invalid hex private key in {args.private_key!r}: {exc}\n")
            return 2
    if args.share:
        shares = []
        for p in args.share:
            sh_path = Path(p)
            if not sh_path.is_file():
                sys.stderr.write(f"error: share file not found: {p!r}\n")
                return 2
            shares.append(sh_path.read_bytes())
        creds["shares"] = shares
    try:
        data = reader.extract(args.slot, **creds)
    except Exception as exc:
        sys.stderr.write(f"error: extraction failed: {exc}\n")
        return 1
    if args.out:
        write_secret(args.out, data, overwrite=True)
        print(f"wrote {args.out} ({len(data)} bytes, mode 0600)")
    else:
        sys.stdout.buffer.write(data)
    return 0


def _cmd_unpack_project(args: argparse.Namespace) -> int:
    reader = DocxPlusReader.from_bytes(Path(args.docx).read_bytes())
    creds = {"password": args.password} if args.password else {}
    dest = reader.extract_project(args.slot, args.dest, **creds)
    print(f"extracted project to {dest}")
    return 0


def _cmd_verify_reproduction(args: argparse.Namespace) -> int:
    reader = DocxPlusReader.from_bytes(Path(args.docx).read_bytes())
    expected = bytes.fromhex(Path(args.expected_key).read_text().strip()) if args.expected_key else None
    info = reader.verify_reproduction(args.slot, expected_public_key=expected)
    if expected is None:
        info["_warning"] = f"signer {reader.signer()[:16]}… is self-asserted; pass --expected-key to authenticate"
    print(json.dumps(info, indent=2))
    return 0 if info.get("attested") and info.get("verified") else 1


def _cmd_reproduce(args: argparse.Namespace) -> int:
    if not args.allow_execution:
        sys.stderr.write(
            "reproduce EXECUTES code carried by the document. Re-run with "
            "--allow-execution, and only in a sandbox you trust.\n"
        )
        return 2
    reader = DocxPlusReader.from_bytes(Path(args.docx).read_bytes())
    creds = {"password": args.password} if args.password else {}
    result = reader.reproduce(args.slot, args.dest, allow_execution=True, **creds)
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
        Path(args.emit_proof).write_text(json.dumps(log.consistency_proof(), indent=2))
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
    """Build an .odt carrying the same signed intelligence layer as the .docx profile."""
    from .odt_container import OdtPlusBuilder

    builder = OdtPlusBuilder(paragraphs=[args.text], title=args.title)
    recipients = [bytes.fromhex(h) for h in (args.recipient or [])]
    threshold = tuple(int(x) for x in args.threshold.split(":")) if args.threshold else None
    seal = {}
    if args.password:
        seal["password"] = args.password
    elif recipients:
        seal["recipients"] = recipients
        if getattr(args, "pad_recipients", 0):
            seal["recipient_padding"] = args.pad_recipients

    for spec in args.module or []:
        parts = spec.split(":")
        if len(parts) != 2:
            sys.stderr.write(
                f"error: invalid --module format {spec!r}; expected SLOT:FILE\n"
            )
            return 2
        slot, src = parts
        src_path = Path(src)
        if not src_path.is_file():
            sys.stderr.write(f"error: module file not found: {src!r}\n")
            return 2
        payload = src_path.read_bytes()
        if threshold:
            builder.add_threshold(slot, payload, k=threshold[0], n=threshold[1])
        else:
            builder.add_module(slot, payload, payload_type=args.payload_type,
                               kdf=args.kdf, **seal)

    if args.signing_key:
        key_path = Path(args.signing_key)
        if not key_path.is_file():
            sys.stderr.write(f"error: signing key file not found: {args.signing_key!r}\n")
            return 2
        try:
            builder.sign(bytes.fromhex(key_path.read_text().strip()))
        except ValueError as exc:
            sys.stderr.write(f"error: invalid hex signing key in {args.signing_key!r}: {exc}\n")
            return 2
    for keyfile in args.cosign or []:
        kf_path = Path(keyfile)
        if not kf_path.is_file():
            sys.stderr.write(f"error: cosigner key file not found: {keyfile!r}\n")
            return 2
        try:
            builder.add_cosigner(bytes.fromhex(kf_path.read_text().strip()))
        except ValueError as exc:
            sys.stderr.write(f"error: invalid hex cosigner key in {keyfile!r}: {exc}\n")
            return 2

    written = write_document(builder.build(), args.output)
    if threshold and builder.threshold_shares:
        share_dir = Path(args.shares_dir or "shares")
        share_dir.mkdir(parents=True, exist_ok=True)
        for slot, shares in builder.threshold_shares.items():
            for i, sh in enumerate(shares, 1):
                write_secret(share_dir / f"{slot}.share{i}.bin", sh)
    print(f"wrote {' and '.join(str(w) for w in written)}")
    return 0


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
    except Exception as exc:
        sys.stderr.write(f"error: failed to open ODT document {args.odt!r}: {exc}\n")
        return 1
    creds = {}
    if args.password:
        creds["password"] = args.password
    if args.private_key:
        pk_path = Path(args.private_key)
        if not pk_path.is_file():
            sys.stderr.write(f"error: private key file not found: {args.private_key!r}\n")
            return 2
        try:
            creds["private_key"] = bytes.fromhex(pk_path.read_text().strip())
        except ValueError as exc:
            sys.stderr.write(f"error: invalid hex private key in {args.private_key!r}: {exc}\n")
            return 2
    if args.share:
        shares = []
        for p in args.share:
            sh_path = Path(p)
            if not sh_path.is_file():
                sys.stderr.write(f"error: share file not found: {p!r}\n")
                return 2
            shares.append(sh_path.read_bytes())
        creds["shares"] = shares
    try:
        data = reader.extract(args.slot, **creds)
    except Exception as exc:
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
    """Measure how detectable a stego carrier is, using the in-tree statistics.

    The security model tells readers to check their own carriers before an
    adversary does; without a command that is advice with no way to follow it.
    """
    from . import steg_bridge

    report = steg_bridge.steganalysis_report(Path(args.image), steps=args.steps)
    print(json.dumps(report, indent=2))
    # Exit 1 when the carrier looks embedded, so the check is usable in a script.
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
    log_path.write_text(log.to_json())

    out = {"appended_index": entry.index, "entries": len(log.entries), "root": log.merkle_tree_root()}
    if args.signing_key:
        priv = bytes.fromhex(Path(args.signing_key).read_text().strip())
        sth = log.signed_tree_head(priv, timestamp=args.timestamp)
        Path(args.sth_out or "sth.json").write_text(json.dumps(sth, indent=2))
        out["sth"] = args.sth_out or "sth.json"
    else:
        out["_warning"] = (
            "no --signing-key: the log is UNANCHORED, and an unanchored chain "
            "proves only self-consistency"
        )
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
    if args.type == "x25519":
        priv, pub = crypto.generate_recipient_key()
    elif args.type == "hybrid-recipient":
        kp = crypto.generate_hybrid_recipient_key()
        priv, pub = kp.classical_priv + kp.pq_priv, kp.public_bytes
    elif args.type == "hybrid-signing":
        kp = crypto.generate_hybrid_signing_key()
        priv, pub = kp.classical_priv + kp.pq_priv, kp.public_bytes
    else:
        priv, pub = crypto.generate_signing_key()
    try:
        write_secret(args.output, priv.hex())
    except SecretExistsError as exc:
        # Silently replacing a signing key destroys an identity irrecoverably.
        print(str(exc))
        return 1
    Path(args.output + ".pub").write_text(pub.hex())  # public by definition
    print(f"wrote {args.output} (mode 0600) and {args.output}.pub ({args.type})")
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
    b.add_argument("--password", help="password-seal all modules")
    b.add_argument("--kdf", choices=["scrypt", "argon2id", "pbkdf2"], default="scrypt",
                       help="password key-derivation function (default: scrypt)")
    b.add_argument("--recipient", action="append", metavar="HEXPUB", help="X25519 recipient (repeatable)")
    b.add_argument("--pad-recipients", type=int, default=0,
                   help="pad the recipient slot count to N, hiding how many "
                        "recipients there really are")
    b.add_argument("--threshold", metavar="K:N", help="Shamir k-of-n seal")
    b.add_argument("--shares-dir", help="where to write threshold shares")
    b.add_argument("--signing-key", help="hex Ed25519 private key file")
    b.add_argument(
        "--attest", action="store_true",
        help="run each project's .docxplus-reproduce.json recipe and seal the attestation",
    )
    b.add_argument("--cosign", action="append", metavar="KEYFILE", help="hex Ed25519 co-signer key (repeatable)")
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
    e.add_argument("--private-key", help="hex X25519 private key file (multi-recipient)")
    e.add_argument("--share", action="append", metavar="FILE", help="threshold share (repeatable)")
    e.set_defaults(func=_cmd_extract)

    up = sub.add_parser("unpack-project", help="extract a project module to a directory")
    up.add_argument("docx")
    up.add_argument("slot")
    up.add_argument("dest")
    up.add_argument("--password")
    up.set_defaults(func=_cmd_unpack_project)

    vr = sub.add_parser("verify-reproduction", help="cryptographically verify a repro attestation (no execution)")
    vr.add_argument("docx")
    vr.add_argument("slot")
    vr.add_argument("--expected-key", help="hex Ed25519 public key file to pin the signer (authenticate)")
    vr.set_defaults(func=_cmd_verify_reproduction)

    rp = sub.add_parser("reproduce", help="OPT-IN: re-run a carried project's attested command in a sandbox")
    rp.add_argument("docx")
    rp.add_argument("slot")
    rp.add_argument("dest")
    rp.add_argument("--password")
    rp.add_argument("--allow-execution", action="store_true", help="required; executes carried code")
    rp.set_defaults(func=_cmd_reproduce)

    vt = sub.add_parser(
        "verify-transparency",
        help="verify a transparency log's hash chain, signed tree head, and inclusion proofs",
    )
    vt.add_argument("log", help="transparency log JSON (TransparencyLog.to_json output)")
    vt.add_argument("--expected-root", metavar="HEX", help="pin the expected Merkle root")
    vt.add_argument("--sth", metavar="FILE", help="signed tree head JSON to authenticate the log")
    vt.add_argument("--expected-key", help="hex Ed25519 public key file pinning the STH signer")
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
    ob.add_argument("--module", action="append", metavar="SLOT:FILE")
    ob.add_argument("--payload-type", default="bytes")
    ob.add_argument("--password")
    ob.add_argument("--kdf", choices=["scrypt", "argon2id", "pbkdf2"], default="scrypt",
                       help="password key-derivation function (default: scrypt)")
    ob.add_argument("--recipient", action="append", metavar="HEXPUB")
    ob.add_argument("--pad-recipients", type=int, default=0,
                    help="pad the recipient slot count to N")
    ob.add_argument("--threshold", metavar="K:N")
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

    ac = sub.add_parser("analyze-carrier", help="statistical steganalysis of a PNG carrier")
    ac.add_argument("image")
    ac.add_argument("--steps", type=int, default=10, help="prefix-sweep resolution")
    ac.set_defaults(func=_cmd_analyze_carrier)

    ta = sub.add_parser("transparency-append", help="append an attestation to a transparency log")
    ta.add_argument("log", help="log JSON (created when absent)")
    ta.add_argument("--attestation", metavar="FILE", help="attestation JSON to record")
    ta.add_argument("--metadata", metavar="JSON", help="inline JSON metadata for the entry")
    ta.add_argument("--timestamp", type=int, help="explicit timestamp (reproducible builds)")
    ta.add_argument("--signing-key", help="hex Ed25519 key; emits a signed tree head")
    ta.add_argument("--sth-out", help="where to write the signed tree head")
    ta.set_defaults(func=_cmd_transparency_append)

    vf = sub.add_parser(
        "verify",
        help="verify AUTHENTICITY: signature + package binding under a pinned key",
    )
    vf.add_argument("document", help=".docx/.docxplus or .odt/.odtplus (profile is detected)")
    vf.add_argument("--expected-key", help="hex Ed25519 public key file; required for a 0 exit")
    vf.add_argument("--require-cosigner", action="append", metavar="KEYFILE",
                    help="hex Ed25519 public key that must also have signed (repeatable)")
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

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
