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

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

import crypto
from container import DocxPlusBuilder, DocxPlusReader
from validate import validate_bytes


def _cmd_build(args: argparse.Namespace) -> int:
    builder = DocxPlusBuilder(paragraphs=[args.text], title=args.title)
    recipients = [bytes.fromhex(h) for h in (args.recipient or [])]
    threshold = tuple(int(x) for x in args.threshold.split(":")) if args.threshold else None
    seal = {}
    if args.password:
        seal["password"] = args.password
    elif recipients:
        seal["recipients"] = recipients

    for spec in args.module or []:
        slot, channel, src = spec.split(":", 2)
        payload = Path(src).read_bytes()
        if threshold:
            builder.add_threshold(slot, payload, k=threshold[0], n=threshold[1], channel_id=channel)
        else:
            builder.add_module(slot, channel, payload, payload_type=args.payload_type, **seal)

    for spec in args.project or []:
        slot, path = spec.split(":", 1)
        # A project ships its own .docxplus-reproduce.json when --attest is set.
        builder.add_project(slot, path, reproduce=args.attest or None, **seal)

    if args.signing_key:
        builder.sign(bytes.fromhex(Path(args.signing_key).read_text().strip()))

    data = builder.build()
    Path(args.output).write_bytes(data)
    if threshold and builder.threshold_shares:
        share_dir = Path(args.shares_dir or "shares")
        share_dir.mkdir(parents=True, exist_ok=True)
        for slot, shares in builder.threshold_shares.items():
            for i, sh in enumerate(shares, 1):
                (share_dir / f"{slot}.share{i}.bin").write_bytes(sh)
        print(f"wrote {args.output} and {sum(len(s) for s in builder.threshold_shares.values())} shares to {share_dir}")
    else:
        print(f"wrote {args.output}")
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
    reader = DocxPlusReader.from_bytes(Path(args.docx).read_bytes())
    creds = {}
    if args.password:
        creds["password"] = args.password
    if args.private_key:
        creds["private_key"] = bytes.fromhex(Path(args.private_key).read_text().strip())
    if args.share:
        creds["shares"] = [Path(p).read_bytes() for p in args.share]
    data = reader.extract(args.slot, **creds)
    if args.out:
        Path(args.out).write_bytes(data)
        print(f"wrote {args.out} ({len(data)} bytes)")
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


def _cmd_validate(args: argparse.Namespace) -> int:
    report = validate_bytes(Path(args.docx).read_bytes())
    print(json.dumps(report.to_dict(), indent=2))
    return 0 if report.ok else 1


def _cmd_keygen(args: argparse.Namespace) -> int:
    if args.type == "x25519":
        priv, pub = crypto.generate_recipient_key()
    else:
        priv, pub = crypto.generate_signing_key()
    Path(args.output).write_text(priv.hex())
    Path(args.output + ".pub").write_text(pub.hex())
    print(f"wrote {args.output} and {args.output}.pub ({args.type})")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="docxplus", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    b = sub.add_parser("build", help="build a DOCX+ document")
    b.add_argument("output")
    b.add_argument("--text", default="This is an ordinary document.")
    b.add_argument("--title", default="Document")
    b.add_argument("--module", action="append", metavar="SLOT:CHANNEL:FILE")
    b.add_argument("--project", action="append", metavar="SLOT:DIR", help="carry a whole directory")
    b.add_argument("--payload-type", default="bytes")
    b.add_argument("--password", help="password-seal all modules")
    b.add_argument("--recipient", action="append", metavar="HEXPUB", help="X25519 recipient (repeatable)")
    b.add_argument("--threshold", metavar="K:N", help="Shamir k-of-n seal")
    b.add_argument("--shares-dir", help="where to write threshold shares")
    b.add_argument("--signing-key", help="hex Ed25519 private key file")
    b.add_argument(
        "--attest", action="store_true",
        help="run each project's .docxplus-reproduce.json recipe and seal the attestation",
    )
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

    v = sub.add_parser("validate", help="validate OPC + intelligence conformance")
    v.add_argument("docx")
    v.set_defaults(func=_cmd_validate)

    k = sub.add_parser("keygen", help="generate a signing (ed25519) or recipient (x25519) key")
    k.add_argument("output")
    k.add_argument("--type", choices=["ed25519", "x25519"], default="ed25519")
    k.set_defaults(func=_cmd_keygen)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
