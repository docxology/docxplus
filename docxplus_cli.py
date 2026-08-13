#!/usr/bin/env python3
"""``docxplus`` command-line interface — build, inspect, extract, validate DOCX+.

Thin orchestrator: all logic lives in ``src/``. Examples::

    docxplus build out.docx --text "Hello" --module brief:custom_xml:payload.json
    docxplus inspect out.docx
    docxplus extract out.docx brief --out brief.json
    docxplus validate out.docx
    docxplus keygen key.hex
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

import crypto  # noqa: E402
from container import DocxPlusBuilder, DocxPlusReader  # noqa: E402
from validate import validate_bytes  # noqa: E402


def _cmd_build(args: argparse.Namespace) -> int:
    builder = DocxPlusBuilder(paragraphs=[args.text], title=args.title)
    for spec in args.module or []:
        slot, channel, src = spec.split(":", 2)
        payload = Path(src).read_bytes()
        builder.add_module(slot, channel, payload, password=args.password)
    if args.signing_key:
        builder.sign(bytes.fromhex(Path(args.signing_key).read_text().strip()))
    Path(args.output).write_bytes(builder.build())
    print(f"wrote {args.output}")
    return 0


def _cmd_inspect(args: argparse.Namespace) -> int:
    reader = DocxPlusReader.from_bytes(Path(args.docx).read_bytes())
    info = {
        "modules": [r.to_dict() for r in reader.manifest.records],
        "signature": reader.signature_status(),
        "version": reader.manifest.version,
    }
    print(json.dumps(info, indent=2))
    return 0


def _cmd_extract(args: argparse.Namespace) -> int:
    reader = DocxPlusReader.from_bytes(Path(args.docx).read_bytes())
    data = reader.extract(args.slot, password=args.password)
    if args.out:
        Path(args.out).write_bytes(data)
        print(f"wrote {args.out} ({len(data)} bytes)")
    else:
        sys.stdout.buffer.write(data)
    return 0


def _cmd_validate(args: argparse.Namespace) -> int:
    report = validate_bytes(Path(args.docx).read_bytes())
    print(json.dumps(report.to_dict(), indent=2))
    return 0 if report.ok else 1


def _cmd_keygen(args: argparse.Namespace) -> int:
    priv, pub = crypto.generate_signing_key()
    Path(args.output).write_text(priv.hex())
    Path(args.output + ".pub").write_text(pub.hex())
    print(f"wrote {args.output} and {args.output}.pub")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="docxplus", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_build = sub.add_parser("build", help="build a DOCX+ document")
    p_build.add_argument("output")
    p_build.add_argument("--text", default="This is an ordinary document.")
    p_build.add_argument("--title", default="Document")
    p_build.add_argument(
        "--module",
        action="append",
        metavar="SLOT:CHANNEL:FILE",
        help="attach a payload file on a channel under a manifest slot",
    )
    p_build.add_argument("--password", help="encrypt all attached modules")
    p_build.add_argument("--signing-key", help="hex Ed25519 private key file")
    p_build.set_defaults(func=_cmd_build)

    p_inspect = sub.add_parser("inspect", help="list intelligence modules")
    p_inspect.add_argument("docx")
    p_inspect.set_defaults(func=_cmd_inspect)

    p_extract = sub.add_parser("extract", help="extract one module by slot")
    p_extract.add_argument("docx")
    p_extract.add_argument("slot")
    p_extract.add_argument("--out")
    p_extract.add_argument("--password")
    p_extract.set_defaults(func=_cmd_extract)

    p_validate = sub.add_parser("validate", help="validate OPC + intelligence conformance")
    p_validate.add_argument("docx")
    p_validate.set_defaults(func=_cmd_validate)

    p_keygen = sub.add_parser("keygen", help="generate an Ed25519 signing key")
    p_keygen.add_argument("output")
    p_keygen.set_defaults(func=_cmd_keygen)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
