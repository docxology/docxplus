#!/usr/bin/env python3
"""Publish one reviewed docxplus asset bundle through native GitVault admission.

The optional SDK is loaded only from the explicitly supplied vault configuration's
adjacent _tools directory. This script never changes settings or credentials.
"""
from __future__ import annotations

import argparse
import importlib
import json
import os
import stat
import subprocess
import sys
import time
import tomllib
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import quote

from docxplus.release_publication import (
    PublicationError,
    confirmation_phrase,
    create_plan,
    missing_assets,
    read_assets,
    validate_plan,
    verify_remote_identity,
)

REPOSITORY = "docxology/docxplus"
ROOT = Path(__file__).resolve().parents[1]
API = f"repos/{REPOSITORY}"
MAX_PLAN_BYTES = 1024 * 1024


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PublicationError(message)


def inside_repository(path: Path) -> Path:
    absolute = Path(os.path.abspath(path))
    require(absolute.resolve().is_relative_to(ROOT), "path must remain in this repository")
    return absolute



def operational_path(path: Path) -> Path:
    absolute = inside_repository(path)
    operational_root = ROOT / "build/wfz-release"
    require(operational_root.resolve() == operational_root
            and absolute.is_relative_to(operational_root)
            and absolute.resolve().is_relative_to(operational_root),
            "publication assets and records must remain under the real build/wfz-release directory")
    return absolute


def unique_object(pairs: list[tuple]) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def read_plan(path: Path) -> dict:
    path = operational_path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and 0 < before.st_size <= MAX_PLAN_BYTES, "unsafe or oversized plan file")
        data = bytearray()
        while len(data) <= before.st_size:
            block = os.read(descriptor, min(65536, before.st_size + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        after = os.fstat(descriptor)
        fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        require(len(data) == before.st_size and all(getattr(before, key) == getattr(after, key)
                                                  for key in fields), "plan changed during read")
    finally:
        os.close(descriptor)
    value = json.loads(data, object_pairs_hook=unique_object)
    return validate_plan(value, now=int(time.time()))


_BINARY_DOWNLOAD = r'''
import hashlib,json,sys
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler,ProxyHandler,Request,build_opener
rates=[]
def record(headers):
    allowed={'x-ratelimit-used','x-ratelimit-remaining','x-ratelimit-limit','x-ratelimit-resource','x-ratelimit-reset','retry-after'}
    row={key.lower():str(value)[:128] for key,value in headers.items() if key.lower() in allowed}
    if row:rates.append(row)
class Redirect(HTTPRedirectHandler):
    count=0
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        record(headers);self.count+=1;target=urlsplit(newurl)
        if not(self.count<=5 and target.scheme=='https' and target.hostname in {'api.github.com','github.com','release-assets.githubusercontent.com','objects.githubusercontent.com'} and target.port in (None,443) and target.username is None and target.password is None and not target.fragment):raise ValueError('unsafe redirect')
        return Request(newurl,headers={'Accept':'application/octet-stream','User-Agent':'docxplus-release-publication'},method='GET')
try:
    identifier,size,seconds=int(sys.argv[1]),int(sys.argv[2]),float(sys.argv[3])
    if not(identifier>0 and 0<size<=128*1024*1024 and 0<seconds<=15):raise ValueError('invalid bounds')
    token=sys.stdin.buffer.read(4097)
    if not(0<len(token)<=4096):raise ValueError('invalid token input')
    request=Request(f'https://api.github.com/repos/docxology/docxplus/releases/assets/{identifier}',headers={'Authorization':'Bearer '+token.decode('ascii'),'Accept':'application/octet-stream','User-Agent':'docxplus-release-publication'})
    opener=build_opener(ProxyHandler({}),Redirect());digest=hashlib.sha256();count=0
    with opener.open(request,timeout=seconds) as response:
        record(response.headers)
        if response.status!=200:raise ValueError('asset status')
        while count<=size:
            block=response.read(min(65536,size+1-count))
            if not block:break
            count+=len(block)
            if count>size:raise ValueError('asset exceeds bound')
            digest.update(block)
    if count!=size:raise ValueError('asset shorter than planned')
    print(json.dumps({'ok':True,'bytes':count,'sha256':digest.hexdigest(),'rates':rates}),flush=True)
except Exception as error:
    headers=getattr(error,'headers',None)
    if headers is not None:record(headers)
    print(json.dumps({'ok':False,'error_type':type(error).__name__,'rates':rates}),flush=True)
    sys.exit(2)
'''


class Native:
    """Finite adapter around the installed native locks, identity, budget and transport."""

    def __init__(self, config: Path):
        sys.dont_write_bytecode = True
        os.environ.pop("GH_DEBUG", None)
        self.config = config.resolve(strict=True)
        tools = self.config.parent / "_tools"
        require(tools.is_dir(), "native SDK must be adjacent to the explicit vault configuration")
        sys.path.insert(0, str(tools))
        self.library = importlib.import_module("vaultlib")
        self.locks = importlib.import_module("vault_locks")
        self.activity = importlib.import_module("vault_activity")
        self.identities = importlib.import_module("vault_github_identity")
        self.budget = importlib.import_module("vault_github_budget")
        self.github = importlib.import_module("vault_github")
        self.plans = importlib.import_module("vault_github_plans")
        self.storage = importlib.import_module("vault_json")
        self.sources = importlib.import_module("vault_sources")
        self.cfg = self.library.configuration(self.config)
        self.original_cfg = self.cfg
        self.sdk_root = tools.resolve().parent
        for module in (self.library, self.locks, self.activity, self.identities, self.budget,
                       self.github, self.plans, self.storage, self.sources):
            require(Path(module.__file__).resolve().parent == tools.resolve(),
                    "native SDK modules do not match the selected tooling root")
        self.bindings = self.sources.source_bindings(self.sdk_root)
        self.deadline = time.monotonic() + 300
        self.lease_deadline = self.deadline
        self.actor = self.identities.write_identity(self.cfg, "docxology")
        self.identity = self.identities.resolve(self.cfg, self.actor, write=True)
        require(self.identity.mechanism == "token", "publication requires a mapped pinned token")
        self.observe_identity()

    def timeout(self, bound: float = 15) -> float:
        remaining = min(self.deadline, self.lease_deadline) - time.monotonic()
        require(remaining > 0, "bounded publication operation expired")
        return min(bound, remaining)

    def check_bindings(self) -> None:
        self.locks.check_configuration(self.original_cfg)
        require(self.sources.source_bindings(self.sdk_root) == self.bindings,
                "native source/configuration changed; requalify and re-plan")

    def record_headers(self, headers) -> None:
        rate = self.github.rate_from_headers({key.lower(): value for key, value in headers.items()})
        if rate:
            self.budget.record_resources(self.cfg, self.actor, {"core": rate})

    def observe_identity(self) -> None:
        """Observe the pinned token's actual viewer within native admission/deadlines."""
        self.check_bindings()
        allowed, _ = self.budget.plan_cost(self.cfg, self.actor, 1, resource="graphql")
        require(allowed, "native GraphQL identity budget refused the request")
        with self.budget.slot(self.cfg, wait=0):
            response = self.github.gh_graphql(
                self.identities.VIEWER_QUERY, identity=self.identity,
                timeout=self.timeout(), attempts=1,
            )
        if response.rate:
            self.budget.record_resources(self.cfg, self.actor, {"graphql": response.rate})
        body = response.data if isinstance(response.data, dict) else {}
        data = body.get("data") if isinstance(body.get("data"), dict) else {}
        viewer = data.get("viewer") if isinstance(data.get("viewer"), dict) else {}
        require(viewer.get("login") == self.actor, "pinned token's answering identity changed")

    def get(self, path: str, *, params: dict | None = None):
        self.check_bindings()
        allowed, _ = self.budget.plan_cost(self.cfg, self.actor, 1, resource="core")
        require(allowed, "native GitHub read budget refused the request")
        with self.budget.slot(self.cfg, wait=0):
            response = self.github.gh_api(path, identity=self.identity, params=params,
                                          timeout=self.timeout(), attempts=1)
        if response.rate:
            self.budget.record_resources(self.cfg, self.actor, {"core": response.rate})
        return response.data

    def local_source(self) -> tuple[str, str]:
        environment = self.library.git_environment()
        environment["GIT_OPTIONAL_LOCKS"] = "0"

        def git(*args: str) -> str:
            result = subprocess.run(["git", "-C", str(ROOT), *args], stdin=subprocess.DEVNULL,
                                    capture_output=True,
                                    env=environment, timeout=self.timeout(5), check=True)
            return result.stdout.decode("utf-8").strip()

        require(Path(git("rev-parse", "--show-toplevel")) == ROOT,
                "working copy is not the publication repository")
        require(git("branch", "--show-current") == "main", "publication requires local main")
        require(not git("status", "--porcelain=v1", "--untracked-files=normal"),
                "publication requires a clean committed working copy")
        return git("rev-parse", "HEAD"), git("rev-parse", "HEAD^{tree}")

    @contextmanager
    def lease(self, *, mutation: bool = False):
        self.check_bindings()
        cfg = self.library.configuration(self.config)
        if mutation:
            require(self.activity.lock_held(self.library.root_of(cfg) / "Local/operation.lock",
                                           exclusive_probe=True) is False,
                    "native idle-writer admission is busy or unavailable")
        with self.locks.repository_operation(cfg, REPOSITORY, "docxplus-release-publication",
                                             wait=False, working_copy=ROOT):
            self.cfg = cfg
            self.lease_deadline = min(self.deadline, time.monotonic() + 45)
            try:
                self.check_bindings()
                if mutation:
                    self.plans.require_enabled(cfg, "release")
                    require(self.identities.write_identity(cfg, "docxology") == self.actor,
                            "native owner mapping changed")
                    self.timeout()
                    self.identity = self.identities.resolve(cfg, self.actor, write=True)
                    require(self.identity.mechanism == "token", "mapped pinned token unavailable")
                    self.observe_identity()
                yield
            finally:
                self.lease_deadline = self.deadline

    def store(self, path: Path, value: dict, *, new: bool = False) -> None:
        path = operational_path(path)
        ignored = subprocess.run(["git", "-C", str(ROOT), "check-ignore", "-q", "--", str(path)],
                                 stdin=subprocess.DEVNULL, capture_output=True,
                                 env=self.library.git_environment(), timeout=self.timeout(5), check=False)
        require(ignored.returncode == 0, "publication records must be ignored operational files")
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if new:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.close(descriptor)
        self.storage.write_regular_json(path, value)

    def remote(self, release_id: int, tag: str) -> dict:
        actor = self.get("user").get("login")
        repository = self.get(API)
        require(repository.get("full_name") == REPOSITORY
                and repository.get("default_branch") == "main"
                and repository.get("archived") is False and repository.get("disabled") is False
                and (repository.get("permissions") or {}).get("push") is True,
                "live repository capability does not authorize this publication")
        main = self.get(f"{API}/git/ref/heads/main")["object"]["sha"]
        tree = self.get(f"{API}/git/commits/{main}")["tree"]["sha"]
        target = self.get(f"{API}/git/ref/tags/{quote(tag, safe='')}")["object"]
        for _ in range(4):
            if target.get("type") == "commit":
                break
            require(target.get("type") == "tag", "tag has an unsupported object type")
            target = self.get(f"{API}/git/tags/{target['sha']}")["object"]
        require(target.get("type") == "commit", "tag nesting exceeds the bounded peel")
        release = self.get(f"{API}/releases/{release_id}")
        return {"actor": actor, "main_commit": main, "main_tree": tree,
                "tag_commit": target["sha"], "release": release}

    def asset_rows(self, plan: dict) -> list[dict]:
        rows = self.get(f"{API}/releases/{plan['release_id']}/assets", params={"per_page": 100})
        require(isinstance(rows, list) and len(rows) <= 6, "unexpected release-asset inventory")
        normalized = []
        ids, names = set(), set()
        for row in rows:
            require(isinstance(row, dict), "malformed release-asset row")
            identifier, name, size = row.get("id"), row.get("name"), row.get("size")
            require(type(identifier) is int and identifier > 0 and identifier not in ids
                    and isinstance(name, str) and name in plan["assets"] and name not in names
                    and type(size) is int and size == plan["assets"][name]["bytes"]
                    and row.get("state") == "uploaded", "conflicting release-asset inventory")
            ids.add(identifier)
            names.add(name)
            normalized.append({"id": identifier, "name": name, "bytes": size})
        return sorted(normalized, key=lambda row: row["name"])

    def download(self, identifier: int, size: int) -> str:
        require(type(identifier) is int and identifier > 0 and type(size) is int
                and 0 < size <= 128 * 1024 * 1024, "invalid bounded download identity")
        self.check_bindings()
        allowed, _ = self.budget.plan_cost(self.cfg, self.actor, 1, resource="core")
        require(allowed, "native GitHub download budget refused the request")
        environment = self.identity.environment
        token = environment.get("GH_TOKEN") or environment.get("GITHUB_TOKEN")
        require(isinstance(token, str) and bool(token), "pinned token unavailable for asset readback")
        child_environment = {key: value for key, value in os.environ.items()
                             if key not in {"GH_TOKEN", "GITHUB_TOKEN", "GH_DEBUG"}}
        # Parent timeout kills/reaps this one non-forking reader even during DNS,
        # TLS, redirect/header handling or a slow buffered body read. No token argv.
        with self.budget.slot(self.cfg, wait=0):
            seconds = self.timeout()
            response = subprocess.run(
                [sys.executable, "-I", "-B", "-c", _BINARY_DOWNLOAD,
                 str(identifier), str(size), str(seconds)], input=token.encode("ascii"),
                capture_output=True, env=child_environment, timeout=seconds, check=False,
            )
        data = json.loads(response.stdout, object_pairs_hook=unique_object)
        require(isinstance(data, dict) and isinstance(data.get("rates"), list)
                and len(data["rates"]) <= 7, "invalid bounded asset-reader response")
        for headers in data["rates"]:
            require(isinstance(headers, dict), "invalid asset-reader rate observation")
            self.record_headers(headers)
        require(response.returncode == 0 and data.get("ok") is True
                and data.get("bytes") == size, "bounded binary asset readback failed")
        digest = data.get("sha256")
        require(isinstance(digest, str) and len(digest) == 64
                and all(char in "0123456789abcdef" for char in digest),
                "invalid downloaded asset digest")
        self.check_bindings()
        return digest

    def verified_assets(self, plan: dict) -> list[dict]:
        result = []
        for row in self.asset_rows(plan):
            result.append(row | {"sha256": self.download(row["id"], row["bytes"])})
        missing_assets(plan, result)
        return result

    def mutate(self, plan: dict, argv: list[str], *, content: bytes | None = None) -> dict:
        self.check_bindings()
        self.timeout()
        allowed, _ = self.budget.reserve_allows(self.cfg, self.actor, "core")
        require(allowed, "native GitHub reserve refused the mutation")
        allowed, _ = self.budget.write_window_allows(self.cfg, targets=1)
        require(allowed, "native GitHub write window refused the mutation")
        # Count attempts conservatively; ambiguous writes are never automatically retried.
        self.budget.record_write(self.cfg, targets=1)
        binary = {} if content is None else {"binary_input": content}
        with self.budget.slot(self.cfg, wait=0):
            validate_plan(plan, now=int(time.time()))
            response = self.github.invoke(argv, identity=self.identity, timeout=self.timeout(),
                                           attempts=1, include=True, resource="core", **binary)
        if response.rate:
            self.budget.record_resources(self.cfg, self.actor, {"core": response.rate})
        self.check_bindings()
        return response.data


def apply(native: Native, plan: dict, assets: Path, receipt_path: Path) -> dict:
    payloads = read_assets(plan, assets)
    receipt = {"schema": "docxplus.release-publication-receipt.v1", "plan_id": plan["plan_id"],
               "source_commit": plan["main_commit"], "source_tree": plan["main_tree"],
               "native_source_bindings": native.bindings,
               "native_configuration": {"path": str(native.original_cfg.source_version[0]),
                                        "sha256": native.original_cfg.source_version[1]},
               "attempted": [], "confirmed": [], "published": None, "verified": False}
    with native.lease():
        native.store(receipt_path, receipt, new=True)
    try:
        state = native.remote(plan["release_id"], plan["tag"])
        verify_remote_identity(plan, **state)
        receipt["published"] = not state["release"]["draft"]
        with native.lease():
            native.store(receipt_path, receipt)
        verified = native.verified_assets(plan)
        missing = missing_assets(plan, verified)
        require(state["release"]["draft"] or not missing,
                "a published release cannot be repaired or overwritten")
        writes = len(missing) + int(state["release"]["draft"])
        if writes:
            allowed, _ = native.budget.write_window_allows(native.cfg, targets=writes)
            require(allowed, "native GitHub write window cannot admit the bounded publication")
        for name in missing:
            with native.lease(mutation=True):
                validate_plan(plan, now=int(time.time()))
                require(native.local_source() == (plan["main_commit"], plan["main_tree"]),
                        "local main source changed")
                live = native.remote(plan["release_id"], plan["tag"])
                verify_remote_identity(plan, **live)
                require(live["release"]["draft"] is True, "release was published during upload")
                current = native.asset_rows(plan)
                require(current == [{key: row[key] for key in ("id", "name", "bytes")}
                                    for row in verified], "remote asset identities changed")
                receipt["attempted"].append({"operation": "upload", "name": name})
                native.store(receipt_path, receipt)
                endpoint = (f"https://uploads.github.com/{API}/releases/{plan['release_id']}"
                            f"/assets?name={quote(name, safe='')}")
                row = native.mutate(plan, ["api", endpoint, "--method", "POST", "--include", "--input", "-",
                                          "-H", "Content-Type: application/octet-stream",
                                          "-H", f"Content-Length: {len(payloads[name])}"], content=payloads[name])
                require(isinstance(row, dict) and row.get("name") == name
                        and row.get("size") == len(payloads[name]) and type(row.get("id")) is int
                        and row["id"] > 0, "upload acknowledgement is not the planned asset")
            digest = native.download(row["id"], len(payloads[name]))
            require(digest == plan["assets"][name]["sha256"], "uploaded bytes failed SHA256 readback")
            verified.append({"id": row["id"], "name": name, "bytes": len(payloads[name]), "sha256": digest})
            verified.sort(key=lambda item: item["name"])
            missing_assets(plan, verified)
            receipt["confirmed"].append({"operation": "upload", "name": name, "id": row["id"],
                                          "sha256": digest})
            with native.lease():
                native.store(receipt_path, receipt)
        require(not missing_assets(plan, verified), "release assets remain incomplete")
        # Matching published reconciliation consumes no mutation admission or write window.
        with native.lease(mutation=state["release"]["draft"]):
            validate_plan(plan, now=int(time.time()))
            require(native.local_source() == (plan["main_commit"], plan["main_tree"]),
                    "local main source changed before publication")
            live = native.remote(plan["release_id"], plan["tag"])
            verify_remote_identity(plan, **live)
            require(native.asset_rows(plan) == [{key: row[key] for key in ("id", "name", "bytes")}
                                               for row in verified], "verified asset identities changed")
            if live["release"]["draft"]:
                require(state["release"]["draft"], "published release unexpectedly became a draft")
                receipt["attempted"].append({"operation": "publish"})
                receipt["published"] = None  # Unknown until authenticated readback, never assumed false.
                native.store(receipt_path, receipt)
                native.mutate(plan, ["api", f"{API}/releases/{plan['release_id']}", "--method", "PATCH",
                                     "--include", "-F", "draft=false", "-f", "make_latest=true"])
        # A successful PATCH alone never establishes publication or asset integrity.
        final = native.remote(plan["release_id"], plan["tag"])
        verify_remote_identity(plan, **final)
        receipt["published"] = not final["release"]["draft"]
        with native.lease():
            native.store(receipt_path, receipt)
        require(receipt["published"] is True, "remote release is not published")
        final_assets = native.verified_assets(plan)
        require(not missing_assets(plan, final_assets), "published assets are incomplete")
        latest = native.get(f"{API}/releases/latest")
        require(latest.get("id") == plan["release_id"], "published release is not the latest release")
        receipt.update(verified=True, assets=final_assets,
                       release_url=f"https://github.com/{REPOSITORY}/releases/tag/{plan['tag']}")
    except Exception as error:
        # Never serialize exception arguments: transports can contain signed URLs or credentials.
        receipt["failure_type"] = type(error).__name__
        with native.lease():
            native.store(receipt_path, receipt)
        raise
    with native.lease():
        native.store(receipt_path, receipt)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("plan", "apply"):
        sub = commands.add_parser(command)
        sub.add_argument("--vault-config", type=Path, required=True)
        sub.add_argument("--assets", type=Path, required=True)
        if command == "plan":
            sub.add_argument("--release-id", type=int, required=True)
            sub.add_argument("--out", type=Path, required=True)
        else:
            sub.add_argument("--plan", type=Path, required=True)
            sub.add_argument("--confirmation", required=True)
            sub.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    try:
        assets = operational_path(args.assets)
        output = operational_path(args.out if args.command == "plan" else args.receipt)
        # Reject mismatched/expired confirmation before resolving credentials or making requests.
        plan = read_plan(args.plan) if args.command == "apply" else None
        if plan is not None:
            require(args.confirmation == confirmation_phrase(plan), "exact publication confirmation required")
        native = Native(args.vault_config)
        version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
        if args.command == "plan":
            native.plans.require_enabled(native.cfg, "release")
            require(args.release_id > 0, "release id must be positive")
            commit, tree = native.local_source()
            state = native.remote(args.release_id, f"v{version}")
            plan = create_plan(assets, version=version, actor=native.actor, main_commit=commit,
                               main_tree=tree, release=state["release"], now=int(time.time()),
                               ttl_seconds=3600)
            verify_remote_identity(plan, **state)
            missing_assets(plan, native.verified_assets(plan))
            with native.lease():
                native.store(output, plan, new=True)
            print(json.dumps({"plan_id": plan["plan_id"], "confirmation": confirmation_phrase(plan),
                              "expires_at": plan["expires_at"], "assets": plan["assets"]}, sort_keys=True))
        else:
            require(plan["version"] == version, "plan version differs from package authority")
            receipt = apply(native, plan, assets, output)
            print(json.dumps({key: receipt[key] for key in ("published", "verified", "release_url")},
                             sort_keys=True))
        return 0
    except Exception as error:  # noqa: BLE001 - native errors must never dump credential-bearing arguments
        message = str(error) if isinstance(error, PublicationError) else type(error).__name__
        print(json.dumps({"ok": False, "error_type": type(error).__name__, "detail": message}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
