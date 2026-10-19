# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Temporary PR 852 diagnostic; also an external plugin for the unchanged tests.

Prepare runs before isolation. Run requires a Linux network namespace containing
only loopback. Each source snapshot gets a fresh pytest process in the same locked
environment. Original timing assertions stay active; failures remain failures.
"""

from __future__ import annotations

import argparse
import ast
import cProfile
import dataclasses
import hashlib
import importlib
import importlib.metadata
import importlib.util
import io
import json
import math
import os
import platform
import pstats
import re
import resource
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
from pathlib import Path
from unittest.mock import patch

import coverage
import pytest

PUBLIC_SHA = "091a509b3d6ba8ff5be528966e1f43c2e68cf214"
CANDIDATE_SHA = "c18d97262f1503efb2c57632054a607298b56e24"
EXPECTED_UV = "0.10.12"
RUN_PLAN = (
    ("01-public", "public"),
    ("02-candidate", "candidate"),
    ("03-candidate", "candidate"),
    ("04-public", "public"),
)
# Fixed ABBA order. All four measured runs occur even after a failure; no retries.
CASE_TIMEOUT_SECONDS = 300
ADDED_TEST_FUNCTIONS = frozenset()
TEST_FILE = "tests/nodes/test_security_remediation.py"
TEST_NAME = "test_real_binary_structure_is_not_instruction_noise"
OUTPUT_FIELDS = ("risk_recommendation", "analysis_completeness", "findings", "inspection_ledger")
PROFILE_NODES = (
    "artifact_integrity",
    "static_patterns_prompt_injection",
    "static_patterns_privilege_escalation",
)
_ROWS: dict[str, dict] = {}
_ACTIVE_ITEM = None
_NETWORK_ATTEMPTS: list[str] = []
_COVERAGE_IDENTITY: dict = {}


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # A killed writer may leave its temporary file, but never a partial final JSON.
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=path.name + ".",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(json.dumps(value, indent=2, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def json_value(value):
    if dataclasses.is_dataclass(value):
        return json_value(dataclasses.asdict(value))
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return {str(key): json_value(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [json_value(item) for item in value]
    return value


def fingerprint(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def canonical_output(result: dict) -> dict:
    output = json_value({key: result.get(key) for key in OUTPUT_FIELDS})
    identifiers = {
        finding["finding_id"]: fingerprint(
            {key: value for key, value in finding.items() if key != "finding_id"}
        )
        for finding in output["findings"]
    }

    def replace(value):
        if isinstance(value, str):
            return identifiers.get(value, value)
        if isinstance(value, list):
            return [replace(item) for item in value]
        if isinstance(value, dict):
            return {key: replace(item) for key, item in value.items()}
        return value

    return replace(output)


def semantic_audit(result: dict, parameters: dict) -> dict[str, bool]:
    """Audit returned values even if pytest's earlier timing assertion fails.

    This is separate from, and does not replace, the assertions in TEST_NAME.
    """
    output = json_value(result)
    target = f"asset.{parameters['kind']}"
    if parameters["container"]:
        target = "assets.zip!/" + target
    complete = output["analysis_completeness"]
    referenced = parameters["referenced"]
    partial = [
        event
        for event in output["inspection_ledger"]
        if event.get("path") == target and event.get("outcome") == "partial"
    ]
    return {
        "no_incidental_instruction_rules": not {"AE4", "P2", "P9", "MP2", "TM1"}
        & {finding["rule_id"] for finding in output["findings"]},
        "expected_risk": output["risk_recommendation"] == ("CAUTION" if referenced else "SAFE"),
        "expected_completeness": complete["is_complete"] is (not referenced),
        "expected_partial_ledger": (
            any(event.get("reason_code") == "size_limit" for event in partial)
            if referenced
            else not partial
        ),
        "binary_scope_recorded": any(
            event["reason_code"] in {"binary_content", "binary_text_projection"}
            for event in complete["scope_exclusions"]
        ),
    }


def deny_network(*args, **kwargs):
    _NETWORK_ATTEMPTS.append("socket connection attempted")
    raise AssertionError("Network forbidden during parser timing diagnosis")


def coverage_identity(current) -> dict:
    tracer = current._collector.core.tracer_class
    result = {
        "version": coverage.__version__,
        "tracer": f"{tracer.__module__}.{tracer.__name__}",
        "branch": current.config.branch,
        "relative_files": current.config.relative_files,
        "source": current.config.source,
    }
    if (
        tracer.__name__ != "CTracer"
        or not result["branch"]
        or not result["relative_files"]
        or result["source"] != ["src/skillspector"]
    ):
        raise AssertionError(f"Expected CTracer with branch coverage: {result}")
    return result


@pytest.fixture(autouse=True)
def binary_diagnostic_no_network(monkeypatch):
    monkeypatch.setattr(socket.socket, "connect", deny_network)
    monkeypatch.setattr(socket.socket, "connect_ex", deny_network)
    monkeypatch.setattr(socket, "create_connection", deny_network)


def pytest_runtest_setup(item):
    global _ACTIVE_ITEM
    _ACTIVE_ITEM = item
    if _COVERAGE_IDENTITY:
        return
    _COVERAGE_IDENTITY.update(coverage_identity(coverage.Coverage.current()))
    from skillspector.graph import graph

    original = graph.invoke

    def invoke(*args, **kwargs):
        started = time.monotonic()
        cpu_started = time.process_time()
        result = original(*args, **kwargs)
        cpu_elapsed = time.process_time() - cpu_started
        elapsed = time.monotonic() - started
        parameters = dict(_ACTIVE_ITEM.callspec.params)
        _ROWS[_ACTIVE_ITEM.nodeid] = {
            "nodeid": _ACTIVE_ITEM.nodeid,
            "parameters": parameters,
            "graph_elapsed_seconds": elapsed,
            "graph_process_cpu_seconds": cpu_elapsed,
            "graph_cpu_to_wall_ratio": cpu_elapsed / elapsed if elapsed else None,
            "_raw_result": result,
        }
        return result

    graph.invoke = invoke


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    report = (yield).get_result()
    if report.when == "call" and item.nodeid in _ROWS:
        row = _ROWS[item.nodeid]
        # Hashing and semantic audits occur after the original timing assertion.
        result = row.pop("_raw_result")
        canonical = canonical_output(result)
        row.update(
            pytest_outcome=report.outcome,
            failure_text=str(report.longrepr) if report.failed else None,
            test_elapsed_seconds=report.duration,
            all_original_assertions_reached=report.passed,
            returned_output=json_value({key: result.get(key) for key in OUTPUT_FIELDS}),
            canonical_output=canonical,
            output_sha256=fingerprint(canonical),
            independent_semantic_audit=semantic_audit(result, row["parameters"]),
        )


def read_optional(path: Path) -> dict:
    try:
        return {"path": str(path), "text": path.read_text()}
    except (OSError, UnicodeError) as error:
        return {"path": str(path), "unavailable": type(error).__name__}


def cpu_identity() -> dict:
    """Raw Linux host/cgroup data; unavailable fields stay explicitly unavailable."""
    cpuinfo = read_optional(Path("/proc/cpuinfo"))
    model_keys = {
        "model name",
        "Hardware",
        "Processor",
        "vendor_id",
        "cpu family",
        "model",
        "stepping",
    }
    models = {}
    for line in cpuinfo.get("text", "").splitlines():
        key, separator, value = line.partition(":")
        if separator and key.strip() in model_keys:
            models.setdefault(key.strip(), set()).add(value.strip())
    cgroup = read_optional(Path("/proc/self/cgroup"))
    directories = {
        Path("/sys/fs/cgroup"),
        Path("/sys/fs/cgroup/cpu"),
        Path("/sys/fs/cgroup/cpu,cpuacct"),
    }
    for line in cgroup.get("text", "").splitlines():
        fields = line.split(":", 2)
        if len(fields) != 3:
            continue
        controllers, relative = fields[1], fields[2].lstrip("/")
        base = Path("/sys/fs/cgroup") / controllers if controllers else Path("/sys/fs/cgroup")
        leaf = base / relative
        # Preserve ancestor quota limits as well as the leaf's setting.
        if leaf.is_relative_to(base):
            directories.add(leaf)
            directories.update(parent for parent in leaf.parents if parent.is_relative_to(base))
    filenames = (
        "cpu.max",
        "cpu.stat",
        "cpu.pressure",
        "cpu.weight",
        "cpuset.cpus.effective",
        "cpu.cfs_quota_us",
        "cpu.cfs_period_us",
        "cpuacct.usage",
        "cpuset.cpus",
    )
    return {
        "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "processor": platform.processor(),
        "machine": platform.machine(),
        "cpu_count": os.cpu_count(),
        "affinity": sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None,
        "cpu_models": {key: sorted(value) for key, value in models.items()},
        "cpuinfo": cpuinfo,
        "self_cgroup": cgroup,
        "mountinfo": read_optional(Path("/proc/self/mountinfo")),
        "cgroup_settings": [
            read_optional(directory / name)
            for directory in sorted(directories)
            for name in filenames
        ],
        "proc_stat": read_optional(Path("/proc/stat")),
        "loadavg": read_optional(Path("/proc/loadavg")),
        "cpu_pressure": read_optional(Path("/proc/pressure/cpu")),
    }


def source_inventory(source: Path) -> dict[str, str]:
    return {
        str(path.relative_to(source)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(source.rglob("*"))
        if path.is_file()
        and "__pycache__" not in path.parts
        and path.suffix not in {".pyc", ".pyo"}
    }


def distribution_inventory() -> dict:
    """Hash actual installed files, including native libraries, after timed tests.

    Bytecode is excluded because it is runtime-generated; imports use disabled
    bytecode writes. The common editable project's distribution metadata is
    recorded, while snapshot source selection is checked independently.
    """
    result = {}
    for dist in importlib.metadata.distributions():
        name = re.sub(r"[-_.]+", "-", dist.metadata["Name"]).lower()
        files, missing = {}, []
        for entry in sorted(dist.files or [], key=str):
            path = Path(dist.locate_file(entry))
            if path.suffix in {".pyc", ".pyo"} or "__pycache__" in path.parts:
                continue
            if path.is_file():
                files[str(entry)] = hashlib.sha256(path.read_bytes()).hexdigest()
            else:
                missing.append(str(entry))
        result[name] = {
            "version": dist.version,
            "files": files,
            "files_sha256": fingerprint(files),
            "missing_recorded_files": missing,
            "has_recorded_files": bool(dist.files),
        }
    return result


def runtime_identity() -> dict:
    import skillspector

    source = Path(skillspector.__file__).resolve().parent
    distributions = distribution_inventory()
    origins = {
        name: str(Path(module.__file__).resolve())
        for name, module in list(sys.modules.items())
        if (name == "skillspector" or name.startswith("skillspector."))
        and getattr(module, "__file__", None)
    }
    return {
        "python": sys.version,
        "executable": sys.executable,
        "executable_sha256": hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
        "platform": platform.platform(),
        "cpu": cpu_identity(),
        "source_package": str(source),
        "source_files": source_inventory(source),
        "loaded_source_modules": origins,
        "all_loaded_source_inside_snapshot": all(
            Path(origin).is_relative_to(source) for origin in origins.values()
        ),
        "distribution_version": skillspector.__version__,
        "distributions": {name: value["version"] for name, value in distributions.items()},
        "installed_distribution_files": distributions,
        "installed_distribution_files_sha256": fingerprint(distributions),
    }


def pytest_sessionfinish(session, exitstatus):
    output = os.environ.get("BINARY_TIMING_OUTPUT")
    if not output:
        return
    valid = (
        len(_ROWS) == 6
        and not _NETWORK_ATTEMPTS
        and all(all(row["independent_semantic_audit"].values()) for row in _ROWS.values())
    )
    if not valid:
        session.exitstatus = 1
    write_json(
        Path(output) / "outcomes.json",
        {
            "pytest_exit_status": int(exitstatus),
            "final_exit_status": int(session.exitstatus),
            "diagnostic_valid": valid,
            "network_attempts": _NETWORK_ATTEMPTS,
            "coverage": _COVERAGE_IDENTITY,
            "runtime": runtime_identity(),
            "cases": list(_ROWS.values()),
        },
    )


def test_contract(root: Path) -> dict:
    source = (root / TEST_FILE).read_text()
    lines = source.splitlines(keepends=True)
    module = ast.parse(source)
    functions = {}
    for node in module.body:
        if isinstance(node, ast.FunctionDef) and node.name in {
            TEST_NAME,
            "_compressed_binary_image",
        }:
            first = min([node.lineno] + [item.lineno for item in node.decorator_list])
            raw = "".join(lines[first - 1 : node.end_lineno])
            functions[node.name] = {
                "sha256": hashlib.sha256(raw.encode()).hexdigest(),
                "source": raw,
            }
    if set(functions) != {TEST_NAME, "_compressed_binary_image"}:
        raise AssertionError("Original test and binary fixture helper required")
    original_nodes = [
        node
        for node in module.body
        if not isinstance(node, ast.FunctionDef) or node.name not in ADDED_TEST_FUNCTIONS
    ]
    normalized = ast.dump(
        ast.Module(body=original_nodes, type_ignores=[]), include_attributes=False
    )
    return {
        "original_functions": functions,
        "original_module_ast_sha256": hashlib.sha256(normalized.encode()).hexdigest(),
        "added_functions": sorted(
            node.name
            for node in module.body
            if isinstance(node, ast.FunctionDef) and node.name in ADDED_TEST_FUNCTIONS
        ),
        "conftest_sha256": hashlib.sha256((root / "tests/conftest.py").read_bytes()).hexdigest(),
    }


def prepare(repository: Path, candidate: str, output: Path) -> None:
    if candidate != CANDIDATE_SHA:
        raise ValueError(
            "This prepared artifact is pinned to exact c18d972; never use an event head"
        )
    if output.exists():
        raise ValueError("Output must be a new directory to prevent stale evidence")
    uv_path = shutil.which("uv")
    if not uv_path:
        raise AssertionError("uv identity is required during preparation")
    uv_version = subprocess.check_output([uv_path, "--version"], text=True).strip()
    if not uv_version.startswith("uv " + EXPECTED_UV + " ") and uv_version != "uv " + EXPECTED_UV:
        raise AssertionError(f"Expected observed uv {EXPECTED_UV}: {uv_version}")
    output.mkdir(parents=True)
    identity = {
        "public": PUBLIC_SHA,
        "candidate": candidate,
        "declared_run_plan": RUN_PLAN,
        "uv": {
            "version": uv_version,
            "path": uv_path,
            "binary_sha256": hashlib.sha256(Path(uv_path).read_bytes()).hexdigest(),
        },
        "diagnostic_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "runner_image_environment": {
            key: os.environ.get(key)
            for key in ("ImageOS", "ImageVersion", "RUNNER_OS", "RUNNER_ARCH")
        },
        "preparation_cpu": cpu_identity(),
        "snapshots": {},
    }
    for label, sha in (("public", PUBLIC_SHA), ("candidate", candidate)):
        resolved = subprocess.check_output(
            ["git", "rev-parse", "--verify", f"{sha}^{{commit}}"], cwd=repository, text=True
        ).strip()
        if resolved != sha:
            raise ValueError("Source identity mismatch")
        archive = subprocess.check_output(["git", "archive", sha], cwd=repository)
        root = output / "snapshots" / label
        root.mkdir(parents=True)
        with tarfile.open(fileobj=io.BytesIO(archive)) as bundle:
            bundle.extractall(root, filter="data")
        identity["snapshots"][label] = {
            "sha": sha,
            "tree": subprocess.check_output(
                ["git", "rev-parse", f"{sha}^{{tree}}"], cwd=repository, text=True
            ).strip(),
            "archive_sha256": hashlib.sha256(archive).hexdigest(),
            "test_sha256": hashlib.sha256((root / TEST_FILE).read_bytes()).hexdigest(),
            "lock_sha256": hashlib.sha256((root / "uv.lock").read_bytes()).hexdigest(),
            "nonproject_lock_packages_sha256": fingerprint(
                [
                    package
                    for package in tomllib.loads((root / "uv.lock").read_text())["package"]
                    if package["name"] != "skillspector"
                ]
            ),
            "test_and_coverage_config": {
                key: tomllib.loads((root / "pyproject.toml").read_text())["tool"].get(key)
                for key in ("pytest", "coverage")
            },
            "source_inventory": source_inventory(root / "src/skillspector"),
            "test_contract": test_contract(root),
        }
    for field in ("test_sha256", "nonproject_lock_packages_sha256", "test_and_coverage_config"):
        if identity["snapshots"]["public"][field] != identity["snapshots"]["candidate"][field]:
            raise AssertionError(f"Shared dependency/test configuration changed: {field}")
    public = identity["snapshots"]["public"]["test_contract"]
    target = identity["snapshots"]["candidate"]["test_contract"]
    for field in ("original_functions", "original_module_ast_sha256", "conftest_sha256"):
        if public[field] != target[field]:
            raise AssertionError(
                f"Existing binary tests/fixtures or original module changed: {field}"
            )
    if public["added_functions"] or set(target["added_functions"]) != ADDED_TEST_FUNCTIONS:
        raise AssertionError("No test functions may be excluded for the c18 source comparison")
    write_json(output / "identity.json", identity)


def isolated_environment(root: Path, destination: Path) -> dict[str, str]:
    return {
        "PATH": str(Path(sys.executable).parent) + os.pathsep + "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "PYTHONPATH": str(Path(__file__).resolve().parent) + os.pathsep + str(root / "src"),
        "PYTHONDONTWRITEBYTECODE": "1",
        "COVERAGE_FILE": str(destination / ".coverage"),
        "BINARY_TIMING_OUTPUT": str(destination),
    }


def run_process_group(command, *, cwd, env, stdout, stderr, timeout, check=False):
    """Run one isolated POSIX process group; kill the group before timeout returns.

    communicate() drains pipes if a caller uses PIPE; diagnostic calls use log
    files. The leader is always waited/reaped after SIGKILL. Children that keep
    this process group are killed too; kernel reparenting handles their reaping.
    """
    process = subprocess.Popen(
        command, cwd=cwd, env=env, stdout=stdout, stderr=stderr, start_new_session=True
    )
    try:
        captured_stdout, captured_stderr = process.communicate(timeout=timeout)
    except BaseException:
        # TimeoutExpired, cancellation, or interruption must not leave graph
        # worker subprocesses running into later ABBA blocks.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        finally:
            process.communicate()
        raise
    result = subprocess.CompletedProcess(
        command, process.returncode, captured_stdout, captured_stderr
    )
    if check:
        result.check_returncode()
    return result


def validate_outcomes(value: object) -> dict:
    """Reject partial/wrong-shaped evidence before aggregate code indexes it."""

    def fields(record, expected, location):
        if not isinstance(record, dict):
            raise ValueError(f"{location} must be an object")
        for name, kind in expected.items():
            if (
                name not in record
                or not isinstance(record[name], kind)
                or (kind is int and isinstance(record[name], bool))
            ):
                raise ValueError(f"{location}.{name} is missing or has the wrong type")

    fields(
        value,
        {
            "diagnostic_valid": bool,
            "pytest_exit_status": int,
            "final_exit_status": int,
            "network_attempts": list,
            "coverage": dict,
            "runtime": dict,
            "cases": list,
        },
        "outcomes",
    )
    runtime = value["runtime"]
    fields(
        runtime,
        {
            "source_package": str,
            "source_files": dict,
            "all_loaded_source_inside_snapshot": bool,
            "distributions": dict,
            "installed_distribution_files_sha256": str,
        },
        "outcomes.runtime",
    )
    for name in ("source_files", "distributions"):
        if not all(
            isinstance(key, str) and isinstance(item, str) for key, item in runtime[name].items()
        ):
            raise ValueError(f"outcomes.runtime.{name} must map strings to strings")
    if not re.fullmatch(r"[0-9a-f]{64}", runtime["installed_distribution_files_sha256"]):
        raise ValueError("Missing or invalid installed-file fingerprint")
    coverage_state = value["coverage"]
    fields(
        coverage_state,
        {"version": str, "tracer": str, "branch": bool, "relative_files": bool, "source": list},
        "outcomes.coverage",
    )
    if (
        not coverage_state["tracer"].endswith(".CTracer")
        or not coverage_state["branch"]
        or not coverage_state["relative_files"]
        or coverage_state["source"] != ["src/skillspector"]
    ):
        raise ValueError("Coverage identity does not match the diagnostic contract")
    expected_ids = {
        f"{TEST_FILE}::{TEST_NAME}[{referenced}-{container}-{kind}]"
        for referenced, container in ((False, False), (True, False), (False, True))
        for kind in ("pdf", "gif")
    }
    seen = set()
    for index, row in enumerate(value["cases"]):
        fields(
            row,
            {
                "nodeid": str,
                "canonical_output": dict,
                "returned_output": dict,
                "parameters": dict,
                "output_sha256": str,
                "all_original_assertions_reached": bool,
                "test_elapsed_seconds": (int, float),
                "failure_text": (str, type(None)),
                "graph_elapsed_seconds": (int, float),
                "graph_process_cpu_seconds": (int, float),
                "pytest_outcome": str,
                "independent_semantic_audit": dict,
            },
            f"cases[{index}]",
        )
        if row["nodeid"] in seen:
            raise ValueError("Duplicate case identity")
        seen.add(row["nodeid"])
        for name in ("graph_elapsed_seconds", "graph_process_cpu_seconds", "test_elapsed_seconds"):
            if isinstance(row[name], bool) or not math.isfinite(row[name]) or row[name] < 0:
                raise ValueError(f"cases[{index}].{name} must be finite and nonnegative")
        fields(
            row["canonical_output"],
            {
                "risk_recommendation": str,
                "analysis_completeness": dict,
                "findings": list,
                "inspection_ledger": list,
            },
            f"cases[{index}].canonical_output",
        )
        fields(
            row["canonical_output"]["analysis_completeness"],
            {"is_complete": bool},
            f"cases[{index}].canonical_output.analysis_completeness",
        )
        fields(
            row["returned_output"],
            {
                "risk_recommendation": str,
                "analysis_completeness": dict,
                "findings": list,
                "inspection_ledger": list,
            },
            f"cases[{index}].returned_output",
        )
        fields(
            row["parameters"],
            {"kind": str, "referenced": bool, "container": bool},
            f"cases[{index}].parameters",
        )
        parameters = row["parameters"]
        expected_id = (
            f"{TEST_FILE}::{TEST_NAME}[{parameters['referenced']}-"
            f"{parameters['container']}-{parameters['kind']}]"
        )
        if row["nodeid"] != expected_id:
            raise ValueError("Case parameters do not match its identity")
        if row["output_sha256"] != fingerprint(row["canonical_output"]):
            raise ValueError("Canonical output fingerprint mismatch")
        if row["pytest_outcome"] not in {"passed", "failed", "skipped"}:
            raise ValueError("Invalid pytest outcome")
        if row["all_original_assertions_reached"] != (row["pytest_outcome"] == "passed"):
            raise ValueError("Original assertion status is inconsistent")
        audit = row["independent_semantic_audit"]
        audit_keys = {
            "no_incidental_instruction_rules",
            "expected_risk",
            "expected_completeness",
            "expected_partial_ledger",
            "binary_scope_recorded",
        }
        if set(audit) != audit_keys or not all(isinstance(item, bool) for item in audit.values()):
            raise ValueError("Independent semantic audit is incomplete")
        if value["diagnostic_valid"] and not all(audit.values()):
            raise ValueError("Diagnostic validity contradicts a failed semantic audit")
    if len(value["cases"]) != 6 or seen != expected_ids:
        raise ValueError("All six original PDF/GIF case identities are required")
    if value["diagnostic_valid"] and value["network_attempts"]:
        raise ValueError("Diagnostic validity contradicts network attempts")
    return value


def read_outcomes(path: Path) -> tuple[dict | None, dict | None]:
    """Keep invalid raw evidence untouched; return an error instead of aborting ABBA."""
    evidence = {"path": str(path)}
    try:
        raw = path.read_bytes()
    except OSError as error:
        evidence.update(
            kind="missing" if isinstance(error, FileNotFoundError) else "read_error",
            detail=f"{type(error).__name__}: {error}",
        )
        return None, evidence
    evidence.update(size_bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError, RecursionError) as error:
        evidence.update(kind="malformed_json", detail=f"{type(error).__name__}: {error}")
        return None, evidence
    try:
        return validate_outcomes(value), None
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError) as error:
        evidence.update(kind="invalid_schema", detail=f"{type(error).__name__}: {error}")
        return None, evidence


def run(output: Path, include_profile: bool) -> int:
    if sys.version_info[:3] != (3, 12, 3) or sys.platform != "linux":
        raise AssertionError("Use the exact Linux CPython 3.12.3 diagnostic runtime")
    interfaces = socket.if_nameindex()
    if any(name != "lo" for _, name in interfaces):
        raise AssertionError(f"Run in an isolated network namespace; found {interfaces}")
    identity = json.loads((output / "identity.json").read_text())
    if identity["public"] != PUBLIC_SHA or identity["candidate"] != CANDIDATE_SHA:
        raise AssertionError("Prepared source identity differs from the pinned comparison")
    if (
        identity["diagnostic_script_sha256"]
        != hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    ):
        raise AssertionError("Diagnostic changed after preparation")
    results = output / "results"
    results.mkdir()  # Fail closed on stale/reused results.
    summaries = {}
    failed = False
    dependency_fingerprints = set()
    for run_id, label in RUN_PLAN:
        root = output / "snapshots" / label
        destination = results / run_id
        destination.mkdir()
        if (
            hashlib.sha256((root / TEST_FILE).read_bytes()).hexdigest()
            != identity["snapshots"][label]["test_sha256"]
            or test_contract(root) != identity["snapshots"][label]["test_contract"]
        ):
            raise AssertionError("Test assertions or fixtures changed after preparation")
        command = [
            sys.executable,
            "-m",
            "pytest",
            "-v",
            "-p",
            "no:cacheprovider",
            "-p",
            Path(__file__).stem,
            "--cov=src/skillspector",
            "--cov-report=term-missing",
            f"--cov-report=xml:{destination / 'coverage.xml'}",
            f"--cov-report=json:{destination / 'coverage.json'}",
            f"--junitxml={destination / 'junit.xml'}",
            "--durations=10",
            f"{TEST_FILE}::{TEST_NAME}",
            "-k",
            "pdf or gif",
        ]
        before_cpu = cpu_identity()
        before_usage = resource.getrusage(resource.RUSAGE_CHILDREN)
        started = time.monotonic()
        timed_out = False
        with (destination / "pytest.log").open("w", encoding="utf-8") as log:
            try:
                process = run_process_group(
                    command,
                    cwd=root,
                    env=isolated_environment(root, destination),
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    timeout=CASE_TIMEOUT_SECONDS,
                    check=False,
                )
                exit_code = process.returncode
            except subprocess.TimeoutExpired:
                timed_out = True
                exit_code = 124
                log.write(
                    "\nDiagnostic child exceeded fixed 300-second process bound; failure retained.\n"
                )
        elapsed = time.monotonic() - started
        after_usage = resource.getrusage(resource.RUSAGE_CHILDREN)
        row = {
            "source": label,
            "command": command,
            "exit_code": exit_code,
            "timed_out": timed_out,
            "elapsed_seconds": elapsed,
            "child_user_cpu_seconds": after_usage.ru_utime - before_usage.ru_utime,
            "child_system_cpu_seconds": after_usage.ru_stime - before_usage.ru_stime,
            "cpu_before": before_cpu,
            "cpu_after": cpu_identity(),
        }
        summaries[run_id] = row
        failed |= exit_code != 0
        outcomes_path = destination / "outcomes.json"
        outcomes, outcome_error = read_outcomes(outcomes_path)
        if outcome_error is not None:
            failed = True
            row["outcomes_error"] = outcome_error
            row["missing_outcomes"] = outcome_error["kind"] == "missing"
        else:
            row["outcomes"] = outcomes
            failed |= not outcomes["diagnostic_valid"]
            source = (root / "src" / "skillspector").resolve()
            expected_files = identity["snapshots"][label]["source_inventory"]
            source_matches = (
                outcomes["runtime"]["source_package"] == str(source)
                and outcomes["runtime"]["source_files"] == expected_files
                and source_inventory(source) == expected_files
                and outcomes["runtime"]["all_loaded_source_inside_snapshot"]
            )
            row["source_matches_snapshot"] = source_matches
            failed |= not source_matches
            locked = tomllib.loads((root / "uv.lock").read_text())["package"]
            allowed = {}
            for package in locked:
                allowed.setdefault(re.sub(r"[-_.]+", "-", package["name"]).lower(), set()).add(
                    package["version"]
                )
            mismatches = {
                name: version
                for name, version in outcomes["runtime"]["distributions"].items()
                if name != "skillspector" and version not in allowed.get(name, set())
            }
            row["dependency_mismatches"] = mismatches
            failed |= bool(mismatches)
            row["evidence_valid"] = bool(
                outcomes["diagnostic_valid"] and source_matches and not mismatches
            )
            if row["evidence_valid"]:
                dependency_fingerprints.add(
                    outcomes["runtime"]["installed_distribution_files_sha256"]
                )
        # Persist every run immediately; a later interruption cannot erase prior failures.
        write_json(destination / "run.json", row)
    comparisons = []
    reference_row = summaries.get("01-public", {})
    reference = reference_row.get("outcomes") if reference_row.get("evidence_valid") else None
    if reference is None:
        failed = True
    else:
        public = {item["nodeid"]: item for item in reference["cases"]}
        for run_id, label in RUN_PLAN[1:]:
            evidence_row = summaries[run_id]
            outcomes = evidence_row.get("outcomes") if evidence_row.get("evidence_valid") else None
            if outcomes is None:
                failed = True
                continue
            observed = {item["nodeid"]: item for item in outcomes["cases"]}
            failed |= public.keys() != observed.keys() or len(public) != 6
            for nodeid in sorted(public.keys() & observed.keys()):
                equal = public[nodeid]["canonical_output"] == observed[nodeid]["canonical_output"]
                comparisons.append(
                    {
                        "reference_run": "01-public",
                        "observed_run": run_id,
                        "source": label,
                        "nodeid": nodeid,
                        "outputs_equal": equal,
                        "reference_graph_seconds": public[nodeid]["graph_elapsed_seconds"],
                        "observed_graph_seconds": observed[nodeid]["graph_elapsed_seconds"],
                        "reference_graph_cpu_seconds": public[nodeid]["graph_process_cpu_seconds"],
                        "observed_graph_cpu_seconds": observed[nodeid]["graph_process_cpu_seconds"],
                    }
                )
                failed |= not equal
    dependencies_identical = len(dependency_fingerprints) == 1 and all(
        row.get("evidence_valid", False) for row in summaries.values()
    )
    failed |= not dependencies_identical
    if include_profile:
        # Optional attribution remains outside the predetermined measured sequence.
        root = output / "snapshots" / "candidate"
        destination = results / "serial-profile"
        destination.mkdir()
        with (destination / "profile.log").open("w", encoding="utf-8") as log:
            try:
                process = run_process_group(
                    [
                        sys.executable,
                        "-m",
                        "coverage",
                        "run",
                        "--branch",
                        "--source=src/skillspector",
                        str(Path(__file__).resolve()),
                        "profile",
                        "--output",
                        str(destination),
                    ],
                    cwd=root,
                    env=isolated_environment(root, destination),
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    timeout=120,
                    check=False,
                )
                profile_exit_code = process.returncode
            except subprocess.TimeoutExpired:
                profile_exit_code = 124
        summaries["serial_profile_exit_code"] = profile_exit_code
        failed |= profile_exit_code != 0
    write_json(
        results / "summary.json",
        {
            "identity": identity,
            "network_interfaces": interfaces,
            "declared_run_plan": RUN_PLAN,
            "runs": summaries,
            "comparisons": comparisons,
            "dependencies_identical": dependencies_identical,
            "failed": failed,
            "limits": "Fixed ABBA: four fresh processes, six unchanged cases each, no warmup/discard/retry. First process alone sees initial OS-cache state. Shared-host scheduling and cache effects remain. Does not reproduce preceding full-suite global state. CPU observations are process totals including graph worker threads, not exact core allocation. No timing threshold changed.",
        },
    )
    return int(failed)


def profile_serial(output: Path) -> None:
    """Direct synchronous node calls; no graph worker threads or nested profilers."""
    graph_module = importlib.import_module("skillspector.graph")
    spec = importlib.util.spec_from_file_location("binary_fixture", Path.cwd() / TEST_FILE)
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    rows = []
    with (
        tempfile.TemporaryDirectory(prefix="binary-profile-") as temporary,
        patch.object(socket.socket, "connect", deny_network),
        patch.object(socket.socket, "connect_ex", deny_network),
        patch.object(socket, "create_connection", deny_network),
        patch("skillspector.model_info._resolve_context_length", return_value=131072),
    ):
        root = Path(temporary)
        (root / "SKILL.md").write_text("---\nname: ordinary-assets\n---\nA helper.\n")
        (root / "asset.pdf").write_bytes(fixture._compressed_binary_image("pdf"))
        state = {"skill_path": temporary, "use_llm": False}
        state.update(graph_module.resolve_input(state))
        state.update(graph_module.build_context(state))
        for name in PROFILE_NODES:
            profiler = cProfile.Profile()
            started = time.monotonic()
            profiler.enable()
            try:
                result = graph_module.ANALYZER_NODES[name](state)
            finally:
                profiler.disable()
            elapsed = time.monotonic() - started
            if result.get("findings"):
                raise AssertionError(f"Unexpected finding from {name}: {result['findings']}")
            profiler.dump_stats(str(output / f"{name}.pstats"))
            report = io.StringIO()
            pstats.Stats(profiler, stream=report).sort_stats("cumulative").print_stats(60)
            (output / f"{name}.txt").write_text(report.getvalue())
            rows.append({"node": name, "elapsed_seconds": elapsed})
    if _NETWORK_ATTEMPTS:
        raise AssertionError("Profile attempted network access")
    write_json(
        output / "summary.json",
        {
            "purpose": "Serial direct-node attribution; scheduling differs from graph, not a timing assertion",
            "coverage": coverage_identity(coverage.Coverage.current()),
            "nodes": rows,
        },
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "run", "profile"))
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--candidate")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile", action="store_true")
    args = parser.parse_args()
    if args.mode == "prepare" and args.candidate is None:
        parser.error("prepare requires --candidate")
    output = args.output.resolve()
    if args.mode == "prepare":
        prepare(args.repository.resolve(), args.candidate, output)
    elif args.mode == "run":
        return run(output, args.profile)
    else:
        profile_serial(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
