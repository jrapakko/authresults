# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""Case-table run guards (PLAN.md 6.2; AL2b acceptance, AL3a red-team F4).

- The pending hook lives in ``tests/_pending.py``; the one marked line below
  loads it. AL2b deletes that line and the file, and nothing else here.
- Permanent: a ``test_case`` item may carry no xfail marker except the
  pending one (``raises=Pending, strict=True, reason="AL2b"``) and only for
  an id the pending hook stashed under ``PENDING_KEY``; any xfailed
  ``test_case`` report outside that set fails the run. After AL2b the set
  is empty, so any xfail fails.
- Permanent: when the whole case table is requested (the default run, the
  ``tests`` directory, or ``tests/test_cases.py`` as a file), the collected
  ``test_case`` ids must equal the ``ALL_CASES`` ids, in order. A deselected
  or skipped ``test_case`` item fails the run in every case.

- Permanent: the run is refused when ``PYTEST_ADDOPTS`` or
  ``PYTEST_PLUGINS`` is set, when assertions are not rewritten, or when the
  timeout plugin is missing (AL3a round 3, N1).

``tests/test_case_table_meta.py`` checks this file's shape and pins its
post-AL2b form by hash, so it cannot patch the case-table helpers unnoticed.
"""

import os
from pathlib import Path

import pytest

from ._case import PENDING_KEY, Pending
from .test_cases import ALL_CASES

# --- AL2b: delete from here to the end marker and the blank line after it ---
# isort: split
from ._pending import pytest_collection_modifyitems  # noqa: F401 - a hook

# --- end of the AL2b deletion ------------------------------------------------

_TESTS = Path(__file__).resolve().parent
_TABLE = _TESTS / "test_cases.py"
_FUNCTION = "test_case"
_FAULTS: list[str] = []  # deselected, skipped or wrongly xfailed test_case items
_PENDING: set[str] = set()  # the ids the pending hook marked, this run
_PENDING_MARK = {"raises": Pending, "strict": True, "reason": "AL2b"}


def _is_case_item(item: pytest.Item) -> bool:
    return isinstance(item, pytest.Function) and item.originalname == _FUNCTION


def _whole_table_requested(config: pytest.Config) -> bool:
    base = config.invocation_params.dir
    for arg in config.args:
        if "::" in arg:
            continue
        target = (base / arg).resolve()
        if target == _TABLE or _TESTS.is_relative_to(target):
            return True
    return False


def _case_id(nodeid: str) -> str:
    return nodeid.rsplit("::", 1)[-1].removeprefix(_FUNCTION + "[").removesuffix("]")


def _xfail_fault(item: pytest.Function) -> str | None:
    marks = list(item.iter_markers("xfail"))
    if not marks:
        return None
    allowed = (
        len(marks) == 1
        and not marks[0].args
        and marks[0].kwargs == _PENDING_MARK
        and item.callspec.id in _PENDING
    )
    return None if allowed else f"xfail not from the pending hook: {item.nodeid}"


def pytest_configure(config: pytest.Config) -> None:
    for name in ("PYTEST_ADDOPTS", "PYTEST_PLUGINS"):
        if os.environ.get(name):
            msg = f"refused: {name} is set (the case table runs with fixed options)"
            raise pytest.UsageError(msg)
    if config.getoption("assertmode") != "rewrite":
        msg = "refused: the case table needs assertion rewriting (--assert=rewrite)"
        raise pytest.UsageError(msg)
    manager = config.pluginmanager
    if not (manager.hasplugin("timeout") or manager.hasplugin("pytest_timeout")):
        msg = "refused: the timeout plugin (pytest-timeout) is not loaded"
        raise pytest.UsageError(msg)


def pytest_deselected(items: list[pytest.Item]) -> None:
    _FAULTS.extend(f"deselected: {i.nodeid}" for i in items if _is_case_item(i))


def pytest_collection_finish(session: pytest.Session) -> None:
    pending: frozenset[str] = session.config.stash.get(PENDING_KEY, frozenset())
    _PENDING.update(pending)
    for item in session.items:
        if isinstance(item, pytest.Function) and _is_case_item(item):
            fault = _xfail_fault(item)
            if fault is not None:
                _FAULTS.append(fault)
    if _FAULTS:
        raise pytest.UsageError("; ".join(_FAULTS))
    if not _whole_table_requested(session.config):
        return
    collected = [
        item.callspec.id
        for item in session.items
        if isinstance(item, pytest.Function) and _is_case_item(item)
    ]
    if collected != [case.id for case in ALL_CASES]:
        msg = "collected test_case ids differ from the ALL_CASES ids"
        raise pytest.UsageError(msg)


def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[None]) -> None:
    if not (isinstance(item, pytest.Function) and _is_case_item(item)):
        return
    # An imperative pytest.xfail() in any phase: a pending case xfails only
    # through its marker, on Pending.
    if call.excinfo is not None and call.excinfo.errisinstance(pytest.xfail.Exception):
        _FAULTS.append(f"imperative xfail: {item.nodeid}")
    # Re-checked at run time: a marker added after collection is caught too.
    if call.when == "call":
        fault = _xfail_fault(item)
        if fault is not None:
            _FAULTS.append(fault)


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    is_case = report.nodeid.split("::")[-1].startswith(_FUNCTION + "[")
    if not is_case:
        return
    if hasattr(report, "wasxfail"):
        if _case_id(report.nodeid) not in _PENDING:
            _FAULTS.append(f"xfailed outside PENDING_IDS: {report.nodeid}")
    elif report.skipped:
        _FAULTS.append(f"skipped: {report.nodeid}")


def pytest_sessionfinish(session: pytest.Session) -> None:
    if _FAULTS:
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


def pytest_terminal_summary(terminalreporter: pytest.TerminalReporter) -> None:
    for fault in _FAULTS:
        terminalreporter.write_line(f"case-table guard: {fault}", red=True)
