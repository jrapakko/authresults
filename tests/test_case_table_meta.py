# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""Checks on the case table itself (PLAN.md 6, AL3a acceptance)."""

import ast
import datetime as dt
import hashlib
import ipaddress
import re
from pathlib import Path
from typing import cast

import pytest

from authresults import (
    ArcAuthenticationResults,
    AuthenticationResults,
    AuthResultsError,
    Deviation,
    ErrorReason,
    Result,
)
from authresults._errors import InternalCause

from . import cases_rfc8601, cases_spike, cases_vendor
from ._case import ANY_POSITION, UNSET, Case, ar, fingerprint, prop, res
from .test_cases import ALL_CASES, is_stub_error

SPIKE_NAMES = (
    "google-like good",
    "header.d form",
    "upper case",
    "version 1",
    "version 2",
    "pass in comment",
    "nested comment",
    "arc comment carrying dmarc=pass",
    "x-dmarc",
    "dmarc=passed",
    "pass in quoted string",
    "quoted value with ; and =",
    "untrusted id",
    "from in other result",
    "lookalike from",
    "idna a-label",
    "idna u-label",
    "none",
    "nonexistent prefix",
    "reason=",
    "policy.*",
    "unknown ptype (microsoft style)",
    "empty",
    "only id",
    "garbled",
    "unclosed comment",
    "deep nesting",
    "folded",
)

# AU-Q16: these reasons carry no position (to_value errors never do).
_NO_POSITION = {
    ErrorReason.INVALID_TYPE,
    ErrorReason.EMPTY,
    ErrorReason.INTERNAL,
    ErrorReason.DUPLICATE_PROPERTY,
}

_TIMING_LENGTH = 8192  # PLAN.md 6, AL3a row: the default max_length

_ERROR_CASES = [c for c in ALL_CASES if isinstance(c.expected, ErrorReason)]


def _payload(case: Case) -> AuthenticationResults | None:
    if isinstance(case.expected, ArcAuthenticationResults):
        return case.expected.payload
    if isinstance(case.expected, AuthenticationResults) and case.call != "to_value":
        return case.expected
    return None


def test_ids_unique_and_plain() -> None:
    ids = [c.id for c in ALL_CASES]
    assert len(ids) == len(set(ids))
    for case_id in ids:
        assert case_id.isascii()
        assert case_id.isprintable()
        assert case_id == case_id.strip()
        assert "\\" not in case_id, case_id  # pytest would escape it


def test_every_reason_reached() -> None:
    reached = {c.expected for c in _ERROR_CASES}
    assert reached == set(ErrorReason) - {ErrorReason.INTERNAL}


@pytest.mark.parametrize("deviation", list(Deviation))
def test_every_deviation_lenient_and_strict(deviation: Deviation) -> None:
    lenient = [
        c
        for c in ALL_CASES
        if (p := _payload(c)) is not None and deviation in p.deviations
    ]
    strict = [
        c
        for c in ALL_CASES
        if c.expected is ErrorReason.DEVIATION and c.deviation is deviation
    ]
    assert lenient
    assert strict


def test_deviation_field_only_on_deviation_cases() -> None:
    for case in ALL_CASES:
        if case.expected is ErrorReason.DEVIATION:
            assert type(case.deviation) is Deviation, case.id
            assert case.kwargs.get("strict_syntax") is True, case.id
        else:
            assert case.deviation is None, case.id


def test_spike_names_exact() -> None:
    ids = [c.id for c in cases_spike.CASES]
    assert sorted(ids) == sorted((*SPIKE_NAMES, "deep nesting (within cap)"))


def test_every_case_cited() -> None:
    for case in ALL_CASES:
        assert case.cite.strip(), case.id


def test_rfc8601_cites() -> None:
    pattern = re.compile(
        r"IETF RFC 8601, (Appendix B\.[2-7]|Section 2\.7\.6)[^;]*"
        r" \(unmodified excerpt\)"
    )
    for case in cases_rfc8601.CASES:
        assert pattern.match(case.cite), case.id


def test_positions() -> None:
    for case in ALL_CASES:
        if not isinstance(case.expected, ErrorReason):
            assert case.position is UNSET, case.id
        elif case.position is ANY_POSITION:
            continue
        elif case.expected in _NO_POSITION or case.call == "to_value":
            assert case.position is None, case.id
        else:
            assert type(case.position) is int, case.id
            assert case.position >= 0, case.id
            if isinstance(case.value, str):
                # str.__len__: a case value may be a str subclass that lies.
                assert case.position <= str.__len__(case.value), case.id


def test_call_shapes() -> None:
    for case in ALL_CASES:
        expected = case.expected
        if case.call == "to_value":
            assert isinstance(case.value, AuthenticationResults), case.id
            assert set(case.kwargs) <= {"ascii_only"}, case.id
            assert isinstance(expected, (str, ErrorReason)), case.id
        elif case.call == "get_unique":
            assert case.lookup is not None, case.id
        else:
            assert case.lookup is None, case.id
        if case.call == "parse" and not isinstance(expected, ErrorReason):
            assert type(expected) is AuthenticationResults, case.id
        if case.call == "parse_arc" and not isinstance(expected, ErrorReason):
            assert type(expected) is ArcAuthenticationResults, case.id
        if case.call in {"domain_of", "ascii_domain"}:
            assert expected is None or isinstance(expected, (str, ErrorReason))


def test_timing_cases() -> None:
    timed = [c for c in ALL_CASES if c.timeout is not None]
    for case in timed:
        assert isinstance(case.value, str)
        assert len(case.value) >= _TIMING_LENGTH, case.id
    values = {c.value for c in timed}
    assert values >= {char * _TIMING_LENGTH for char in '(";'}


# Vendor provenance and rewriting (PLAN.md 4, AU-Q19).

_DOC_V4 = [
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
]
_DOC_V6 = ipaddress.ip_network("2001:db8::/32")
_RESERVED = (
    "example",
    "test",
    "invalid",
    "localhost",
    "example.com",
    "example.net",
    "example.org",
)
_DOTTED = re.compile(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
_V6 = re.compile(r"[0-9A-Fa-f]*:[0-9A-Fa-f:]*:[0-9A-Fa-f]*")
# A local-part before @ (atext without "=", so smtp.mailfrom=x@ yields x).
_LOCAL = re.compile(
    r"(?<![A-Za-z0-9.!#$%&'*+/?^_`{|}~-])([A-Za-z0-9.!#$%&'*+/?^_`{|}~-]*)@"
)
_PTYPES = frozenset({"header", "smtp", "body", "policy", "dns"})
_LOCAL_PARTS = frozenset({"", "sender", "bounces"})
_QUOTED_LOCAL = re.compile(r'"((?:[^"\\]|\\.)*)"@')
_QUOTED_LOCAL_PARTS: frozenset[str] = frozenset()  # none in the vendor shapes
_SINGLE_AFTER_AT = re.compile(r"@([A-Za-z0-9-]+)(?![A-Za-z0-9.-])")
_SINGLE_LABEL_NAMES = frozenset({"localhost"})  # RFC 2606
_FIRST_TOKEN = re.compile(
    r'[ \t\r\n]*(?:\([^)]*\)[ \t\r\n]*)*("[^"]*"|[^ \t\r\n;(=/]+)(\s*[=/])?'
)
_PROSE_DOTTED = frozenset({"plan.md"})


def _name_ok(name: str) -> bool:
    lowered = name.lower()
    if lowered in cases_vendor.VENDOR_HOSTNAMES:
        return True
    return any(lowered == s or lowered.endswith("." + s) for s in _RESERVED)


def _in_comment(value: str) -> list[bool]:
    """Per character: inside a comment (quoted-pairs and quoted strings kept)."""
    mask: list[bool] = []
    depth = 0
    quoted = False
    escaped = False
    for char in value:
        mask.append(depth > 0)
        if escaped:
            escaped = False
        elif char == "\\" and (depth or quoted):
            escaped = True
        elif quoted:
            quoted = char != '"'
        elif char == '"' and not depth:
            quoted = True
        elif char == "(":
            depth += 1
        elif char == ")" and depth:
            depth -= 1
    return mask


def _dotted_problem(text: str, match: re.Match[str], *, header: bool) -> bool:
    """True if this dotted run is a name or IPv4 address that is not allowed.

    In a header value, ``ptype.property=`` is skipped only outside comments;
    in prose (``rewrite``, ``cite``) a ``ptype.property`` mention is skipped.
    """
    found = match.group()
    labels = found.lower().split(".")
    if all(label.isdigit() for label in labels):
        if len(labels) != 4:  # noqa: PLR2004 - not a dotted quad: a section number
            return False
        address = ipaddress.ip_address(found)
        return not any(address in net for net in _DOC_V4)
    if found.lower() in _PROSE_DOTTED:
        return False
    if labels[0] in _PTYPES and len(labels) == 2:  # noqa: PLR2004 - ptype.property
        if not header:
            return False
        outside = not _in_comment(text)[match.start()]
        if outside and text[match.end() :].lstrip(" ").startswith("="):
            return False
    return not _name_ok(found)


def _authserv_id_problems(value: str) -> list[str]:
    """A single-label authserv-id is flagged unless allowlisted.

    A first token followed by = or / is a method (AU-Q35), not an id.
    """
    match = _FIRST_TOKEN.match(value)
    if match is None or match.group(2):
        return []
    found = match.group(1).strip('"')
    if "." in found or found.lower() in _SINGLE_LABEL_NAMES:
        return []
    return [found]


def _text_problems(text: str, *, header: bool) -> list[str]:
    """Names, addresses and local-parts in a header value or in prose."""
    problems = [
        m.group()
        for m in _DOTTED.finditer(text)
        if _dotted_problem(text, m, header=header)
    ]
    for match in _V6.finditer(text):
        try:
            address6 = ipaddress.ip_address(match.group())
        except ValueError:
            continue
        if address6 not in _DOC_V6:
            problems.append(match.group())
    problems.extend(
        m.group(1) + "@"
        for m in _LOCAL.finditer(text)
        if m.group(1).lower() not in _LOCAL_PARTS
    )
    problems.extend(
        m.group()
        for m in _QUOTED_LOCAL.finditer(text)
        if m.group(1) not in _QUOTED_LOCAL_PARTS
    )
    problems.extend(
        "@" + m.group(1)
        for m in _SINGLE_AFTER_AT.finditer(text)
        if m.group(1).lower() not in _SINGLE_LABEL_NAMES
    )
    if header:
        problems.extend(_authserv_id_problems(text))
    return problems


def _vendor_problems(case: Case) -> list[str]:
    assert isinstance(case.value, str)
    return [
        *_text_problems(case.value, header=True),
        *_text_problems(case.rewrite or "", header=False),
        *_text_problems(case.cite, header=False),
    ]


@pytest.mark.parametrize("case", cases_vendor.CASES, ids=lambda c: c.id)
def test_vendor_case(case: Case) -> None:
    assert case.url is not None
    assert case.url.startswith("https://")
    assert case.read is not None
    assert dt.date.fromisoformat(case.read).isoformat() == case.read
    assert case.rewrite
    assert _vendor_problems(case) == []


def _probe(value: str, rewrite: str = "x", cite: str = "x") -> list[str]:
    return _vendor_problems(
        Case(id="probe", value=value, expected=None, cite=cite, rewrite=rewrite)
    )


def test_vendor_checker_flags() -> None:
    assert _probe("contoso.com; spf=pass smtp.mailfrom=a.example") == ["contoso.com"]
    assert _probe("x.example; iprev=pass policy.iprev=10.0.0.1") == ["10.0.0.1"]
    assert _probe("x.example; iprev=pass policy.iprev=2001:db9::1") == ["2001:db9::1"]
    assert _probe("mx.google.com; iprev=pass policy.iprev=2001:db8::1") == []
    # name.tld= hidden in a comment is not mistaken for ptype.property
    assert _probe("x.example; dkim=pass (header.contoso=1 bank.com=pass)") == [
        "header.contoso",
        "bank.com",
    ]
    # local-parts outside the allowlist
    assert _probe("x.example; spf=pass smtp.mailfrom=jdoe@example.com") == ["jdoe@"]
    assert _probe("x.example; dkim=pass header.i=@example.com") == []
    # rewrite notes and cites are scanned too
    assert _probe("x.example; none", rewrite="192.168.50.50 -> 198.51.100.50") == [
        "192.168.50.50"
    ]
    assert _probe("x.example; none", cite="seen at contoso.com, PLAN.md 2.4") == [
        "contoso.com"
    ]
    assert _probe("x.example; none", rewrite="pm_bounces@ -> bounces@") == [
        "pm_bounces@"
    ]
    assert _probe("x.example; none", cite="G16 (smtp.mail is unregistered)") == []
    # a quoted local-part outside the (empty) allowlist
    assert _probe('x.example; spf=pass smtp.mailfrom="jane doe"@example.com') == [
        '"jane doe"@'
    ]
    # single-label names: as the authserv-id, and as a domain after @
    assert _probe("mailhost; spf=pass") == ["mailhost"]
    assert _probe('"mailhost"; spf=pass') == ["mailhost"]
    assert _probe("x.example; dkim=pass header.i=@corp") == ["@corp"]
    assert _probe("x.example; dkim=pass header.i=@localhost") == []
    # a missing authserv-id (AU-Q35) is not mistaken for a single-label id
    assert _probe("spf=pass smtp.mailfrom=example.com") == []
    assert _probe(" (c) dkim / 1 = pass") == []


def test_only_vendor_cases_carry_provenance() -> None:
    vendor_ids = {c.id for c in cases_vendor.CASES}
    for case in ALL_CASES:
        if case.id not in vendor_ids:
            assert case.url is None, case.id
            assert case.read is None, case.id


# The comparison helpers themselves.


def test_fingerprint_catches_loose_types() -> None:
    model = ar(
        "example.com",
        res("dkim", "pass", prop("header", "d", "x", registered=True), registered=True),
        deviations=(Deviation.BARE_PROPERTY,),
    )
    as_set = AuthenticationResults(
        authserv_id=model.authserv_id,
        version=model.version,
        version_given=model.version_given,
        none=model.none,
        results=model.results,
        deviations=cast("frozenset[Deviation]", {Deviation.BARE_PROPERTY}),
    )
    as_str = AuthenticationResults(
        authserv_id=model.authserv_id,
        version=model.version,
        version_given=model.version_given,
        none=model.none,
        results=model.results,
        deviations=cast("frozenset[Deviation]", frozenset({"bare_property"})),
    )
    as_int = AuthenticationResults(
        authserv_id=model.authserv_id,
        version=model.version,
        version_given=cast("bool", 0),
        none=model.none,
        results=model.results,
        deviations=model.deviations,
    )
    as_list = AuthenticationResults(
        authserv_id=model.authserv_id,
        version=model.version,
        version_given=model.version_given,
        none=model.none,
        results=cast("tuple[Result, ...]", list(model.results)),
        deviations=model.deviations,
    )
    for loose in (as_set, as_str, as_int, as_list):
        assert fingerprint(loose) != fingerprint(model)
    assert fingerprint(model) == fingerprint(
        ar(
            "example.com",
            res(
                "dkim",
                "pass",
                prop("header", "d", "x", registered=True),
                registered=True,
            ),
            deviations=(Deviation.BARE_PROPERTY,),
        )
    )


def test_stub_detection_is_exact() -> None:
    def internal(type_name: str | None) -> AuthResultsError:
        err = AuthResultsError(ErrorReason.INTERNAL)
        if type_name is not None:
            err.__cause__ = InternalCause(type_name)
        return err

    assert is_stub_error(internal("NotImplementedError"))
    assert not is_stub_error(internal("RuntimeError"))
    assert not is_stub_error(internal(None))
    other = AuthResultsError(ErrorReason.SYNTAX, 0)
    other.__cause__ = InternalCause("NotImplementedError")
    assert not is_stub_error(other)
    plain = AuthResultsError(ErrorReason.INTERNAL)
    plain.__cause__ = NotImplementedError()
    assert not is_stub_error(plain)


# The run guards in tests/conftest.py (AL3a red-team F4): it may only import
# ALL_CASES and the pending hook, may not assign attributes or reach for
# dynamic tools, and may only define known hooks and private helpers.

_CONFTEST_IMPORTS = {
    (0, "pathlib"): {"Path"},
    (1, "test_cases"): {"ALL_CASES"},
    (1, "_case"): {"PENDING_KEY", "Pending"},
    (1, "_pending"): {"pytest_collection_modifyitems"},
}
_CONFTEST_HOOKS = {
    "pytest_configure",
    "pytest_deselected",
    "pytest_collection_finish",
    "pytest_runtest_makereport",
    "pytest_runtest_logreport",
    "pytest_sessionfinish",
    "pytest_terminal_summary",
}
_BANNED_NAMES = {
    "setattr",
    "delattr",
    "monkeypatch",
    "MonkeyPatch",
    "globals",
    "vars",
    "exec",
    "eval",
    "compile",
    "importlib",
    "__import__",
    "sys",
    "pytest_plugins",
}
# Attribute loads that reach a function's bound defaults, code or namespace
# (AL3a round 3, N2): pytest's Function.obj, then __kwdefaults__ and kin.
_BANNED_ATTRIBUTES = {
    "obj",
    "__kwdefaults__",
    "__defaults__",
    "__dict__",
    "__code__",
    "__closure__",
    "__globals__",
    "__setattr__",
}


def _check_conftest_node(node: ast.AST) -> None:
    if isinstance(node, ast.Import):
        assert {a.name for a in node.names} <= {"os", "pytest"}
        assert all(a.asname is None for a in node.names)
    elif isinstance(node, ast.ImportFrom):
        allowed = _CONFTEST_IMPORTS[(node.level, node.module or "")]
        assert {a.name for a in node.names} <= allowed
    elif isinstance(node, ast.Attribute):
        if not isinstance(node.ctx, ast.Load):
            assert node.attr == "exitstatus", "attribute assignment"
        assert node.attr not in _BANNED_NAMES
        assert node.attr not in _BANNED_ATTRIBUTES, node.attr
        if isinstance(node.value, ast.Name) and node.value.id == "os":
            assert node.attr == "environ", "os is only read for os.environ"
    elif isinstance(node, ast.Subscript):
        assert isinstance(node.ctx, ast.Load), "subscript store or delete"
    elif isinstance(node, ast.Name):
        assert node.id not in _BANNED_NAMES
    elif isinstance(node, ast.Global | ast.Nonlocal):
        pytest.fail("global or nonlocal statement")


def _check_conftest_statement(statement: ast.stmt) -> None:
    if isinstance(statement, ast.FunctionDef):
        name = statement.name
        assert name.startswith("_") or name in _CONFTEST_HOOKS, name
    elif isinstance(statement, ast.Assign | ast.AnnAssign):
        targets = (
            statement.targets
            if isinstance(statement, ast.Assign)
            else [statement.target]
        )
        for target in targets:
            assert isinstance(target, ast.Name), "module-level target"
            assert target.id.startswith("_"), target.id
    else:
        assert isinstance(statement, ast.Expr | ast.Import | ast.ImportFrom)


def test_conftest_shape() -> None:
    source = (Path(__file__).parent / "conftest.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        _check_conftest_node(node)
    for statement in tree.body:
        _check_conftest_statement(statement)


# AL3a round 3, N1: the files AL2b may edit or add cannot reach into the
# frozen case table. The frozen files are the ones the AL2b acceptance diff
# covers; everything else under tests/, and any .py at the repository root,
# is scanned.

_TESTS_DIR = Path(__file__).resolve().parent
_ROOT = _TESTS_DIR.parent
_FROZEN = {"_case.py", "test_cases.py", "test_case_table_meta.py"}
_DEFAULT_INTERNALS = {"__kwdefaults__", "__defaults__", "__code__", "__closure__"}
# The public case-building API of tests/_case.py: what tests/cases_redteam.py
# (appended by AL2b) and AL2b's own tests need to write and compare cases.
# Pending, PENDING_KEY, fingerprint, UNSET and the private marker classes
# drive the harness itself and stay with the guard files.
_CASE_PUBLIC = {"Case", "Options", "ar", "res", "prop", "bare", "ANY_POSITION"}
_GUARD_IMPORTS = {
    "conftest.py": {"_case": {"PENDING_KEY", "Pending"}, "test_cases": {"ALL_CASES"}},
    "_pending.py": {"_case": {"PENDING_KEY", "Pending"}, "test_cases": {"ALL_CASES"}},
}
_SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "mutants", "dist", "build"}


def _non_frozen_files() -> list[Path]:
    tests = [
        p
        for p in sorted(_TESTS_DIR.glob("*.py"))
        if p.name not in _FROZEN
        and not (p.name.startswith("cases_") and p.name != "cases_redteam.py")
    ]
    return tests + sorted(_ROOT.glob("*.py"))


def _module_of(node: ast.ImportFrom) -> str:
    """The tests-relative module an import names, e.g. "_case" or "test_cases"."""
    module = node.module or ""
    if node.level == 0:
        return module.removeprefix("tests.") if module.startswith("tests.") else ""
    return module


def _plain_import_problems(node: ast.Import) -> list[str]:
    return [
        f"import {alias.name}"
        for alias in node.names
        if alias.name.split(".")[-1] in {"test_cases", "_case", "conftest"}
    ]


def _from_import_problems(
    node: ast.ImportFrom, allowed: dict[str, set[str]]
) -> list[str]:
    module = _module_of(node)
    names = {a.name for a in node.names}
    if module in {"", "tests"} and (node.level or node.module == "tests"):
        # from . import x, from tests import x
        hidden = names & {"test_cases", "_case", "conftest"}
        return [f"import of module {n}" for n in sorted(hidden)]
    if module == "conftest":
        return ["import from conftest"]
    if module == "test_cases":
        extra = names - allowed.get("test_cases", set())
        return [f"import from test_cases: {sorted(extra)}"] if extra else []
    if module == "_case":
        extra = names - allowed.get("_case", _CASE_PUBLIC)
        return [f"import of _case internals: {sorted(extra)}"] if extra else []
    return []


def _import_problems(node: ast.AST, allowed: dict[str, set[str]]) -> list[str]:
    if isinstance(node, ast.Import):
        return _plain_import_problems(node)
    if isinstance(node, ast.ImportFrom):
        return _from_import_problems(node, allowed)
    return []


def _imported_names(tree: ast.Module) -> set[str]:
    bound: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import | ast.ImportFrom):
            bound.update((a.asname or a.name).split(".")[0] for a in node.names)
    return bound


def _tree_problems(source: str, name: str) -> list[str]:
    tree = ast.parse(source)
    allowed = _GUARD_IMPORTS.get(name, {})
    imported = _imported_names(tree)
    problems: list[str] = []
    for node in ast.walk(tree):
        problems.extend(_import_problems(node, allowed))
        if isinstance(node, ast.Attribute) and node.attr in _DEFAULT_INTERNALS:
            problems.append(f"attribute {node.attr}")
        elif isinstance(node, ast.Name) and node.id in _DEFAULT_INTERNALS:
            problems.append(f"name {node.id}")
        elif isinstance(node, ast.Constant) and node.value in _DEFAULT_INTERNALS:
            problems.append(f"string {node.value}")
        if isinstance(node, ast.Attribute) and not isinstance(node.ctx, ast.Load):
            # Only a plain local name may have attributes assigned: never an
            # imported module, nor an expression such as sys.modules[...].
            base = node.value
            if not isinstance(base, ast.Name) or base.id in imported:
                problems.append(f"store .{node.attr}")
    return problems


def _scan_problems(path: Path) -> list[str]:
    name = path.name if path.parent == _TESTS_DIR else f"<root>/{path.name}"
    source = path.read_text(encoding="utf-8")
    return [f"{path.name}: {p}" for p in _tree_problems(source, name)]


def test_non_frozen_files_keep_out_of_the_table() -> None:
    problems = [p for path in _non_frozen_files() for p in _scan_problems(path)]
    assert problems == []


def test_only_one_conftest() -> None:
    found = [
        p.relative_to(_ROOT).as_posix()
        for p in _ROOT.rglob("conftest.py")
        if not (set(p.relative_to(_ROOT).parts[:-1]) & _SKIP_DIRS)
    ]
    assert found == ["tests/conftest.py"]


def _plant(source: str, name: str = "test_planted.py") -> list[str]:
    return _tree_problems(source, name)


def test_non_frozen_scan_flags() -> None:
    assert _plant("from . import test_cases\n") == ["import of module test_cases"]
    assert _plant("from .test_cases import ALL_CASES\n") == [
        "import from test_cases: ['ALL_CASES']"
    ]
    assert _plant("import tests.test_cases\n") == ["import tests.test_cases"]
    assert _plant("from ._case import fingerprint, Case\n") == [
        "import of _case internals: ['fingerprint']"
    ]
    assert _plant("from tests._case import Pending\n") == [
        "import of _case internals: ['Pending']"
    ]
    assert _plant("from ._case import Case, ar, res, prop, bare\n") == []
    assert _plant("def f(): pass\nf.__kwdefaults__\n") == ["attribute __kwdefaults__"]
    assert _plant("g = getattr(f, '__defaults__')\n") == ["string __defaults__"]
    assert _plant("from . import cases_grammar\ncases_grammar.CASES = ()\n") == [
        "store .CASES"
    ]
    assert _plant("import sys\nsys.modules['x'].CASES = ()\n") == ["store .CASES"]
    assert _plant("from . import conftest\n") == ["import of module conftest"]
    # the guard files may import exactly what they need
    assert _plant("from .test_cases import ALL_CASES\n", name="conftest.py") == []
    assert _plant("from ._case import PENDING_KEY\n", name="_pending.py") == []


# AL3a round 3: the post-AL2b form of tests/conftest.py, pinned by hash.
#
# How the hash is computed: read tests/conftest.py as UTF-8 text; while
# tests/_pending.py exists, delete every line from the first line that starts
# with "# --- AL2b: delete" through the first line that starts with
# "# --- end of the AL2b deletion", inclusive, plus the one blank line right
# after it, line endings included; take the SHA-256 of the UTF-8 bytes of
# what is left. Deleting exactly those lines leaves a ruff-clean file. Once
# tests/_pending.py is gone, the file itself (with no such block left) must
# have this hash.
_CONFTEST_POST_AL2B_SHA256 = (
    "7b42a223c219aac0be2b27b14431a86c6e8ddb5f2fd8dc018c6edf19d04c1f0c"
)
_BLOCK_START = "# --- AL2b: delete"
_BLOCK_END = "# --- end of the AL2b deletion"


def _post_al2b(text: str) -> str:
    lines = text.splitlines(keepends=True)
    start = next(i for i, line in enumerate(lines) if line.startswith(_BLOCK_START))
    end = next(i for i, line in enumerate(lines) if line.startswith(_BLOCK_END))
    assert start < end
    if end + 1 < len(lines) and not lines[end + 1].strip():
        end += 1
    return "".join(lines[:start] + lines[end + 1 :])


def test_conftest_post_al2b_hash() -> None:
    text = (_TESTS_DIR / "conftest.py").read_text(encoding="utf-8")
    if (_TESTS_DIR / "_pending.py").exists():
        text = _post_al2b(text)
    else:
        assert _BLOCK_START not in text
        assert _BLOCK_END not in text
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    assert digest == _CONFTEST_POST_AL2B_SHA256
