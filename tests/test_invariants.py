# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""Source invariants of the package, checked with the stdlib ``ast`` module.

Recursion. No graph node reaches itself. The graph is name-based and errs
towards flagging: names are merged across modules and classes, so two methods
with the same name are one node. Nodes are:

- every function and method, with an edge to every name it references
  (calls, plain references such as ``map(f, xs)``, attribute names, and the
  constant name in ``getattr(obj, "name")``); ``super().<name>`` is not an edge;
- every module-level and class-level assignment target, and every assignment
  to a ``global`` name inside a function (``_HANDLERS = {...}``,
  ``_again = _parse``, ``_deeper = functools.partial(_scan)``,
  ``dispatch = visit``), with edges to the names in the assigned expression;
- every class, with edges to its own ``__init__``, ``__post_init__`` or
  ``__new__`` and to the names in its class-body values (field defaults,
  ``default_factory``), so ``Node(...)`` inside ``Node.__init__`` is a cycle;
- a method calling ``type(<its first parameter>)`` refers to its class.

Banned constructs, because they hide edges from a name-based graph or load
code by name:

- ``lambda`` (use a ``def``); ``type(...)(...)``; the ``__class__`` and
  ``__dict__`` attributes; star imports;
- ``getattr`` whose name is not a string constant, or names a banned attribute;
- the names ``__import__``, ``__builtins__``, ``importlib``, ``eval``,
  ``exec``, ``compile``, ``globals``, ``locals``, ``vars``, ``breakpoint``,
  ``setattr``, ``delattr``, ``get_type_hints`` and ``ForwardRef`` (the last
  two evaluate strings), as names, attributes or ``from`` imports;
- the attributes ``re``, ``sys``, ``os``, ``builtins`` and ``subprocess``;
- on each allowed module (and its alias), every attribute whose value is a
  module (``enum.bltns``, ``typing.functools``, ``contextlib.os``), computed
  on the running Python with ``inspect.ismodule``, plus
  ``dataclasses.replace``; the same names as ``from <module> import``;
- hand-written dunder methods other than ``__init__``, ``__post_init__`` and
  ``__reduce__``.

Known limit: implicit recursion through operators or protocols (``a == b``
calling ``__eq__``, ``yield from x`` calling ``__iter__``, ``hash``, ``repr``)
cannot be seen in the AST without types. The dunder ban removes hand-written
ones. The dataclass-generated ``__eq__``, ``__hash__`` and ``__repr__`` recurse
only through the fixed model nesting (``ArcAuthenticationResults`` ->
``AuthenticationResults`` -> ``Result`` -> ``Property``), whose depth does not
depend on the input. Calls through local variables bound to a module object,
or through objects passed in from outside, are not tracked.

Imports. No ``re``. Only an allowlist of stdlib modules, plus relative imports
within the package.

Ruff has no recursion rule (``ruff rule --all`` checked at AL2a), hence this
test.
"""

import ast
import importlib
import inspect
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parent.parent / "src" / "authresults"
ALLOWED_IMPORTS = frozenset(
    {"enum", "dataclasses", "typing", "collections.abc", "contextlib", "functools"}
)
BANNED_NAMES = frozenset(
    {
        "__import__",
        "__builtins__",
        "importlib",
        "eval",
        "exec",
        "compile",
        "globals",
        "locals",
        "vars",
        "breakpoint",
        "setattr",
        "delattr",
        "get_type_hints",
        "ForwardRef",
    }
)
BANNED_ATTRIBUTES = BANNED_NAMES | {
    "re",
    "sys",
    "os",
    "builtins",
    "subprocess",
    "__dict__",
    "__class__",
}
# Per-module attributes that are banned on top of the module-valued ones.
EXTRA_MODULE_BANS = {"dataclasses": frozenset({"replace"})}
ALLOWED_DUNDERS = frozenset({"__init__", "__post_init__", "__reduce__"})
INIT_METHODS = frozenset({"__init__", "__post_init__", "__new__"})
Function = ast.FunctionDef | ast.AsyncFunctionDef


def _module_attribute_bans() -> dict[str, frozenset[str]]:
    """For each allowed module (and the package of a dotted one), the banned
    attribute names: every attribute whose value is a module, except allowed
    submodules (``collections.abc``), plus ``EXTRA_MODULE_BANS``. Computed on
    the running Python, since these differ between versions.
    """
    bans: dict[str, frozenset[str]] = {}
    for allowed in ALLOWED_IMPORTS:
        parts = allowed.split(".")
        for depth in range(1, len(parts) + 1):
            name = ".".join(parts[:depth])
            module = importlib.import_module(name)
            submodules = {n for n, v in vars(module).items() if inspect.ismodule(v)}
            keep = {
                p.split(".")[depth] for p in ALLOWED_IMPORTS if p.startswith(f"{name}.")
            }
            bans[name] = frozenset(
                (submodules - keep) | EXTRA_MODULE_BANS.get(name, frozenset())
            )
    return bans


MODULE_ATTRIBUTE_BANS = _module_attribute_bans()
ALL_MODULE_ATTRIBUTE_BANS = frozenset().union(*MODULE_ATTRIBUTE_BANS.values())


def _package_sources() -> dict[str, str]:
    return {p.name: p.read_text(encoding="utf-8") for p in sorted(PACKAGE.glob("*.py"))}


def _is_super_attribute(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "super"
    )


def _getattr_constant(node: ast.AST) -> str | None:
    """The name in ``getattr(obj, "name")``, else ``None``."""
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "getattr"
        and len(node.args) >= 2  # noqa: PLR2004 - getattr(obj, name[, default])
        and isinstance(node.args[1], ast.Constant)
        and isinstance(node.args[1].value, str)
    ):
        return node.args[1].value
    return None


def _referenced_names(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute) and not _is_super_attribute(node):
            names.add(node.attr)
        constant = _getattr_constant(node)
        if constant is not None:
            names.add(constant)
    return names


def _target_names(target: ast.expr) -> set[str]:
    return {n.id for n in ast.walk(target) if isinstance(n, ast.Name)}


def _assignment(statement: ast.AST) -> tuple[set[str], ast.expr | None] | None:
    """Targets and value of an assignment statement, else ``None``."""
    if isinstance(statement, ast.Assign):
        return set().union(*map(_target_names, statement.targets)), statement.value
    if isinstance(statement, ast.AnnAssign | ast.AugAssign):
        return _target_names(statement.target), statement.value
    return None


def _scope_statements(tree: ast.Module) -> list[ast.stmt]:
    """Statements of the module body and of every class body in it."""
    statements: list[ast.stmt] = []
    pending: list[list[ast.stmt]] = [tree.body]
    while pending:
        for statement in pending.pop():
            statements.append(statement)
            if isinstance(statement, ast.ClassDef):
                pending.append(statement.body)
    return statements


def _class_edges(cls: ast.ClassDef) -> set[str]:
    """A class refers to its own init methods and to its class-body values
    (field defaults, ``default_factory``)."""
    edges: set[str] = set()
    for statement in cls.body:
        if isinstance(statement, Function) and statement.name in INIT_METHODS:
            edges.add(statement.name)
        assignment = _assignment(statement)
        if assignment is not None and assignment[1] is not None:
            edges.update(_referenced_names(assignment[1]))
    return edges


def _self_type_calls(cls: ast.ClassDef) -> dict[str, set[str]]:
    """Methods that call ``type(<first parameter>)`` refer to their class."""
    edges: dict[str, set[str]] = {}
    for method in cls.body:
        if not (isinstance(method, Function) and method.args.args):
            continue
        first = method.args.args[0].arg
        for node in ast.walk(method):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "type"
                and node.args
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id == first
            ):
                edges.setdefault(method.name, set()).add(cls.name)
    return edges


def _global_assignments(function: Function) -> dict[str, set[str]]:
    """Assignments to ``global`` names inside a function, as module-level nodes."""
    declared = {
        name
        for node in ast.walk(function)
        if isinstance(node, ast.Global)
        for name in node.names
    }
    nodes: dict[str, set[str]] = {}
    for node in ast.walk(function):
        assignment = _assignment(node)
        if assignment is None:
            continue
        targets, value = assignment
        for target in targets & declared:
            entry = nodes.setdefault(target, set())
            if value is not None:
                entry.update(_referenced_names(value))
    return nodes


def _walk_nodes(tree: ast.Module) -> list[tuple[str, set[str]]]:
    """Nodes from functions (and their ``global`` assignments) and classes."""
    nodes: list[tuple[str, set[str]]] = []
    for node in ast.walk(tree):
        if isinstance(node, Function):
            nodes.append((node.name, _referenced_names(node)))
            nodes.extend(_global_assignments(node).items())
        elif isinstance(node, ast.ClassDef):
            nodes.append((node.name, _class_edges(node)))
            nodes.extend(_self_type_calls(node).items())
    return nodes


def _scope_nodes(tree: ast.Module) -> list[tuple[str, set[str]]]:
    """Nodes from module-level and class-level assignments."""
    nodes: list[tuple[str, set[str]]] = []
    for statement in _scope_statements(tree):
        assignment = _assignment(statement)
        if assignment is not None:
            targets, value = assignment
            refs = set() if value is None else _referenced_names(value)
            nodes.extend((target, refs) for target in targets)
    return nodes


def call_graph(sources: dict[str, str]) -> dict[str, set[str]]:
    """Map each graph node (see the module docstring) to the nodes it refers to."""
    refs: dict[str, set[str]] = {}
    for source in sources.values():
        tree = ast.parse(source)
        for name, targets in _walk_nodes(tree) + _scope_nodes(tree):
            refs.setdefault(name, set()).update(targets)
    return {name: targets & refs.keys() for name, targets in refs.items()}


def recursive_functions(graph: dict[str, set[str]]) -> set[str]:
    """Return every node that can reach itself."""
    found: set[str] = set()
    for start, targets in graph.items():
        seen: set[str] = set()
        stack = list(targets)
        while stack:
            name = stack.pop()
            if name == start:
                found.add(start)
                break
            if name not in seen:
                seen.add(name)
                stack.extend(graph[name])
    return found


def _module_aliases(tree: ast.Module) -> dict[str, str]:
    """Local name -> module for ``import x``, ``import x.y`` and ``import x as y``."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
                else:
                    top = alias.name.split(".")[0]
                    aliases[top] = top
    return aliases


def _bad_getattr(node: ast.Call) -> bool:
    if not (isinstance(node.func, ast.Name) and node.func.id == "getattr"):
        return False
    name = _getattr_constant(node)
    return (
        name is None or name in BANNED_ATTRIBUTES or name in ALL_MODULE_ATTRIBUTE_BANS
    )


def _is_type_call_call(node: ast.Call) -> bool:
    return (
        isinstance(node.func, ast.Call)
        and isinstance(node.func.func, ast.Name)
        and node.func.func.id == "type"
    )


def _banned_import_from(node: ast.ImportFrom) -> list[str]:
    module_bans = MODULE_ATTRIBUTE_BANS.get(node.module or "", frozenset())
    found: list[str] = []
    for alias in node.names:
        if alias.name == "*":
            found.append(f"{node.lineno}: star import")
        elif alias.name in BANNED_ATTRIBUTES or alias.name in module_bans:
            found.append(f"{node.lineno}: import of {alias.name}")
    return found


def _banned_attribute(node: ast.Attribute, aliases: dict[str, str]) -> str | None:
    if node.attr in BANNED_ATTRIBUTES:
        return f"{node.lineno}: attribute .{node.attr}"
    if isinstance(node.value, ast.Name) and node.value.id in aliases:
        module = aliases[node.value.id]
        if node.attr in MODULE_ATTRIBUTE_BANS.get(module, frozenset()):
            return f"{node.lineno}: attribute {module}.{node.attr}"
    return None


def banned_constructs(source: str) -> list[str]:
    """Return one ``line: what`` entry per banned construct in *source*."""
    tree = ast.parse(source)
    aliases = _module_aliases(tree)
    found: list[str] = []
    for node in ast.walk(tree):
        line = getattr(node, "lineno", 0)
        if isinstance(node, ast.Lambda):
            found.append(f"{line}: lambda")
        elif isinstance(node, ast.Call) and _bad_getattr(node):
            found.append(f"{line}: dynamic getattr")
        elif isinstance(node, ast.Call) and _is_type_call_call(node):
            found.append(f"{line}: call of type(...)")
        elif isinstance(node, ast.Name) and node.id in BANNED_NAMES:
            found.append(f"{line}: name {node.id}")
        elif isinstance(node, ast.Attribute):
            banned = _banned_attribute(node, aliases)
            if banned:
                found.append(banned)
        elif isinstance(node, ast.ImportFrom):
            found.extend(_banned_import_from(node))
        elif (
            isinstance(node, Function)
            and node.name.startswith("__")
            and node.name.endswith("__")
            and node.name not in ALLOWED_DUNDERS
        ):
            found.append(f"{line}: dunder {node.name}")
    return found


def imported_modules(source: str) -> set[str]:
    """Return absolute module names imported by *source* (relative ones skipped)."""
    modules: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            modules.add(node.module or "")
    return modules


def _is_re(module: str) -> bool:
    return module == "re" or module.startswith("re.")


# --- the package ------------------------------------------------------------


def test_package_has_modules() -> None:
    assert "__init__.py" in _package_sources()


def test_package_has_no_recursion() -> None:
    assert recursive_functions(call_graph(_package_sources())) == set()


@pytest.mark.parametrize("module", sorted(_package_sources()))
def test_module_has_no_banned_constructs(module: str) -> None:
    assert banned_constructs(_package_sources()[module]) == []


@pytest.mark.parametrize("module", sorted(_package_sources()))
def test_module_imports(module: str) -> None:
    imports = imported_modules(_package_sources()[module])
    assert not any(_is_re(m) for m in imports)
    assert imports <= ALLOWED_IMPORTS


# --- self-tests on planted sources ------------------------------------------

RECURSION_CASES: dict[str, tuple[dict[str, str], set[str]]] = {
    "direct": (
        {"a.py": "def walk(node):\n    return [walk(c) for c in node]\n"},
        {"walk"},
    ),
    "mutual": (
        {
            "a.py": "def even(n):\n    return n == 0 or odd(n - 1)\n",
            "b.py": "def odd(n):\n    return n != 0 and even(n - 1)\n",
        },
        {"even", "odd"},
    ),
    "method": (
        {
            "a.py": (
                "class Tree:\n"
                "    def visit(self):\n"
                "        for child in self.children:\n"
                "            child.visit()\n"
            )
        },
        {"visit"},
    ),
    "super_chain": (
        {
            "a.py": (
                "class Base:\n    def run(self, n):\n        return self.run(n - 1)\n"
            )
        },
        {"run"},
    ),
    "reference": (
        {"a.py": "def flatten(items):\n    return list(map(flatten, items))\n"},
        {"flatten"},
    ),
    "nested": (
        {
            "a.py": (
                "def outer(x):\n"
                "    def helper(y):\n"
                "        return outer(y)\n"
                "    return helper(x)\n"
            )
        },
        {"outer", "helper"},
    ),
    "dispatch_table": (
        {
            "a.py": (
                "def _comment(s, i):\n"
                "    return _HANDLERS[s[i]](s, i + 1)\n"
                '_HANDLERS = {"(": _comment}\n'
            )
        },
        {"_comment", "_HANDLERS"},
    ),
    "annotated_dispatch_table": (
        {
            "a.py": (
                "def _comment(s, i):\n"
                "    return _HANDLERS[s[i]](s, i + 1)\n"
                '_HANDLERS: dict = {"(": _comment}\n'
            )
        },
        {"_comment", "_HANDLERS"},
    ),
    "class_attribute_alias": (
        {
            "a.py": (
                "class P:\n"
                "    def visit(self, node):\n"
                "        return self.again(node)\n"
                "    again = visit\n"
            )
        },
        {"visit", "again"},
    ),
    "module_alias": (
        {"a.py": "def _parse(x):\n    return _again(x)\n_again = _parse\n"},
        {"_parse", "_again"},
    ),
    "partial": (
        {
            "a.py": (
                "import functools\n"
                "def _scan(s, d):\n"
                "    return _deeper(s, d + 1)\n"
                "_deeper = functools.partial(_scan)\n"
            )
        },
        {"_scan", "_deeper"},
    ),
    "class_instantiation": (
        {
            "a.py": (
                "class Node:\n"
                "    def __init__(self, text):\n"
                "        self.child = Node(text[1:]) if text else None\n"
            )
        },
        {"Node", "__init__"},
    ),
    "post_init_instantiation": (
        {"a.py": ("class Node:\n    def __post_init__(self):\n        Node()\n")},
        {"Node", "__post_init__"},
    ),
    "module_lambda": (
        {"a.py": "walk = lambda n: [walk(c) for c in n]\n"},
        {"walk"},
    ),
    "getattr_constant_self": (
        {
            "a.py": (
                "class P:\n"
                "    def visit(self, n):\n"
                '        return getattr(self, "visit")(n)\n'
            )
        },
        {"visit"},
    ),
    "type_self_in_init": (
        {
            "a.py": (
                "class N:\n"
                "    def __init__(self, t):\n"
                "        make = type(self)\n"
                "        self.c = make(t[1:]) if t else None\n"
            )
        },
        {"N", "__init__"},
    ),
    "default_factory": (
        {
            "a.py": (
                "import dataclasses\n"
                "def _make():\n"
                "    return N()\n"
                "@dataclasses.dataclass\n"
                "class N:\n"
                "    c: object = dataclasses.field(default_factory=_make)\n"
            )
        },
        {"N", "_make"},
    ),
    "global_alias": (
        {
            "a.py": (
                "def setup():\n"
                "    global _again\n"
                "    _again = _parse\n"
                "def _parse(x):\n"
                "    return _again(x)\n"
            )
        },
        {"_again", "_parse"},
    ),
    "clean": (
        {
            "a.py": (
                "import enum\n"
                "LIMIT = 8\n"
                "class Error(ValueError):\n"
                "    def __init__(self, reason):\n"
                "        super().__init__(str(reason))\n"
                "def parse(value):\n"
                "    return _parse_payload(value)\n"
                "def _parse_payload(value):\n"
                "    raise Error(LIMIT)\n"
            )
        },
        set(),
    ),
}


@pytest.mark.parametrize(
    ("sources", "expected"), RECURSION_CASES.values(), ids=RECURSION_CASES.keys()
)
def test_recursion_detector(sources: dict[str, str], expected: set[str]) -> None:
    assert recursive_functions(call_graph(sources)) == expected


BANNED_CASES: dict[str, tuple[str, list[str]]] = {
    "lambda_module": ("walk = lambda n: n\n", ["1: lambda"]),
    "lambda_in_function": (
        "def outer(n):\n    go = lambda k: go(k - 1) if k else 0\n    return go(n)\n",
        ["2: lambda"],
    ),
    "getattr_concatenated": (
        (
            "class P:\n"
            "    def step(self, n):\n"
            '        return getattr(self, "st" + "ep")(n - 1)\n'
        ),
        ["3: dynamic getattr"],
    ),
    "getattr_visitor": (
        (
            "class P:\n"
            "    def visit(self, node):\n"
            '        return getattr(self, "visit_" + node.kind)(node)\n'
        ),
        ["3: dynamic getattr"],
    ),
    "getattr_variable": (
        "def f(o, n):\n    return getattr(o, n)\n",
        ["2: dynamic getattr"],
    ),
    "getattr_one_arg": ("def f(o):\n    return getattr(o)\n", ["2: dynamic getattr"]),
    "getattr_banned_constant": (
        'import typing\nP = getattr(typing, "re", None)\n',
        ["2: dynamic getattr"],
    ),
    "dunder_import": (
        'def f():\n    return __import__("x")\n',
        ["2: name __import__"],
    ),
    "builtins_lookup": (
        'def f():\n    return __builtins__["open"]\n',
        ["2: name __builtins__"],
    ),
    "importlib": (
        'def f():\n    return importlib.import_module("x")\n',
        ["2: name importlib"],
    ),
    "eval": ('X = eval("1")\n', ["1: name eval"]),
    "exec": ('exec("x = 1")\n', ["1: name exec"]),
    "compile": ('C = compile("1", "f", "eval")\n', ["1: name compile"]),
    "globals_dispatch": ("def f(n):\n    return globals()[n]()\n", ["2: name globals"]),
    "module_re_attribute": (
        'import dataclasses\nP = dataclasses.re.compile("a+")\n',
        ["2: attribute .re", "2: attribute .compile"],
    ),
    "module_sys_attribute": (
        "import enum\nM = enum.sys.modules\n",
        ["2: attribute .sys"],
    ),
    "from_import_re": ("from dataclasses import re\n", ["1: import of re"]),
    "dunder_eq": (
        (
            "class Box:\n"
            "    def __eq__(self, other):\n"
            "        return self.inner == other.inner\n"
        ),
        ["2: dunder __eq__"],
    ),
    "dunder_iter": (
        (
            "class T:\n"
            "    def __iter__(self):\n"
            "        for c in self.children:\n"
            "            yield from c\n"
        ),
        ["2: dunder __iter__"],
    ),
    "type_call_call": (
        "class N:\n    def __init__(self, t):\n        self.c = type(self)(t)\n",
        ["3: call of type(...)"],
    ),
    "dunder_class": (
        "class N:\n    def __init__(self, t):\n        self.c = self.__class__(t)\n",
        ["3: attribute .__class__"],
    ),
    "dataclasses_replace": (
        "import dataclasses\ndef f(m):\n    return dataclasses.replace(m, d=1)\n",
        ["3: attribute dataclasses.replace"],
    ),
    "aliased_dataclasses_replace": (
        "import dataclasses as dc\nR = dc.replace\n",
        ["2: attribute dataclasses.replace"],
    ),
    "from_dataclasses_import_replace": (
        "from dataclasses import replace\n",
        ["1: import of replace"],
    ),
    "setattr": (
        'import enum\nsetattr(enum, "_again", 1)\n',
        ["2: name setattr"],
    ),
    "delattr": ('def f(o):\n    delattr(o, "x")\n', ["2: name delattr"]),
    "enum_bltns_dict": (
        'import enum\nX = enum.bltns.__dict__["__im" + "port__"]("socket")\n',
        ["2: attribute .__dict__", "2: attribute enum.bltns"],
    ),
    "typing_functools": (
        "import typing\nX = typing.functools.partial\n",
        ["2: attribute typing.functools"],
    ),
    "contextlib_os": ("import contextlib\nX = contextlib.os\n", ["2: attribute .os"]),
    "enum_sys_via_getattr": (
        'import enum\nX = getattr(enum, "sys")\n',
        ["2: dynamic getattr"],
    ),
    "from_typing_import_module": (
        "from enum import sys as s\n",
        ["1: import of sys"],
    ),
    "dict_attribute": ("X = int.__dict__\n", ["1: attribute .__dict__"]),
    "star_import": ("from typing import *\n", ["1: star import"]),
    "get_type_hints": (
        "import typing\nX = typing.get_type_hints\n",
        ["2: attribute .get_type_hints"],
    ),
    "forward_ref": (
        'from typing import ForwardRef\nX = ForwardRef("x")\n',
        ["1: import of ForwardRef", "2: name ForwardRef"],
    ),
    "allowed": (
        (
            "class E(ValueError):\n"
            "    def __init__(self, r):\n"
            "        super().__init__(r)\n"
            "    def __reduce__(self):\n"
            "        return (E, (self.r,))\n"
            'X = getattr(E, "mro")\n'
        ),
        [],
    ),
}


@pytest.mark.parametrize(
    ("source", "expected"), BANNED_CASES.values(), ids=BANNED_CASES.keys()
)
def test_banned_construct_detector(source: str, expected: list[str]) -> None:
    assert sorted(banned_constructs(source)) == sorted(expected)


def test_module_attribute_bans_are_computed() -> None:
    assert "sys" in MODULE_ATTRIBUTE_BANS["enum"]
    assert "replace" in MODULE_ATTRIBUTE_BANS["dataclasses"]
    assert "abc" not in MODULE_ATTRIBUTE_BANS["collections"]
    assert set(MODULE_ATTRIBUTE_BANS) >= ALLOWED_IMPORTS


@pytest.mark.parametrize(
    ("source", "is_re", "allowed"),
    [
        ("import re", True, False),
        ("import re as regex", True, False),
        ("from re import compile", True, False),
        ("import os", False, False),
        ("from os import path", False, False),
        ("import enum\nfrom collections.abc import Iterator", False, True),
        ("from ._errors import ErrorReason\nfrom . import _model", False, True),
    ],
)
def test_import_detector(source: str, *, is_re: bool, allowed: bool) -> None:
    imports = imported_modules(source)
    assert any(_is_re(m) for m in imports) is is_re
    assert (imports <= ALLOWED_IMPORTS) is allowed
