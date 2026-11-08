# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""Redact one header value for a bug report: ``python -m authresults.redact``.

Reads one ``Authentication-Results`` or ``ARC-Authentication-Results`` value
on standard input, writes it with personal data replaced on standard output,
and a report on standard error (``docs/plans/al3d.md`` sections 6 and 13).
Best effort: read the output before posting it. Not public API.

The only module that may use ``sys``, and only in the ``__main__`` guard.
"""

import contextlib
import sys
from collections.abc import Sequence
from typing import BinaryIO

from ._api import parse, parse_arc
from ._checks import ascii_lower
from ._errors import AuthResultsError, Deviation
from ._redact import Redaction, redact

MAX_INPUT_BYTES = 1_048_576
EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2
EXIT_INTERNAL = 3

_PREFIX = "authresults.redact: "
_USAGE = b"""\
usage: python -m authresults.redact [--show-originals] < value.txt

Reads one Authentication-Results or ARC-Authentication-Results header value
on standard input and writes it, with domains, addresses, local-parts,
selectors, signatures, long numbers and free text replaced, on standard
output. A report of what was replaced goes to standard error. Best effort:
read the output before posting it.

options:
  -h, --help        show this help and exit
  --show-originals  also list the original values in the report; that
                    report is not for posting
"""
_TOO_LONG = f"input is longer than {MAX_INPUT_BYTES} bytes; nothing written"
_EXHAUSTED = "too many distinct values to number; nothing written"
_INTERNAL = "internal error; nothing written"
_NOT_WRITTEN = "could not write the output"
_HEAD = "best effort; read the output before posting it"
_HEAD_SHOWN = "best effort; ORIGINALS SHOWN BELOW: do not post this report"
_BOM = "﻿"
_FIELD_NAMES = ("arc-authentication-results", "authentication-results")
_WSP = frozenset(" \t")
_PRINTABLE_MAX = "~"
_BYTE_MAX = 0xFF
_BMP_MAX = 0xFFFF


def _say(stream: BinaryIO, message: str) -> None:
    """Write one fixed message line; a failing stream is ignored."""
    with contextlib.suppress(OSError):
        stream.write(f"{_PREFIX}{message}\n".encode("ascii"))


def _strip(value: str) -> tuple[str, list[str]]:
    """Section 6 step 4: strip a BOM, a field name, a trailing line break."""
    notes: list[str] = []
    if value.startswith(_BOM):
        value = value[len(_BOM) :]
        notes.append("byte order mark")
    for name in _FIELD_NAMES:
        if ascii_lower(value[: len(name)]) == name:
            colon = len(name)
            while colon < len(value) and value[colon] in _WSP:
                colon += 1
            if value[colon : colon + 1] == ":":
                value = value[colon + 1 :]
                notes.append("field name")
            break
    for ending in ("\r\n", "\n"):
        if value.endswith(ending):
            value = value[: -len(ending)]
            notes.append("trailing line break")
            break
    return value, notes


def _escaped(text: str) -> str:
    """Escape an original for ``--show-originals`` to printable ASCII (sec. 13)."""
    out: list[str] = []
    for c in text:
        if " " <= c <= _PRINTABLE_MAX and c not in {"\\", "|"}:
            out.append(c)
        elif c == "\\":
            out.append("\\\\")
        elif ord(c) <= _BYTE_MAX:
            out.append(f"\\x{ord(c):02x}")
        elif ord(c) <= _BMP_MAX:
            out.append(f"\\u{ord(c):04x}")
        else:
            out.append(f"\\U{ord(c):08x}")
    return "".join(out)


def _outcome(value: str, *, arc: bool) -> str:
    """Return the parse outcome after ``parse (...): `` (section 14 item 5)."""
    try:
        if arc:
            deviations = parse_arc(value, max_length=MAX_INPUT_BYTES).payload.deviations
        else:
            deviations = parse(value, max_length=MAX_INPUT_BYTES).deviations
    except AuthResultsError as err:
        line = str(err.reason)
        if err.position is not None:
            line += f" at position {err.position}"
        if err.known_shape is not None:
            line += f" known shape {err.known_shape}"
        return line
    if not deviations:
        return "ok"
    return "ok deviations: " + ", ".join(d.value for d in Deviation if d in deviations)


def _report(value: str, result: Redaction, notes: list[str], *, show: bool) -> str:
    """Return the stderr report (section 6; section 13 with *show*)."""
    shown = "shown" if show else "not shown"
    lines = [_PREFIX + (_HEAD_SHOWN if show else _HEAD)]
    header = f"replaced (originals {shown}):"
    lines.append(header if result.replacements else header + " none")
    for rep, originals in zip(result.replacements, result.originals, strict=True):
        line = f"  {rep.placeholder} {rep.kind} x{rep.count}"
        if show:
            line += " <- " + " | ".join(_escaped(o) for o in originals)
        lines.append(line)
    lines.append(f"free text replaced with ...: {result.free_text}")
    if result.non_ascii or result.controls:
        lines.append(
            f"removed: {result.non_ascii} non-ASCII,"
            f" {result.controls} control or format characters"
        )
    crlf = value.count("\r\n")
    lf = value.count("\n") - crlf
    cr = value.count("\r") - crlf
    if crlf or lf or cr:
        lines.append(f"line breaks: {crlf} CRLF, {lf} LF, {cr} CR")
    if notes:
        lines.append("input: removed " + "; ".join(notes))
    lines.append("parse (original): " + _outcome(value, arc=result.arc))
    lines.append("parse (redacted): " + _outcome(result.text, arc=result.arc))
    return "".join(line + "\n" for line in lines)


def _run(
    argv: Sequence[str], stdin: BinaryIO, stdout: BinaryIO, stderr: BinaryIO
) -> int:
    args = list(argv)
    if args in (["-h"], ["--help"]):
        return _write_out(stdout, stderr, _USAGE)
    if args not in ([], ["--show-originals"]):
        with contextlib.suppress(OSError):
            stderr.write(_USAGE)
        return EXIT_USAGE
    data = stdin.read(MAX_INPUT_BYTES + 1)
    if len(data) > MAX_INPUT_BYTES:
        _say(stderr, _TOO_LONG)
        return EXIT_REFUSED
    value, notes = _strip(data.decode("utf-8", "surrogateescape"))
    result = redact(value)
    if not result.complete:
        _say(stderr, _EXHAUSTED)
        return EXIT_REFUSED
    output = result.text.encode("ascii") + b"\n"
    report = _report(value, result, notes, show=bool(args)).encode("ascii")
    code = _write_out(stdout, stderr, output)
    if code == EXIT_OK:
        try:
            stderr.write(report)
        except OSError:
            code = EXIT_INTERNAL  # stdout is complete; the report is missing
    return code


def _write_out(stdout: BinaryIO, stderr: BinaryIO, data: bytes) -> int:
    """Write and flush *data* to stdout; a failure there is exit 3 (sec. 16)."""
    try:
        stdout.write(data)
        stdout.flush()
    except OSError:
        _say(stderr, _NOT_WRITTEN)
        return EXIT_INTERNAL
    return EXIT_OK


def main(
    argv: Sequence[str], stdin: BinaryIO, stdout: BinaryIO, stderr: BinaryIO
) -> int:
    """Run the helper; return the exit code (0, 1 refused, 2 usage, 3 internal).

    Nothing reaches stdout unless the whole run succeeds, and no message
    holds input text (only ``--show-originals`` lists escaped originals).
    """
    try:
        return _run(argv, stdin, stdout, stderr)
    except Exception:  # noqa: BLE001 - every failure gets the fixed message
        _say(stderr, _INTERNAL)
        return EXIT_INTERNAL


if __name__ == "__main__":
    if sys.stdin is None or sys.stdout is None or sys.stderr is None:
        # A closed stream (17.7): the fixed message if stderr exists, exit 3.
        if sys.stderr is not None:
            _say(sys.stderr.buffer, _INTERNAL)
        raise SystemExit(EXIT_INTERNAL)
    raise SystemExit(
        main(sys.argv[1:], sys.stdin.buffer, sys.stdout.buffer, sys.stderr.buffer)
    )
