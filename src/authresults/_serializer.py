# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

r"""The canonical form written by ``AuthenticationResults.to_value`` (AU-Q17).

``id[ 1]; none`` or ``id[ 1]; method[/v]=result[ reason=V][ ptype.name=V]...``
on one line, single spaces, no comments, no folding. ``V`` is bare if it is
a token, or (for a property value) an address the parser reads back as one;
otherwise it is quoted with ``\`` before ``"`` and ``\``. HTAB is written
inside quotes (AU-Q40); every other control, and every space separator or
format character (AU-Q41), is ``CONTROL_CHAR`` and, with
``ascii_only``, non-ASCII is ``NON_ASCII``. A model the grammar cannot
express is ``SYNTAX`` (AU-Q33(b), AU-Q35, AU-Q26 consequence). Every error
has no position.
"""

from typing import TYPE_CHECKING

from ._errors import AuthResultsError, ErrorReason
from ._lexical import address_fault, is_lower_keyword, is_token
from ._tokenizer import control

if TYPE_CHECKING:
    from ._model import AuthenticationResults, Property, Result

_MAX_METHOD_VERSION = 999_999_999  # nine digits (AU-Q24)


def _fail(reason: ErrorReason) -> AuthResultsError:
    return AuthResultsError(reason)


def _checked(field: object, *, ascii_only: bool) -> str:
    """Return *field* if it is an exact ``str`` free of controls (HTAB aside)."""
    if type(field) is not str:
        raise _fail(ErrorReason.SYNTAX)
    for c in field:
        if c != "\t" and control(c):
            raise _fail(ErrorReason.CONTROL_CHAR)
    if ascii_only and not field.isascii():
        raise _fail(ErrorReason.NON_ASCII)
    return field


def _keyword(field: object, *, ascii_only: bool) -> str:
    word = _checked(field, ascii_only=ascii_only)
    if not is_lower_keyword(word):
        raise _fail(ErrorReason.SYNTAX)
    return word


def _value(field: object, *, ascii_only: bool, address: bool) -> str:
    text = _checked(field, ascii_only=ascii_only)
    if is_token(text) or (address and not address_fault(text)):
        return text
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _property(prop: "Property", *, ascii_only: bool) -> str:
    name = _keyword(prop.name, ascii_only=ascii_only)
    value = _value(prop.value, ascii_only=ascii_only, address=True)
    if prop.ptype is None:
        if name == "reason":
            raise _fail(ErrorReason.SYNTAX)
        return f"{name}={value}"
    return f"{_keyword(prop.ptype, ascii_only=ascii_only)}.{name}={value}"


def _method_version(version: object) -> str:
    if version is None:
        return ""
    if type(version) is not int or not 0 <= version <= _MAX_METHOD_VERSION:
        raise _fail(ErrorReason.SYNTAX)
    return f"/{version}"


def _resinfo(result: "Result", *, ascii_only: bool) -> str:
    parts = [
        _keyword(result.method, ascii_only=ascii_only),
        _method_version(result.method_version),
        "=",
        _keyword(result.result, ascii_only=ascii_only),
    ]
    if result.reason is not None:
        reason = _value(result.reason, ascii_only=ascii_only, address=False)
        parts.append(f" reason={reason}")
    parts.extend(" " + _property(p, ascii_only=ascii_only) for p in result.properties)
    return "".join(parts)


def serialize(model: "AuthenticationResults", *, ascii_only: bool) -> str:
    """Write *model* in the canonical form, or raise (see the module text)."""
    if (
        model.authserv_id is None
        or type(model.version) is not int
        or model.version != 1
    ):
        raise _fail(ErrorReason.SYNTAX)
    if model.none == bool(model.results):
        raise _fail(ErrorReason.SYNTAX)  # none with results, or neither
    parts = [_value(model.authserv_id, ascii_only=ascii_only, address=False)]
    if model.version_given:
        parts.append(" 1")
    if model.none:
        parts.append("; none")
    parts.extend("; " + _resinfo(r, ascii_only=ascii_only) for r in model.results)
    return "".join(parts)
