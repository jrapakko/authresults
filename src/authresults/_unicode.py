# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""Space separators and format characters, refused everywhere (AU-Q41).

The code points of general category Zs, Zl, Zp (except U+0020 SPACE) and
Cf, as sorted, non-overlapping, inclusive ranges. Hard-coded from one
Unicode version, so the result does not depend on the running Python's
``unicodedata`` (which the import allowlist excludes anyway).
"""

UNICODE_VERSION = "17.0.0"

RANGES: tuple[tuple[int, int], ...] = (
    (0x00A0, 0x00A0),
    (0x00AD, 0x00AD),
    (0x0600, 0x0605),
    (0x061C, 0x061C),
    (0x06DD, 0x06DD),
    (0x070F, 0x070F),
    (0x0890, 0x0891),
    (0x08E2, 0x08E2),
    (0x1680, 0x1680),
    (0x180E, 0x180E),
    (0x2000, 0x200F),
    (0x2028, 0x202F),
    (0x205F, 0x2064),
    (0x2066, 0x206F),
    (0x3000, 0x3000),
    (0xFEFF, 0xFEFF),
    (0xFFF9, 0xFFFB),
    (0x110BD, 0x110BD),
    (0x110CD, 0x110CD),
    (0x13430, 0x1343F),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0001, 0xE0001),
    (0xE0020, 0xE007F),
)


def is_space_or_format(c: str) -> bool:
    """Return True if the character *c* is in ``RANGES`` (binary search)."""
    point = ord(c)
    low = 0
    high = len(RANGES)
    while low < high:
        middle = (low + high) // 2
        first, last = RANGES[middle]
        if point < first:
            high = middle
        elif point > last:
            low = middle + 1
        else:
            return True
    return False
