# Copyright 2026 Jess Rapakko
# SPDX-License-Identifier: Apache-2.0

"""Hypothesis profiles for the property and differential tests (PLAN.md 4).

- ``ci`` (the default): about 2,000 examples per property, for every push.
- ``nightly``: 100,000 examples per property, for the scheduled fuzz run
  (``.github/workflows/fuzz.yml``) or by hand.
- ``mutmut``: 200 derandomized examples, so a mutation run (CONTRIBUTING)
  stays affordable and repeatable; not for finding bugs.

Pick one with ``HYPOTHESIS_PROFILE=nightly``. Kept out of
``tests/conftest.py``, which is pinned by hash (PLAN.md 6, AL3b row).
"""

import os
from typing import Final

from hypothesis import HealthCheck, settings

for _name, _examples in (("ci", 2_000), ("nightly", 100_000)):
    settings.register_profile(
        _name,
        max_examples=_examples,
        deadline=None,  # timing varies by machine; the case table has timing cases
        print_blob=True,
        suppress_health_check=(HealthCheck.too_slow,),
    )
settings.register_profile(
    "mutmut",
    max_examples=200,
    derandomize=True,
    database=None,
    deadline=None,
    suppress_health_check=(HealthCheck.too_slow,),
)

PROFILE: Final = os.environ.get("HYPOTHESIS_PROFILE", "ci")
settings.load_profile(PROFILE)

# Seconds per test for pytest-timeout: the pyproject default (120) under
# ``ci``; none under ``nightly``, whose run time scales with the examples.
TIMEOUT: Final = 0 if PROFILE == "nightly" else 120
