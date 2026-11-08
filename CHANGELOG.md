# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- README: how it compares to authres, with each difference tested; the default
  limits.

## [0.1.0] - 2026-11-08

First release.

### Added

- `parse()` for one RFC 8601 `Authentication-Results` value and `parse_arc()`
  for one RFC 8617 `ARC-Authentication-Results` value (RFC 8617 is
  Experimental), returning frozen, slotted dataclasses: `AuthenticationResults`,
  `ArcAuthenticationResults`, `Result` and `Property`.
- Keyword-only limits and flags; defaults `max_length=8192`, `max_results=64`,
  `max_properties=64`, `max_comment_depth=16`, `ascii_only=True`,
  `strict_syntax=False`, `require_registered=False`.
- A closed error set: `AuthResultsError` (a `ValueError`) with `reason`
  (`ErrorReason`, 18 members), `position` and `known_shape` (`KnownShape`,
  5 members, for refused shapes known from real software). Messages never
  contain input text.
- `Deviation` (5 members) for accepted real-world departures from the grammar,
  recorded on the result and refused under `strict_syntax=True`.
- `registered` flags from a frozen snapshot of the IANA Email Authentication
  Parameters registries (last updated 2026-05-22).
- `AuthenticationResults.to_value()`, a canonical serializer that refuses CR,
  LF and other control characters.
- Accessors `results_for()`, `Result.get()` and `Result.get_unique()`; helpers
  `domain_of()` and `ascii_domain()`.
- `python -m authresults.redact`: a best-effort helper that replaces personal
  data in one header value before it is posted in a bug report.
- `py.typed`: the package is fully typed.

[Unreleased]: https://github.com/jrapakko/authresults/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/jrapakko/authresults/releases/tag/v0.1.0
