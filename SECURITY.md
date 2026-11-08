# Security policy

## Supported versions

Only the latest minor release receives security fixes.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's private vulnerability
reporting: open the repository's **Security** tab and choose **Report a
vulnerability**. Do not open a public issue.

You can expect an acknowledgement within a few days. Fixes are released as a
new version and credited in the changelog unless you ask otherwise.

## What counts as a vulnerability

`authresults` parses attacker-controlled input. Any of these is in scope:

- An exception other than `AuthResultsError` escaping `parse()` or
  `parse_arc()` for any `str` input (including `RecursionError` or
  `MemoryError` triggered by the input).
- A mis-parse that creates, changes or hides a result, for example text inside a
  comment or quoted string being read as a method, result or property.
- Super-linear running time in the length of the input.
- Input text appearing in an error message.
- Output from the serializer that could inject a header (CR, LF or other
  control characters).
- A miss in `python -m authresults.redact` that lets personal data through.
  Report it privately, never in a header shape issue, because the reproduction
  contains the data.
