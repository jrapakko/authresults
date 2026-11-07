# Refused shapes

Real-world `Authentication-Results` and `ARC-Authentication-Results` values that
`authresults` refuses, or reads differently from what their producer meant. Each
entry was found by the AL3c vendor sweep and decided by an answered question in
`docs/plan.md` section 10.

Every refused entry has a `KnownShape` member (AU-Q52). When a refusal matches
the entry's detection rule, `AuthResultsError.known_shape` is set to that member;
otherwise it is `None`. The tag holds no input text, leaves `reason` and
`position` unchanged, and does not appear in `str(err)`. Detection runs only on
the error path, at the parser branch the entry names, in the same single pass,
and looks ahead at most one token past the refusing position (AU-Q56).

Each entry also has a pinning case in `tests/cases_refused.py`, which pins
today's outcome (including `known_shape`) and carries the accepting expectation
in a comment. To re-enable a shape: amend that case (plan 6.4), change the named
parser branch, and move the entry to "Re-enabled shapes". The `KnownShape` member
then stays, never set, until a minor release removes it (AU-Q52).

Conventions:

- Values are rewritten to RFC 2606/6761 names and RFC 5737/3849 addresses
  (AU-Q19, AU-Q44). `\r\n` is CRLF, `\t` is TAB.
- Positions are 0-based offsets into the rewritten value.
- "Lenient" is the default call; "strict" is `strict_syntax=True`.
- Parser functions are in `src/authresults/_parser.py`.

## Refused shapes

### Exim ARC-Authentication-Results leading property

- **Source:** Exim, commit `d46a6727798fc48d1756190a6d46d19216348c25`.
  Format string `" i=%d; %s; smtp.remote-ip=%s;\r\n\t%b"` in
  `arc_sign_append_aar`
  (<https://github.com/Exim/exim/blob/d46a6727798fc48d1756190a6d46d19216348c25/src/src/miscmods/arc.c>),
  and the expected test output
  (<https://github.com/Exim/exim/blob/d46a6727798fc48d1756190a6d46d19216348c25/test/mail/4560.a>,
  `ARC-Authentication-Results: i=1; test.ex; smtp.remote-ip=127.0.0.1;` then
  `arc=none`). Read 2026-11-07.
- **Rewritten value** (`parse_arc`): `i=1; example.com; smtp.remote-ip=192.0.2.1;\r\n\tarc=none`
- **Today:** lenient `SYNTAX` at 22 (the `.` that ends the keyword `smtp` where a
  method belongs); strict the same.
- **Decided by:** AU-Q46 (refuse; revisit after 0.1.0 if callers need it).
- **What would accept it:** a model field for properties outside any result,
  plus a new deviation for a leading property. Branch: `_resinfo`, where the
  method keyword (with any method version) is not followed by `=`. The tag
  comes from `_dot_shape` called with `first=True`. That happens only when the
  method keyword is followed directly by the `.` (no CFWS, no method version)
  and the value came through `parse_arc`.
- **Detection rule:** `parse_arc` only; the refusal is that `SYNTAX`, in the
  first resinfo of the payload, at a `.` directly after the method keyword.
  One token of lookahead (AU-Q56) decides it: the token after the `.` is a
  keyword, and the next character after it and any CFWS is `=` (a
  `ptype.property=` where a method belongs). The token must follow the `.`
  directly. CFWS right after the `.` gives no tag: this is deliberate, and
  `parse_arc("i=1; example.com; smtp.(c)remote-ip=192.0.2.1; arc=none")`
  keeps `SYNTAX` at 22 untagged (case
  `exim arc leading property comment after the dot`).
- **Pinning case:** `refused exim arc leading property`
- **KnownShape:** `EXIM_ARC_LEADING_PROPERTY` = `"exim_arc_leading_property"`

### Bare domain between results

- **Source:** Microsoft Learn, "How email authentication works in Microsoft 365",
  section "Composite authentication", the example headers
  (<https://learn.microsoft.com/en-us/defender-office-365/email-authentication-about>,
  page source commit `eb2eb30637011dd57e57d2f48077c61637726035`). The shape
  appears in all four distinct example blocks on that page, and only there.
  Read 2026-11-07.
- **Rewritten value:** `spf=none (sender IP is 192.0.2.8)\r\n  smtp.mailfrom=example.net; example.com; dkim=pass\r\n  (signature was verified) header.d=example.net;\r\n  example.com; dmarc=none action=none header.from=example.com;\r\n  compauth=fail reason=001`
- **Today:** lenient `SYNTAX` at 71 (the `.` of the first stray `example.com`);
  strict `DEVIATION` at 0 (`MISSING_AUTHSERV_ID` is met first, so the strict
  refusal carries no tag).
- **Decided by:** AU-Q48 (refuse and document).
- **What would accept it:** a new deviation for a stray domain between results
  that skips the domain. Branch: `_resinfo`, where the method keyword is not
  followed by `=`. The tag comes from `_dot_shape` called with `first=False`,
  only when the method keyword is followed directly by the `.` (no CFWS, no
  method version).
- **Detection rule:** `parse` or `parse_arc`; the refusal is that `SYNTAX`, in a
  resinfo after the first, at a `.` directly after the method keyword. One
  token of lookahead (AU-Q56) decides it: the token after the `.` is the rest
  of the domain, labels separated by single dots, and the next character after
  it and any CFWS is `;` or the end of the value. Every label, the method
  keyword included, must be an RFC 5321 `sub-domain` (Let-dig [Ldh-str]: no
  leading or trailing `-`), and the last label must hold at least one letter.
  Near misses keep `SYNTAX` at the `.` with no tag:
  `mx.example; dkim=pass; example.-com; spf=pass`,
  `mx.example; dkim=pass; example.com-` and `mx.example; dkim=pass; example.123`
  (each at 30; cases `stray domain near miss label starts with -`,
  `stray domain near miss label ends with -` and
  `stray domain near miss all-digit last label`).
- **Pinning case:** `refused microsoft domain between results`
- **KnownShape:** `STRAY_DOMAIN_BETWEEN_RESULTS` = `"stray_domain_between_results"`

### Job ID appended to the authserv-id

- **Source:** OpenDKIM, commit `ba29fa57b2455143dd86973c2229d6f7b8e16d9b`,
  `opendkim/opendkim.c` lines 14535 to 14558: with `AuthservIDWithJobID` on, the
  authserv-id is followed by `/` and the MTA job ID, then `;`
  (<https://github.com/trusteddomainproject/OpenDKIM/blob/ba29fa57b2455143dd86973c2229d6f7b8e16d9b/opendkim/opendkim.c#L14535-L14558>).
  OpenDMARC writes the same prefix (commit
  `9cebf724d601452d1a671ed5331551dbc18df83a`, `opendmarc/opendmarc.c` lines 3745
  to 3753). The option is opt-in. Read 2026-11-07.
- **Rewritten value:** `mail.example.com/4ABCD1234;\r\n\tdkim=none` (built:
  `4ABCD1234` is a placeholder queue ID; OpenDKIM's LF TAB fold written as CRLF
  TAB).
- **Today:** lenient `SYNTAX` at 16 (the `/`); strict the same.
- **Decided by:** AU-Q50 (refuse, document, leave the option off).
- **What would accept it:** keeping the job ID (a new model field, or a new
  deviation with the authserv-id cut at the `/`). Branch: `_payload`, where no
  `;` follows the authserv-id (and the optional version). The tag comes from
  `_id_shape`: a `/` at the position where the `;` belongs, directly after an
  unquoted authserv-id.
- **Detection rule:** `parse` or `parse_arc`; the refusal is that `SYNTAX` in
  `_payload`, at a `/` directly after an unquoted authserv-id (one read as an
  id, not as a method, per AU-Q39), with no CFWS between them. No lookahead.
- **Pinning case:** `refused opendkim authserv-id job id`
- **KnownShape:** `AUTHSERV_ID_JOB_ID` = `"authserv_id_job_id"`

### Authserv-id with no results and no `none`

- **Source:** Exim, commit `d46a6727798fc48d1756190a6d46d19216348c25`, the
  authresults expansion in `src/src/expand.c`: it writes the authserv-id and
  `"; none"`, then `yield->ptr -= 6;` with the comment "ignore tha ": none" for
  now", then appends each result
  (<https://github.com/Exim/exim/blob/d46a6727798fc48d1756190a6d46d19216348c25/src/src/expand.c>).
  Stalwart mail-auth (commit `9801cd0186c3f21de620c1e0da35382c8c3e9ddf`,
  `src/common/auth_results.rs`) writes the hostname and then the results, so it
  gives the same shape with no results. Inferred from source, not seen in real
  output. Read 2026-11-07.
- **Rewritten value:** `mail.example.com`
- **Today:** lenient `SYNTAX` at 16 (`len(value)`); strict the same.
- **Decided by:** AU-Q51 (refuse for now; quick to change).
- **What would accept it:** reading it as `none` (or as an empty result list)
  with a new deviation for the missing `; none`. Branch: `_payload`, where no
  `;` follows the authserv-id. The tag comes from `_id_shape`: the end of the
  value at the position where the `;` belongs, with no version given. A comment
  at that branch names this entry (AU-Q51).
- **Detection rule:** `parse` or `parse_arc`; the refusal is that `SYNTAX` in
  `_payload` at `len(value)`: the payload is an authserv-id (token or quoted,
  read as an id) followed only by optional CFWS. A value that is only CFWS, an
  authserv-id with a version, or an authserv-id followed by `;` does not match.
  This also tags older cases of the same shape (`only id`, `only id short`,
  `none alone is an authserv-id`, `al3b one-letter id alone`,
  `parse max_length=1 at N`, `parse max_length=2 at N`), as AU-Q56 confirms.
  No lookahead: the parser is already at the end of the value.
- **Pinning case:** `refused exim authserv-id only`
- **KnownShape:** `AUTHSERV_ID_ONLY` = `"authserv_id_only"`

### Received-SPF keys written as results

- **Source:** Mimecast Support, "Policies - DNS Authentication Overview"
  (updated 2026-07-30), section "Confirming Your Configured Checks are Taking
  Place"
  (<https://mimecastsupport.zendesk.com/hc/en-us/articles/34000468841107-Policies-DNS-Authentication-Overview>;
  the HTML page sits behind a bot check, so the body was read from the public
  article API,
  <https://mimecastsupport.zendesk.com/api/v2/help_center/en-us/articles/34000468841107.json>).
  One illustrative example. Read 2026-11-07.
- **Rewritten value:** `mimecast.com; spf=pass (spfCheck: domain of _spf.example.com designates 192.0.2.195 as permitted sender) client-ip=192.0.2.195; envelope-from=sender@example.com; helo=mail.example.com; dkim=pass header.i=@example.com; dmarc=pass (p=allow dis=allow) header.from=example.com`.
  As published, the page has a typo, `envelope- from` (a space after the
  hyphen); the case fixes it. As published, the value is `SYNTAX` at 128 in this
  rewrite: the start of the keyword `envelope-`, which ends in `-` (G3). That
  refusal is untagged, because `envelope-` is not in the key list.
- **Today:** lenient `SYNTAX` at 148: after the `;`, `envelope-from` is read as
  a method, `sender` as its result, and the `@` fails the required CFWS after a
  result (G4). Strict `DEVIATION` at 105: the bare `client-ip` inside the spf
  result (`BARE_PROPERTY`) is met first.
- **Decided by:** AU-Q54 (refuse, log and tag; accepting it by moving the keys
  onto the preceding result across `;` was rejected).
- **What would accept it:** not planned. It would need a new deviation and a
  parser change that attaches `key=value` resinfos to the preceding result.
  Branch: `_resinfo`. For a resinfo that follows a `;` and whose method
  keyword is a key, the reading from the `=` onward (`_result`, which calls
  `_items`) runs inside a `try`, and any `SYNTAX` it raises gets the tag; other
  reasons are left untagged. For this value the refusal is the required-CFWS
  check after the result keyword in `_items`. For other key values it can be
  another check in the same reading (for example `client-ip=192.0.2.1` fails at
  the `.` after the result `192`).
- **Detection rule:** `parse` or `parse_arc`; the refusal is a `SYNTAX` raised
  while reading a resinfo that follows a `;`, and that resinfo's method token
  (the token after the `;` and before `=`) is one of the RFC 7208 section 9.1
  keys `client-ip`, `envelope-from`, `helo`, `receiver`, `identity`,
  `mechanism` or `problem`, compared ASCII case-insensitively. The method token
  is already read when the refusal happens, so the rule looks ahead at most one
  token (AU-Q56). A key resinfo that parses (`identity=mailfrom`) is not
  refused and is not tagged. Edges:
  - A key with a method version is still a key: `helo/1=a.b` is tagged
    (`SYNTAX` at the `.` after `a`; case `au-q54 key with method version`).
  - A refusal before the key's `=` is outside the rule: `client-ip.x=1` is
    refused at the `.` after the key, in `_resinfo`, and is not tagged (case
    `au-q54 key followed by a dot`).
  - Strict: the documented value's first refusal is the `BARE_PROPERTY`
    `DEVIATION` at `client-ip`. It is not after a `;`, so it carries no tag
    (`refused mimecast spf details as results strict`). When no deviation
    comes first, strict gives the same tagged `SYNTAX`
    (`au-q54 receiver key strict` in `tests/cases_grammar.py`).
  - Coverage of the key list and case: `au-q54 receiver key`,
    `au-q54 key compared case-insensitively` (`HELO=`) and
    `au-q54 identity key that parses`.
- **Pinning case:** `refused mimecast spf details as results`
- **KnownShape:** `SPF_DETAILS_AS_RESULTS` = `"spf_details_as_results"`

## Read differently from what the producer meant (accepted, no KnownShape)

These values parse, but not as the producer meant. They are not refused, so they
have no `KnownShape` (AU-Q52b: accepted shapes are visible through
`deviations`).

### Missing `;` between results (Zoho)

- **Source:** Zoho Mail community, "Authentication-results Header format
  incorrect", a user's report that the header "is missing a required
  semi-colon" between results
  (<https://help.zoho.com/portal/en/community/topic/authentication-results-header-format-incorrect>).
  The page renders with script; it was read through WebFetch, so its whitespace
  is not byte-verified. Read 2026-11-07.
- **Rewritten value:** `mx.zoho.com;\r\n dkim=pass\r\n spf=pass (zoho.com: domain of _spf.example.net designates 192.0.2.169 as permitted sender)\r\n smtp.mailfrom=sender@example.net;`
- **Today:** lenient parses as one result, `dkim=pass`, with a bare property
  `spf=pass` and `smtp.mailfrom` (unregistered for dkim), deviations
  `BARE_PROPERTY` and `TRAILING_SEMICOLON`; `results_for("spf")` is empty, so no
  spf pass is created. Strict `DEVIATION` at 27 (the bare `spf`).
- **Decided by:** AU-Q49 (keep the current reading; the README notes that a bare
  property named like a registered method signals a missing `;`).
- **What would read it as meant:** treating a bare property whose name is a
  method keyword followed by `=` and a result keyword as a new resinfo. Branch:
  the bare-property path in `_items` / `_bare`. Not planned.
- **Pinning case:** `refused zoho missing semicolon`

## Re-enabled shapes

None yet.

## Doc layout artefacts and doc typos (no case)

Values whose refusal comes from how a page laid them out or from a slip in the
page, not from what the software writes. They have no case and no `KnownShape`.

- **Microsoft Learn, "Configure trusted ARC sealers"**
  (<https://learn.microsoft.com/en-us/defender-office-365/email-authentication-arc-configure>,
  read 2026-11-07): the `ARC-Authentication-Results: i=2; mx.microsoft.com 1; ...`
  and `Authentication-Results: spf=fail (sender IP is ...) ...` examples break
  lines with no leading whitespace on the continuation lines. Joined with CRLF
  as printed, both are `CONTROL_CHAR` at the first CRLF (AU-Q38 rule 1). With
  one SP added after each line break they parse with known deviations
  (`BARE_PROPERTY`; and `MISSING_AUTHSERV_ID` for the second).
- **Oracle EPM Cloud, "DKIM Support"**, a header written by Proofpoint
  (<https://docs.oracle.com/en/cloud/saas/enterprise-performance-management-common/cgsad/6_house_keeping_tasks_dkim_support_epm_cloud_oci.html>,
  read 2026-11-07): every line of the code block, the field name included, has
  the same indentation, so the continuation lines carry no fold whitespace of
  their own; read that way it is `CONTROL_CHAR` at the first CRLF. The ptype
  `smptp` in `smptp.mailfrom` is a typo on the page (with folds repaired it
  parses, `registered=False`).
- **Google SecOps, Gmail integration, JSON result example**
  (<https://docs.cloud.google.com/chronicle/docs/soar/marketplace-integrations/gmail>,
  read 2026-11-07): `i=1; mx.google.com;       dkim=pass header.i=@labilfrom=sender@example.com;       dara=pass header.i=@example.com`
  is spliced or damaged by redaction (`@labilfrom=` followed by a second
  address). The page has `example@example.com` there; the value above
  rewrites it to `sender@example.com` (the local-part only). It is `SYNTAX`
  at 55, the `=` inside `@labilfrom=...` after the first `@` (the address
  check stops there), lenient and strict. Folds were turned into space runs.
- **Cisco, "User Guide for AsyncOS 15.0 for Cisco Secure Email Gateway",
  chapter "Email Authentication", section "DKIM Verification Checks Performed by
  AsyncOS"**
  (<https://www.cisco.com/c/en/us/td/docs/security/esa/esa15-0/user_guide/b_ESA_Admin_Guide_15-0/b_ESA_Admin_Guide_12_1_chapter_010110.html>,
  read through WebFetch 2026-11-07): three examples of the form
  `example1.com header.from=From:user123@example.com; dkim=pass (signature verified)`
  (the others end in `dkim=pass (partially verified [1000 bytes])` and
  `dkim=permfail (body hash did not verify)`). A doc mock-up (AU-Q55): no `;`
  after the authserv-id, a property before any method, and the header name
  `From:` pasted into the value. `SYNTAX` at the `h` of `header.from` (13 on one
  line), lenient and strict. Cisco's own PDF output (the vendor case
  `vendor cisco esa dmarc`) is well formed.
