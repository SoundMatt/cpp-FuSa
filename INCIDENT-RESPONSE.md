# Incident Response Plan

cpp-FuSa is a development-tool library. This document describes how security
incidents and safety-critical defects are handled per IEC 62443-4-2 CR 6.2.1.

## Scope

Any confirmed vulnerability or defect in cpp-FuSa that could affect the safety
evidence produced by a project using the toolkit — false-clean reports, silent
data corruption, tampered audit packs, or incorrect ASIL/gap determinations.

## Reporting

Report security issues via the GitHub private-vulnerability-reporting feature or
by emailing matt@jellybaby.com with subject `[cpp-FuSa][SECURITY]`.

Do **not** open a public GitHub issue for security defects until a fix is available.

## Response SLAs

| Severity | Initial acknowledgement | Fix / workaround |
|---|---|---|
| Critical | 24 hours | 72 hours |
| High | 48 hours | 7 days |
| Medium/Low | 5 business days | 30 days |

## Severity Definitions

| Severity | Definition |
|---|---|
| **Critical** | Defect causes false-clean output on known-dangerous code, or allows arbitrary code execution via crafted input |
| **High** | Defect silently corrupts evidence files, produces incorrect ASIL determination, or exposes sensitive build environment data |
| **Medium** | Defect causes incorrect findings (false positives/negatives) not affecting safety-critical paths |
| **Low** | Documentation error, cosmetic issue, or low-impact behaviour deviation |

## Handling Steps

1. Triage and confirm the report.
2. Open a private security advisory on GitHub.
3. Develop and test a fix on a private branch.
4. Regenerate qualification evidence: `cpfusa qualify`, `cpfusa verify`, `cpfusa release`.
5. Issue a patch release and publish a CVE advisory if applicable.
6. Update `CHANGELOG.md` and notify downstream users via the GitHub release.

## Safety Impact Assessment

For any defect affecting analysis output:

1. Identify which rules or artifact generators are affected.
2. Determine which projects may have received false-clean evidence from the affected version.
3. Issue guidance to those projects to re-run `cpfusa check`, `cpfusa qualify`, and re-validate their evidence bundle.
4. Update `docs/tool-safety-manual.md` Known Limitations section if the root cause cannot be fully resolved.

## Post-Incident Review

A brief post-incident review is written for Critical/High events and stored in
`docs/security-reviews/`. The review documents:

- Root cause
- Impact scope (which commands, versions, rules affected)
- Fix applied
- Evidence regeneration steps taken
- Recommendations for prevention
