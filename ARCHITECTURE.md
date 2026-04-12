# Architecture

## Why 3 Tiers Instead of Binary

A binary valid/invalid classification loses important signal. Consider:

- `T1566` -- valid format, known technique. Clearly good.
- `T9999` -- valid format, but not in your curated list. Is it hallucinated? Maybe. Or maybe the LLM correctly identified a technique you didn't anticipate. You need a human to check.
- `MITRE-FAKE-001` -- not even close to ATT&CK format. Definitely hallucinated. Discard.

Binary classification forces you to either keep `T9999` (risky) or drop it (potentially losing a valid finding). The 3-tier system lets you keep high-confidence results clean while flagging uncertain ones for review.

## Why Regex for Format Validation

ATT&CK technique IDs follow a strict format: `T` followed by exactly 4 digits, optionally followed by `.` and exactly 3 digits for sub-techniques. This is deterministic and instant to check with a regex.

The pattern `/^T\d{4}(\.\d{3})?$/` catches:
- Missing `T` prefix
- Wrong digit counts (T123, T12345)
- Non-standard separators (T1566-001 instead of T1566.001)
- Completely fabricated identifiers (MITRE-001, ATT-CK-1566)

No network calls, no database lookups, no external dependencies. The format check runs in microseconds.

## Why Per-Incident-Type Allowed Lists

The full ATT&CK matrix has 200+ techniques. Validating against the entire set would catch format errors but wouldn't help with relevance. A phishing incident shouldn't reference hardware firmware techniques.

By curating an allowed set per incident type or assessment scope, you get:
- **Smaller surface area:** fewer techniques means fewer false "verified" results
- **Context-appropriate validation:** only techniques relevant to the analysis pass through
- **Explicit scope boundaries:** the allowed set documents what your analysis considers in-scope

The tradeoff is maintenance. Allowed sets need updating as ATT&CK evolves and as your analysis scope changes.

## Known Limitations

1. **No live ATT&CK database validation.** This library does not fetch or embed the full ATT&CK technique catalog. It validates format and checks against a set you provide. If you need full-catalog validation, combine this with a technique list from the ATT&CK STIX data or the ATT&CK API.

2. **Curated lists require maintenance.** Your allowed sets need to be updated when MITRE adds, deprecates, or renumbers techniques. This is a manual step.

3. **Sub-technique depth is fixed.** The format check allows one level of sub-technique (T1566.001) matching ATT&CK's current structure. If ATT&CK ever adds deeper nesting, the regex would need updating.

4. **No semantic validation.** This library checks IDs, not whether the technique makes sense in context. A verified `T1566` (Phishing) in a finding about disk encryption is syntactically correct but semantically wrong. That's a different problem.
