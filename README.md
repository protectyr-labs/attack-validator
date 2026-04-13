# attack-validator

> Catch hallucinated MITRE ATT&CK IDs in LLM output.

[![CI](https://github.com/protectyr-labs/attack-validator/actions/workflows/ci.yml/badge.svg)](https://github.com/protectyr-labs/attack-validator/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue.svg)](https://www.typescriptlang.org/)

LLMs generating security analysis sometimes hallucinate technique IDs. This validates them in 3 tiers:

| Tier | Meaning | Action |
|------|---------|--------|
| **verified** | Valid format AND in your allowed set | Keep in output |
| **unverified** | Valid format but unknown -- flag for human review | May be a real technique you didn't list |
| **stripped** | Invalid format -- discard | Hallucinated garbage |

## Quick Start

```bash
npm install @protectyr-labs/attack-validator
```

```typescript
import { validateTechniqueIds } from '@protectyr-labs/attack-validator';

const allowed = new Set(['T1566', 'T1566.001', 'T1078', 'T1059']);

const result = validateTechniqueIds(
  ['T1566', 'T9999', 'HALLUCINATED', 'T1078'],
  allowed,
);

// result.verified   => ['T1566', 'T1078']
// result.unverified => ['T9999']          -- valid format, not in set
// result.stripped   => ['HALLUCINATED']   -- invalid format
```

## Why This?

- **3 tiers, not binary** -- unverified IDs might be real techniques the model correctly found
- **Regex format validation** -- instant, deterministic, no API calls
- **Per-incident-type allowed lists** -- reduce hallucination surface by scoping what's expected
- **Full analysis validation** -- `validateAnalysisResult()` processes findings + technique summaries in one call

## API

| Function | Description |
|----------|-------------|
| `validateTechniqueId(id, allowedIds)` | Single ID -- returns `'verified'`, `'unverified'`, or `'stripped'` |
| `validateTechniqueIds(ids, allowedIds)` | Array of IDs -- returns categorized object |
| `validateAnalysisResult(result, allowedIds)` | Full analysis object -- moves unverified to separate field, strips invalid |
| `isValidFormat(id)` | Format check only (`TNNNN` or `TNNNN.NNN`) |

## Limitations

- **Curated lists only** -- does not validate against the full ATT&CK database
- **Manual maintenance** -- allowed lists need updating as ATT&CK evolves
- **Format-only validation** -- a valid-format ID like `T9999` may not exist in ATT&CK

## See Also

- [prompt-shield](https://github.com/protectyr-labs/prompt-shield) -- detect prompt injection before LLM processing

## License

MIT
