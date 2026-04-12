# @protectyr-labs/attack-validator

MITRE ATT&CK technique ID validator for LLM outputs. Catches hallucinated technique IDs using a 3-tier classification system.

## Why This Exists

When LLMs generate security analysis, they reference MITRE ATT&CK technique IDs. Sometimes those IDs are correct. Sometimes they look right but don't exist. Sometimes they're completely made up.

This library validates LLM-generated technique IDs against a curated allowed set and classifies each one into three tiers:

| Tier | Meaning | Action |
|------|---------|--------|
| **verified** | Valid format AND in your allowed set | Keep in output |
| **unverified** | Valid format but NOT in your allowed set | Flag for human review |
| **stripped** | Invalid format (hallucinated) | Discard from output |

The "unverified" tier is the key insight: a technique ID like `T1234` has valid ATT&CK format and might be a real technique the LLM correctly identified -- it just wasn't in your curated per-incident list. That's different from `MITRE-FAKE` which is clearly hallucinated. Binary valid/invalid misses this distinction.

## Quick Start

```bash
npm install @protectyr-labs/attack-validator
```

```typescript
import { validateTechniqueIds } from '@protectyr-labs/attack-validator';

// Curate an allowed set per incident type or assessment scope
const allowed = new Set(['T1566', 'T1566.001', 'T1078', 'T1059']);

// Validate what the LLM produced
const result = validateTechniqueIds(
  ['T1566', 'T9999', 'HALLUCINATED', 'T1078'],
  allowed,
);

console.log(result);
// {
//   verified:   ['T1566', 'T1078'],
//   unverified: ['T9999'],
//   stripped:   ['HALLUCINATED']
// }
```

## API

### `validateTechniqueId(id, allowedIds)`

Validate a single technique ID. Returns `'verified'`, `'unverified'`, or `'stripped'`.

```typescript
validateTechniqueId('T1566', allowed);    // 'verified'
validateTechniqueId('T9999', allowed);    // 'unverified'
validateTechniqueId('FAKE', allowed);     // 'stripped'
```

### `validateTechniqueIds(ids, allowedIds)`

Validate an array of IDs. Returns `{ verified: string[], unverified: string[], stripped: string[] }`.

### `validateAnalysisResult(result, allowedIds)`

Validate a full analysis result object containing findings and a technique summary:

- Findings: verified IDs stay in `mitre_techniques`, unverified go to `unverified_techniques`, invalid IDs are stripped
- Summary: only entries with verified technique IDs are kept

```typescript
const validated = validateAnalysisResult({
  findings: [{
    id: 'F1',
    title: 'Phishing detected',
    description: 'Email-based attack',
    mitre_techniques: ['T1566', 'T9999', 'NOT-REAL'],
  }],
  mitre_techniques_summary: [
    { technique_id: 'T1566', name: 'Phishing', relevance: 'high' },
    { technique_id: 'T9999', name: 'Unknown', relevance: 'low' },
  ],
}, allowed);

// validated.findings[0].mitre_techniques => ['T1566']
// validated.findings[0].unverified_techniques => ['T9999']
// validated.mitre_techniques_summary => [{ technique_id: 'T1566', ... }]
```

### `isValidFormat(id)`

Check if a string matches ATT&CK technique ID format (`T` + 4 digits, optionally `.` + 3 digits for sub-techniques). Does not check whether the ID actually exists.

```typescript
isValidFormat('T1566');     // true
isValidFormat('T1566.001'); // true
isValidFormat('T123');      // false
isValidFormat('MITRE-01');  // false
```

## The 3-Tier Classification

**Tier 1 - Verified:** The technique ID has valid ATT&CK format (`TNNNN` or `TNNNN.NNN`) and exists in your curated allowed set. This is a high-confidence match. Keep it in your output.

**Tier 2 - Unverified:** The technique ID has valid format but is not in your allowed set. This could mean: (a) the LLM correctly identified a real technique you didn't include in your set, or (b) the LLM generated a plausible but non-existent ID. Flag these for human review rather than silently discarding them.

**Tier 3 - Stripped:** The string doesn't match ATT&CK format at all. The LLM hallucinated something that isn't even close. Discard these.

## Development

```bash
git clone https://github.com/protectyr-labs/attack-validator.git
cd attack-validator
npm install
npm test
npm run build
```

## License

MIT
