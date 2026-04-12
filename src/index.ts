/**
 * MITRE ATT&CK Technique ID Validator
 *
 * When LLMs generate ATT&CK technique IDs, they sometimes hallucinate.
 * This library validates IDs using a 3-tier classification:
 *
 * 1. Valid format + in allowed set -> verified (keep)
 * 2. Valid format + NOT in allowed set -> unverified (flag for human review)
 * 3. Invalid format -> stripped (hallucinated, discard)
 */

// Matches T followed by 4 digits, optionally .XXX sub-technique
const ATT_CK_PATTERN = /^T\d{4}(\.\d{3})?$/;

export interface Finding {
  id: string;
  title: string;
  description: string;
  mitre_techniques: string[];
  unverified_techniques?: string[];
  [key: string]: unknown;
}

export interface TechniqueSummary {
  technique_id: string;
  name: string;
  relevance: string;
}

export interface AnalysisResult {
  findings: Finding[];
  mitre_techniques_summary: TechniqueSummary[];
  [key: string]: unknown;
}

export interface ValidationResult {
  verified: string[];
  unverified: string[];
  stripped: string[];
}

/**
 * Validate a single technique ID against an allowed set.
 */
export function validateTechniqueId(
  id: string,
  allowedIds: Set<string>,
): 'verified' | 'unverified' | 'stripped' {
  if (!ATT_CK_PATTERN.test(id)) return 'stripped';
  if (allowedIds.has(id)) return 'verified';
  return 'unverified';
}

/**
 * Validate a list of technique IDs, returning categorized results.
 */
export function validateTechniqueIds(
  ids: string[],
  allowedIds: Set<string>,
): ValidationResult {
  const result: ValidationResult = { verified: [], unverified: [], stripped: [] };

  for (const id of ids) {
    const tier = validateTechniqueId(id, allowedIds);
    result[tier].push(id);
  }

  return result;
}

/**
 * Validate and filter an entire analysis result.
 *
 * - Findings: verified IDs stay in mitre_techniques, unverified moved to
 *   unverified_techniques, invalid IDs stripped
 * - Summary: only verified IDs with valid format are kept
 */
export function validateAnalysisResult(
  result: AnalysisResult,
  allowedIds: Set<string>,
): AnalysisResult {
  return {
    ...result,
    findings: result.findings.map((f) => validateFinding(f, allowedIds)),
    mitre_techniques_summary: result.mitre_techniques_summary.filter(
      (t) => ATT_CK_PATTERN.test(t.technique_id) && allowedIds.has(t.technique_id),
    ),
  };
}

function validateFinding(
  finding: Finding,
  allowedIds: Set<string>,
): Finding {
  const verified: string[] = [];
  const unverified: string[] = [];

  for (const id of finding.mitre_techniques) {
    if (!ATT_CK_PATTERN.test(id)) continue; // strip invalid
    if (allowedIds.has(id)) {
      verified.push(id);
    } else {
      unverified.push(id);
    }
  }

  const result: Finding = {
    ...finding,
    mitre_techniques: verified,
  };

  if (unverified.length > 0) {
    result.unverified_techniques = unverified;
  }

  return result;
}

/**
 * Check if a string is a valid ATT&CK technique ID format.
 * Does NOT check if the ID exists in the ATT&CK framework.
 */
export function isValidFormat(id: string): boolean {
  return ATT_CK_PATTERN.test(id);
}
