import {
  validateTechniqueIds,
  validateAnalysisResult,
  isValidFormat,
} from '../src/index';

// Define an allowed set of technique IDs for this analysis context.
// In practice, curate this per incident type or assessment scope.
const allowedIds = new Set([
  'T1566',     // Phishing
  'T1566.001', // Phishing: Spearphishing Attachment
  'T1566.002', // Phishing: Spearphishing Link
  'T1078',     // Valid Accounts
  'T1059',     // Command and Scripting Interpreter
  'T1059.001', // PowerShell
  'T1053',     // Scheduled Task/Job
]);

// --- Example 1: Validate a list of IDs ---

console.log('=== Validate technique IDs ===\n');

const llmOutput = ['T1566', 'T1059.001', 'T9999', 'MITRE-FAKE', 'T1078'];

const result = validateTechniqueIds(llmOutput, allowedIds);

console.log('Input:', llmOutput);
console.log('Verified (keep):', result.verified);
console.log('Unverified (flag for review):', result.unverified);
console.log('Stripped (hallucinated):', result.stripped);

// --- Example 2: Validate full analysis result ---

console.log('\n=== Validate analysis result ===\n');

const analysisResult = {
  findings: [
    {
      id: 'F-001',
      title: 'Email gateway bypass',
      description: 'Attacker bypassed email security controls',
      mitre_techniques: ['T1566', 'T1566.001', 'T9999', 'HALLUCINATED-ID'],
    },
    {
      id: 'F-002',
      title: 'Credential reuse',
      description: 'Valid credentials used for lateral movement',
      mitre_techniques: ['T1078', 'T1234'],
    },
  ],
  mitre_techniques_summary: [
    { technique_id: 'T1566', name: 'Phishing', relevance: 'high' },
    { technique_id: 'T9999', name: 'Unknown Technique', relevance: 'medium' },
    { technique_id: 'NOT-REAL', name: 'Fake', relevance: 'none' },
  ],
};

const validated = validateAnalysisResult(analysisResult, allowedIds);

for (const finding of validated.findings) {
  console.log(`${finding.id}: ${finding.title}`);
  console.log('  Verified techniques:', finding.mitre_techniques);
  if (finding.unverified_techniques) {
    console.log('  Unverified techniques:', finding.unverified_techniques);
  }
}

console.log('\nSummary (verified only):', validated.mitre_techniques_summary);

// --- Example 3: Format check ---

console.log('\n=== Format validation ===\n');

const candidates = ['T1566', 'T1566.001', 'T123', 'MITRE-001', 'T12345', ''];
for (const c of candidates) {
  console.log(`  "${c}" => ${isValidFormat(c) ? 'valid format' : 'invalid format'}`);
}
