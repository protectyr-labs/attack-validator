import { describe, it, expect } from 'vitest';
import {
  validateTechniqueId,
  validateTechniqueIds,
  validateAnalysisResult,
  isValidFormat,
} from '../src/index';

const ALLOWED = new Set(['T1566', 'T1566.001', 'T1078', 'T1059']);

describe('isValidFormat', () => {
  it('accepts T followed by 4 digits', () => {
    expect(isValidFormat('T1566')).toBe(true);
  });
  it('accepts sub-techniques', () => {
    expect(isValidFormat('T1566.001')).toBe(true);
  });
  it('rejects invalid formats', () => {
    expect(isValidFormat('MITRE-1566')).toBe(false);
    expect(isValidFormat('T123')).toBe(false);
    expect(isValidFormat('T12345')).toBe(false);
    expect(isValidFormat('attack')).toBe(false);
    expect(isValidFormat('')).toBe(false);
  });
});

describe('validateTechniqueId', () => {
  it('returns verified for allowed IDs', () => {
    expect(validateTechniqueId('T1566', ALLOWED)).toBe('verified');
  });
  it('returns unverified for valid format but not in allowed set', () => {
    expect(validateTechniqueId('T9999', ALLOWED)).toBe('unverified');
  });
  it('returns stripped for invalid format', () => {
    expect(validateTechniqueId('FAKE-001', ALLOWED)).toBe('stripped');
  });
});

describe('validateTechniqueIds', () => {
  it('categorizes a mixed list', () => {
    const result = validateTechniqueIds(
      ['T1566', 'T9999', 'HALLUCINATED', 'T1078', 'T1566.001'],
      ALLOWED,
    );
    expect(result.verified).toEqual(['T1566', 'T1078', 'T1566.001']);
    expect(result.unverified).toEqual(['T9999']);
    expect(result.stripped).toEqual(['HALLUCINATED']);
  });
});

describe('validateAnalysisResult', () => {
  it('filters findings and summary', () => {
    const input = {
      findings: [{
        id: 'F1',
        title: 'Phishing',
        description: 'Found phishing',
        mitre_techniques: ['T1566', 'T9999', 'FAKE'],
      }],
      mitre_techniques_summary: [
        { technique_id: 'T1566', name: 'Phishing', relevance: 'high' },
        { technique_id: 'T9999', name: 'Unknown', relevance: 'low' },
        { technique_id: 'FAKE', name: 'Bad', relevance: 'none' },
      ],
    };

    const result = validateAnalysisResult(input, ALLOWED);

    expect(result.findings[0].mitre_techniques).toEqual(['T1566']);
    expect(result.findings[0].unverified_techniques).toEqual(['T9999']);
    expect(result.mitre_techniques_summary).toHaveLength(1);
    expect(result.mitre_techniques_summary[0].technique_id).toBe('T1566');
  });

  it('handles findings with no techniques', () => {
    const input = {
      findings: [{ id: 'F1', title: 'Clean', description: 'No techniques', mitre_techniques: [] }],
      mitre_techniques_summary: [],
    };
    const result = validateAnalysisResult(input, ALLOWED);
    expect(result.findings[0].mitre_techniques).toEqual([]);
    expect(result.findings[0].unverified_techniques).toBeUndefined();
  });
});
