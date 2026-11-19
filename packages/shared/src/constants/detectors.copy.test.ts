import { describe, expect, it } from 'vitest';
import { DETECTORS } from './detectors.js';

// No detector is described as a tier's: a lapsed or absent controls subscription is the only thing that turns one off.

describe('what the detector catalogue says about who has a detector', () => {
  it('names no tier for any detector', () => {
    for (const [key, detector] of Object.entries(DETECTORS)) {
      expect(detector.description, key).not.toMatch(/enterprise/i);
    }
  });

  it('calls the genome drift detector a controls feature', () => {
    expect(DETECTORS['genome_drift']!.description).toContain('A controls feature.');
  });
});
