// the direction rules are the spec. Every field rule, both
// directions, mixed, unchanged, and the fail-closed regex-edit cases.

import { describe, it, expect } from 'vitest';
import {
  classifyDetectorConfigDelta,
  DETECTOR_CONFIG_DEFAULTS,
  type DetectorConfigState,
} from './detector-config-delta.js';

const base = (over?: Partial<DetectorConfigState>): DetectorConfigState => ({
  ...DETECTOR_CONFIG_DEFAULTS,
  custom_patterns: [],
  whitelist_patterns: [],
  severity_overrides: {},
  ...over,
});

const cp = (id: string, severity: 'warning' | 'critical' = 'warning', regex = 'attack') => ({
  id,
  regex,
  severity,
  description: id,
});
const wl = (id: string, regex = 'benign') => ({ id, regex, description: id });

describe('classifyDetectorConfigDelta', () => {
  it('unchanged when nothing differs (and undefined prior = defaults)', () => {
    expect(classifyDetectorConfigDelta(base(), base()).direction).toBe('unchanged');
    expect(classifyDetectorConfigDelta(undefined, base()).direction).toBe('unchanged');
  });

  describe('enabled', () => {
    it('true→false is loosening; false→true is tightening', () => {
      expect(classifyDetectorConfigDelta(base(), base({ enabled: false })).direction).toBe('loosening');
      expect(
        classifyDetectorConfigDelta(base({ enabled: false }), base({ enabled: true })).direction,
      ).toBe('tightening');
    });
  });

  describe('custom patterns', () => {
    it('adding tightens; removing loosens', () => {
      expect(
        classifyDetectorConfigDelta(base(), base({ custom_patterns: [cp('a')] })).direction,
      ).toBe('tightening');
      expect(
        classifyDetectorConfigDelta(base({ custom_patterns: [cp('a')] }), base()).direction,
      ).toBe('loosening');
    });

    it('severity upgrade tightens; downgrade loosens', () => {
      expect(
        classifyDetectorConfigDelta(
          base({ custom_patterns: [cp('a', 'warning')] }),
          base({ custom_patterns: [cp('a', 'critical')] }),
        ).direction,
      ).toBe('tightening');
      expect(
        classifyDetectorConfigDelta(
          base({ custom_patterns: [cp('a', 'critical')] }),
          base({ custom_patterns: [cp('a', 'warning')] }),
        ).direction,
      ).toBe('loosening');
    });

    it('regex edit is fail-closed mixed', () => {
      expect(
        classifyDetectorConfigDelta(
          base({ custom_patterns: [cp('a', 'warning', 'old')] }),
          base({ custom_patterns: [cp('a', 'warning', 'new')] }),
        ).direction,
      ).toBe('mixed');
    });
  });

  describe('whitelist patterns', () => {
    it('adding loosens; removing tightens', () => {
      expect(
        classifyDetectorConfigDelta(base(), base({ whitelist_patterns: [wl('w')] })).direction,
      ).toBe('loosening');
      expect(
        classifyDetectorConfigDelta(base({ whitelist_patterns: [wl('w')] }), base()).direction,
      ).toBe('tightening');
    });

    it('regex edit is fail-closed mixed', () => {
      expect(
        classifyDetectorConfigDelta(
          base({ whitelist_patterns: [wl('w', 'old')] }),
          base({ whitelist_patterns: [wl('w', 'new')] }),
        ).direction,
      ).toBe('mixed');
    });
  });

  describe('severity overrides', () => {
    it('adding a warning downgrade loosens; adding a critical upgrade tightens', () => {
      expect(
        classifyDetectorConfigDelta(base(), base({ severity_overrides: { p1: 'warning' } })).direction,
      ).toBe('loosening');
      expect(
        classifyDetectorConfigDelta(base(), base({ severity_overrides: { p1: 'critical' } })).direction,
      ).toBe('tightening');
    });

    it('warning→critical tightens; critical→warning loosens', () => {
      expect(
        classifyDetectorConfigDelta(
          base({ severity_overrides: { p1: 'warning' } }),
          base({ severity_overrides: { p1: 'critical' } }),
        ).direction,
      ).toBe('tightening');
      expect(
        classifyDetectorConfigDelta(
          base({ severity_overrides: { p1: 'critical' } }),
          base({ severity_overrides: { p1: 'warning' } }),
        ).direction,
      ).toBe('loosening');
    });

    it('removing a warning downgrade tightens; removing a critical upgrade loosens', () => {
      expect(
        classifyDetectorConfigDelta(base({ severity_overrides: { p1: 'warning' } }), base()).direction,
      ).toBe('tightening');
      expect(
        classifyDetectorConfigDelta(base({ severity_overrides: { p1: 'critical' } }), base()).direction,
      ).toBe('loosening');
    });
  });

  it('mixed when both directions present — one hidden loosening cannot ride a tightening write', () => {
    const delta = classifyDetectorConfigDelta(
      base(),
      base({ custom_patterns: [cp('new')], whitelist_patterns: [wl('sneaky')] }),
    );
    expect(delta.direction).toBe('mixed');
    expect(delta.changes).toEqual(
      expect.arrayContaining(['custom_pattern added: new', 'whitelist_pattern added: sneaky']),
    );
  });

  it('changes list narrates every difference for the audit row', () => {
    const delta = classifyDetectorConfigDelta(
      base({ enabled: true, severity_overrides: { p1: 'critical' } }),
      base({ enabled: false, severity_overrides: {} }),
    );
    expect(delta.direction).toBe('loosening');
    expect(delta.changes).toEqual(
      expect.arrayContaining(['enabled: true→false', 'severity_override p1: critical→(none)']),
    );
  });
});
