import { describe, expect, it } from 'vitest';
import { passportServiceGrantIsFresh } from './passport-service.js';

const methodConstraint = { path: 'method', op: 'eq' as const, value: 'GET' };

describe('passport service-grant freshness', () => {
  it('accepts a signed scope that remains inside the standing grant', () => {
    expect(passportServiceGrantIsFresh(
      {
        scopes: ['mail.read'],
        constraints: [methodConstraint, { path: 'url.pathname', op: 'starts_with', value: '/safe' }],
        allow_data_from: ['crm'],
      },
      { scopes: ['*'], constraints: [methodConstraint], allow_data_from: ['crm'] },
      ['mail', 'crm'],
      'mail',
    )).toBe(true);
  });

  it('rejects a token after scopes, constraints, or data flow are narrowed', () => {
    expect(passportServiceGrantIsFresh(
      { scopes: ['mail.send'], constraints: [methodConstraint], allow_data_from: [] },
      { scopes: ['mail.read'], constraints: [methodConstraint], allow_data_from: [] },
      ['mail'],
      'mail',
    )).toBe(false);

    expect(passportServiceGrantIsFresh(
      { scopes: ['mail.read'], constraints: [], allow_data_from: [] },
      { scopes: ['mail.read'], constraints: [methodConstraint], allow_data_from: [] },
      ['mail'],
      'mail',
    )).toBe(false);

    expect(passportServiceGrantIsFresh(
      { scopes: ['mail.read'], constraints: [methodConstraint], allow_data_from: ['crm'] },
      { scopes: ['mail.read'], constraints: [methodConstraint], allow_data_from: [] },
      ['mail', 'crm'],
      'mail',
    )).toBe(false);
  });
});
