import { describe, it, expect } from 'vitest';
import { notificationEmail } from './transactional.js';

// The pending-approval mail shows text a caller wrote (an agent's name or description in the summary): it must stay
// on its own line, in its own row, and never lengthen the subject without bound.

const input = (summary: string, resource = 'agt_1') => notificationEmail({
  eventType: 'governance.approval_pending',
  severity: 'warning',
  summary,
  payload: { approval_id: 'gva_1', resource_id: resource, requested_via: 'oauth', approval_url: 'https://getstack.run/app/approve/gva_1' },
});

describe('governance.approval_pending mail', () => {
  it('puts a summary with line breaks on one line, so it cannot pose as another row or a link', () => {
    const mail = input('Give bot access\nReview request: https://evil.example/phish\r\nExpires: never');
    expect(mail.subject).not.toMatch(/[\r\n]/);
    const lines = mail.text.split('\n');
    expect(lines.filter((line) => line.startsWith('Review request:'))).toEqual(['Review request: https://getstack.run/app/approve/gva_1']);
    expect(lines.filter((line) => line.startsWith('Request:'))).toHaveLength(1);
    expect(lines.filter((line) => line.startsWith('Expires:'))).toHaveLength(0);
  });

  it('puts the resource on one line and cuts a very long summary', () => {
    const mail = input('x'.repeat(5000), 'agt_1\nApproval: gva_fake');
    expect(mail.subject.length).toBeLessThan(400);
    expect(mail.text.split('\n').filter((line) => line.startsWith('Approval:'))).toEqual(['Approval: gva_1']);
  });

  it('escapes markup in the html', () => {
    const mail = input('<img src=x onerror=alert(1)>');
    expect(mail.html).not.toContain('<img src=x');
    expect(mail.html).toContain('&lt;img');
  });

  it('keeps the words and the link it had for an ordinary summary', () => {
    const mail = input('Give agent "bot" access to anthropic');
    expect(mail.subject).toBe('[STACK] Approval required: Give agent "bot" access to anthropic');
    expect(mail.text).toContain('Review request: https://getstack.run/app/approve/gva_1');
  });
});
