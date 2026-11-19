import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { emailChrome, setEmailChrome } from './chrome.js';
import {
  emailChangeCompletedEmail,
  emailChangeConfirmEmail,
  emailChangeNoticeEmail,
  memberInviteEmail,
  notificationEmail,
  notificationVerificationEmail,
  type TransactionalEmail,
} from './transactional.js';

function everyEmail(): TransactionalEmail[] {
  return [
    memberInviteEmail({ inviterEmail: 'owner@install.example', inviteUrl: 'https://stack.install.example/join?t=1' }),
    emailChangeConfirmEmail({ currentEmail: 'old@install.example', confirmUrl: 'https://stack.install.example/c', ttlMinutes: 30 }),
    emailChangeNoticeEmail({ newEmail: 'new@install.example', cancelUrl: 'https://stack.install.example/x', ttlMinutes: 30 }),
    emailChangeCompletedEmail({ newEmail: 'new@install.example' }),
    notificationEmail({ eventType: 'security.credential_reconnect_required', severity: 'warning', payload: { connection_id: 'scon_1' } }),
    notificationEmail({ eventType: 'security.prompt_injection', severity: 'critical', message: 'm', payload: { event_id: 'e1' } }),
    notificationEmail({ eventType: 'governance.approval_pending', severity: 'info', summary: 'Loosen a detector', payload: { approval_id: 'gva_1' } }),
    notificationEmail({ eventType: 'agent.blocked', severity: 'warning', message: 'blocked' }),
    notificationVerificationEmail({ code: '123456', kind: 'delivery method' }),
  ];
}

describe('the emails of an install', () => {
  beforeEach(() => {
    setEmailChrome(null);
    vi.stubEnv('STACK_DEPLOYMENT', 'self_managed');
    vi.stubEnv('STACK_API_BASE_URL', 'https://stack.install.example');
    vi.stubEnv('STACK_SECURITY_CONTACT', '');
  });
  afterEach(() => {
    vi.unstubAllEnvs();
    setEmailChrome(null);
  });

  it('carry no STACK address, logo, typeface, colour or office', () => {
    for (const email of everyEmail()) {
      const all = `${email.subject}\n${email.text}\n${email.html}`;
      expect(all).not.toMatch(/getstack\.run/i);
      expect(all).not.toMatch(/Familjen|<img|Stockholm|#f2f0e9|#201f1c/i);
      expect(email.html).toContain('stack.install.example');
    }
  });

  it('send a person to the administrator when the install names no security contact', () => {
    const email = emailChangeCompletedEmail({ newEmail: 'new@install.example' });
    expect(email.text).toContain('If this was not you, contact your administrator immediately.');
    expect(email.html).toContain('contact your administrator immediately.');
  });

  it("send a person to the install's own configured security contact", () => {
    vi.stubEnv('STACK_SECURITY_CONTACT', 'security@install.example');
    const email = emailChangeCompletedEmail({ newEmail: 'new@install.example' });
    expect(email.text).toContain('If this was not you, contact security@install.example immediately.');
    expect(email.html).toContain('contact security@install.example immediately.');
    expect(`${email.text}${email.html}`).not.toMatch(/getstack/i);
  });

  it('use the chrome a deployment registers, and go back to the neutral one when it is cleared', () => {
    const neutral = emailChrome();
    setEmailChrome({ ...neutral, securityLine: () => 'Write to the registered address.' });
    expect(emailChangeCompletedEmail({ newEmail: 'n@install.example' }).text).toContain('Write to the registered address.');
    setEmailChrome(null);
    expect(emailChrome()).toBe(neutral);
  });
});
