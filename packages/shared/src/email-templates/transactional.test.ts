import { expect, it } from 'vitest';
import { notificationEmail } from './transactional.js';

it('renders one reconnect action without exposing credential data', () => {
  const email = notificationEmail({ eventType: 'security.credential_reconnect_required', severity: 'warning',
    payload: { connection_id: 'scon_fixture', access_token: 'must-not-render' } });
  expect(email.subject).toBe('[STACK] Service reconnect required');
  expect(email.text).toContain('Reconnect this service to continue.');
  expect(email.html).toContain('href="https://getstack.run/services"');
  expect(email.html).toContain('>Reconnect</a>');
  expect(email.text).toContain('scon_fixture');
  expect(email.html + email.text).not.toContain('must-not-render');
});
