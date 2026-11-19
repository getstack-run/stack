import { describe, expect, it } from 'vitest';
import { PROVIDER_OAUTH_RETURN_TO } from './provider-oauth-service.js';

describe('where a provider sign-in returns the browser', () => {
  it('sends a connection back to the Connections room, and the services page stays', () => {
    expect(PROVIDER_OAUTH_RETURN_TO).toEqual({ connect: '/app/connections', services: '/services' });
  });
});
