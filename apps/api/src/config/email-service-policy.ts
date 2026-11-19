/**
 * A hosted production boot needs a mail service: account notices, account transfers and email verification go by
 * email. A staging deployment (`STACK_STAGING=true`) may boot without one: it then sends no mail at all, which is
 * stricter than its allow-list, and a sign-in there needs an API key until a staging mail key is in its vault.
 */
export function assertProductionEmailService(
  nodeEnv: string | undefined,
  resendKey: string | null | undefined,
  stagingDeployment = false,
): void {
  if (nodeEnv === 'production' && !stagingDeployment && !resendKey?.trim()) {
    throw new Error(
      '[BOOT] Resend email service is required in production for account notices, account transfers, and email verification.',
    );
  }
}
