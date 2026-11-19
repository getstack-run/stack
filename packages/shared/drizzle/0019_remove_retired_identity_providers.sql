
DELETE FROM identity_providers p
WHERE p.provider_key IN ('bankid_se', 'eidas', 'id_me', 'login_gov', 'plaid', 'singpass', 'persona')
  AND NOT EXISTS (
    SELECT 1 FROM identity_claims c
    WHERE c.provider_id = p.id OR c.provider_key = p.provider_key
  )
  AND NOT EXISTS (
    SELECT 1 FROM identity_verification_sessions s
    WHERE s.provider_key = p.provider_key
  );
