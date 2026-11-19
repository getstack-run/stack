#!/bin/sh
# Writes the secrets a single-host install needs, as files under ./secrets,
# and a .env to edit. Safe to re-run: it never overwrites a secret that exists
# (a lost key-encryption key cannot be regenerated: everything stored under it
# would be unreadable).
#
#   ./init-secrets.sh [image]
#
# The key-encryption key, the passport signing key and the API key pepper come
# from `stack-engine keys generate`, run inside the API image so the install
# makes them with its own code. The rest are random values.
set -eu

cd "$(dirname "$0")"
IMAGE="${1:-${STACK_ENGINE_API_IMAGE:-ghcr.io/getstack-run/stack-engine-api}:${STACK_ENGINE_VERSION:-0.1.0}}"

umask 077
mkdir -p secrets

random() { head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

if [ ! -e secrets/stack-kek ]; then
  docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/secrets:/out" "$IMAGE" stack-engine keys generate --dir /out/generated
  mv secrets/generated/* secrets/
  rmdir secrets/generated
else
  echo "secrets/stack-kek exists; leaving the generated keys as they are."
fi

[ -e secrets/postgres-password ] || printf '%s' "$(random)" > secrets/postgres-password
[ -e secrets/archive-access-key ] || printf '%s' "stack$(random | head -c 12)" > secrets/archive-access-key
[ -e secrets/archive-secret-key ] || printf '%s' "$(random)" > secrets/archive-secret-key
[ -e secrets/mcp-attestation-key ] || printf '%s' "$(random)" > secrets/mcp-attestation-key
[ -e secrets/database-url ] || printf 'postgresql://stack:%s@postgres:5432/stack' "$(cat secrets/postgres-password)" > secrets/database-url
[ -e secrets/archive-s3-config ] || printf '{"identities":[{"name":"stack","credentials":[{"accessKey":"%s","secretKey":"%s"}],"actions":["Admin","Read","Write","List","Tagging"]}]}' "$(cat secrets/archive-access-key)" "$(cat secrets/archive-secret-key)" > secrets/archive-s3-config
chmod 0400 secrets/* 2>/dev/null || true

if [ ! -e .env ]; then
  cp env.example .env
  echo "Wrote .env: set STACK_API_BASE_URL (the address people reach this install at) before starting."
fi
# The engine containers run as the user that owns the secrets, so they stay readable by that user only.
grep -q "^STACK_UID=" .env || printf 'STACK_UID=%s\nSTACK_GID=%s\n' "$(id -u)" "$(id -g)" >> .env

echo "Secrets are in ./secrets. Back them up now, and keep them out of version control."
