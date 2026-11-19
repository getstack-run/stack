# The engine's container images: one build, three targets.
#
#   docker build -f deploy/docker/Dockerfile --target api    -t stack-engine-api    .
#   docker build -f deploy/docker/Dockerfile --target worker -t stack-engine-worker .
#   docker build -f deploy/docker/Dockerfile --target mcp    -t stack-engine-mcp    .
#
# Build from the repository root. Every image runs as the unprivileged `node`
# user, carries only the compiled output and the production dependencies of what
# it runs (no package manager, no compiler, no linter, no build cache), and sets
# STACK_DEPLOYMENT to self_managed. The API image also carries `stack-engine`,
# the command an operator runs on the machine (see docs/self-managed/operations.md),
# and the migrations, which run as their own step: `node apps/api/dist/db/migrate.js`.
#
# Every image carries its licence at /app/LICENSE and the OCI licence, source and
# title labels (`docker inspect` shows them).
#
# There is no sandbox, script runner or syscall filter in these images: sealed
# skill scripts do not run in a self-managed install.

# ── source ────────────────────────────────────────────────────────
FROM node:22-trixie-slim AS source
WORKDIR /app
RUN corepack enable && corepack prepare pnpm@11.1.2 --activate
COPY . .

# ── builder ───────────────────────────────────────────────────────
# Installs everything and builds the three apps; only their compiled output is read from here.
FROM source AS builder
RUN pnpm install --frozen-lockfile
RUN pnpm exec turbo run build --filter=@stack/api --filter=@stack/worker --filter=@stack/mcp-server-app

# ── production dependencies, one tree per image ───────────────────
# A fresh install of one app and the packages it depends on, production dependencies only, in the layout the app
# runs in (pnpm's per-package symlinked store has to stay where it was made, so each tree is copied whole). A link
# in these trees points at a package the image of that app copies, never at one it leaves out.
FROM source AS deps-api
RUN pnpm install --frozen-lockfile --prod --filter "@stack/api..."
FROM source AS deps-worker
RUN pnpm install --frozen-lockfile --prod --filter "@stack/worker..."
FROM source AS deps-mcp
RUN pnpm install --frozen-lockfile --prod --filter "@stack/mcp-server-app..."

# ── base ──────────────────────────────────────────────────────────
FROM node:22-trixie-slim AS base
RUN apt-get update && apt-get upgrade -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# Runtime only executes Node; omit the package-manager dependency trees.
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
    && rm -f /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack \
      /usr/local/bin/pnpm /usr/local/bin/pnpx /usr/local/bin/yarn /usr/local/bin/yarnpkg
WORKDIR /app
# The licence of what is in the image: the engine's Fair Core License text, with the licensor named
# (deploy/LICENSE in the public repository). Third-party packages carry their own under node_modules.
COPY deploy/LICENSE LICENSE
ENV NODE_ENV=production \
    STACK_DEPLOYMENT=self_managed
LABEL org.opencontainers.image.licenses="LicenseRef-FCL-1.0-ALv2" \
      org.opencontainers.image.vendor="Tomi Lupsakko" \
      org.opencontainers.image.authors="Tomi Lupsakko" \
      org.opencontainers.image.source="https://github.com/getstack-run/stack" \
      org.opencontainers.image.documentation="https://github.com/getstack-run/stack/tree/main/docs/self-managed"
COPY --from=builder /app/package.json                    package.json
COPY --from=builder /app/packages/shared/dist            packages/shared/dist
COPY --from=builder /app/packages/shared/package.json    packages/shared/package.json

# ── api ───────────────────────────────────────────────────────────
FROM base AS api
LABEL org.opencontainers.image.title="STACK engine API" \
      org.opencontainers.image.description="The STACK engine API: passports, the proxy, the record and the control socket."
COPY --from=deps-api /app/node_modules                       node_modules
COPY --from=deps-api /app/packages/shared/node_modules       packages/shared/node_modules
COPY --from=builder /app/packages/vault/dist                 packages/vault/dist
COPY --from=builder /app/packages/vault/package.json         packages/vault/package.json
COPY --from=deps-api /app/packages/vault/node_modules        packages/vault/node_modules
COPY --from=builder /app/packages/dropoff/dist               packages/dropoff/dist
COPY --from=builder /app/packages/dropoff/package.json       packages/dropoff/package.json
COPY --from=deps-api /app/packages/dropoff/node_modules      packages/dropoff/node_modules
# The published claim schemas, read when an evidence pack is exported.
COPY --from=builder /app/packages/shared/src/generated/schemas-bundle.json packages/shared/src/generated/schemas-bundle.json
# The migrations and the compiled runner that applies them.
COPY --from=builder /app/packages/shared/drizzle             packages/shared/drizzle
COPY --from=builder /app/apps/api/dist                       apps/api/dist
COPY --from=builder /app/apps/api/package.json               apps/api/package.json
COPY --from=deps-api /app/apps/api/node_modules              apps/api/node_modules
RUN printf '#!/bin/sh\nexec node /app/apps/api/dist/cli/stack-engine.js "$@"\n' > /usr/local/bin/stack-engine \
    && chmod 0755 /usr/local/bin/stack-engine
USER node
EXPOSE 8080
ENV API_PORT=8080
CMD ["node", "apps/api/dist/server.js"]

# ── worker ────────────────────────────────────────────────────────
FROM base AS worker
LABEL org.opencontainers.image.title="STACK engine worker" \
      org.opencontainers.image.description="The STACK engine worker: the background jobs of the API."
COPY --from=deps-worker /app/node_modules                    node_modules
COPY --from=deps-worker /app/packages/shared/node_modules    packages/shared/node_modules
COPY --from=builder /app/packages/vault/dist                 packages/vault/dist
COPY --from=builder /app/packages/vault/package.json         packages/vault/package.json
COPY --from=deps-worker /app/packages/vault/node_modules     packages/vault/node_modules
COPY --from=builder /app/packages/dropoff/dist               packages/dropoff/dist
COPY --from=builder /app/packages/dropoff/package.json       packages/dropoff/package.json
COPY --from=deps-worker /app/packages/dropoff/node_modules   packages/dropoff/node_modules
COPY --from=builder /app/apps/worker/dist                    apps/worker/dist
COPY --from=builder /app/apps/worker/package.json            apps/worker/package.json
COPY --from=deps-worker /app/apps/worker/node_modules        apps/worker/node_modules
USER node
# Liveness only: the worker answers GET /health on PORT.
EXPOSE 8080
CMD ["node", "apps/worker/dist/worker.js"]

# ── mcp ───────────────────────────────────────────────────────────
FROM base AS mcp
LABEL org.opencontainers.image.title="STACK engine MCP server" \
      org.opencontainers.image.description="The STACK engine MCP server: the tools an agent reaches the engine through."
COPY --from=deps-mcp /app/node_modules                       node_modules
COPY --from=deps-mcp /app/packages/shared/node_modules       packages/shared/node_modules
COPY --from=builder /app/packages/mcp-server/dist            packages/mcp-server/dist
COPY --from=builder /app/packages/mcp-server/package.json    packages/mcp-server/package.json
COPY --from=deps-mcp /app/packages/mcp-server/node_modules   packages/mcp-server/node_modules
COPY --from=builder /app/apps/mcp-server/dist                apps/mcp-server/dist
COPY --from=builder /app/apps/mcp-server/package.json        apps/mcp-server/package.json
COPY --from=deps-mcp /app/apps/mcp-server/node_modules       apps/mcp-server/node_modules
USER node
ENV PORT=3001
EXPOSE 3001
CMD ["node", "apps/mcp-server/dist/serve.js"]
