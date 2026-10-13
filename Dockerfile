# ---- build: generate the Prisma client and compile TypeScript ----
FROM node:24-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
COPY prisma ./prisma
COPY prisma.config.ts ./
RUN npm ci
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm run build

# ---- migrate: one-off job that applies database migrations, then exits ----
# Run before rolling out a new version (compose: auth-migrate; ECS: a one-off task).
# Kept out of the app's startup so several replicas never race to migrate.
FROM build AS migrate
USER node
CMD ["npx", "prisma", "migrate", "deploy"]

# ---- runtime: production dependencies + compiled JS only ----
FROM node:24-alpine AS runtime
ENV NODE_ENV=production \
    JWT_KEYS_DIR=/app/keys
WORKDIR /app
COPY package.json package-lock.json ./
# --omit=optional --omit=peer: @prisma/client lists the Prisma CLI as an optional peer,
#   so the lockfile marks the CLI tree "devOptional", which --omit=dev alone keeps. Without
#   this the image ships the CLI, Studio, engines and a MySQL driver (~250 MB). The only
#   purely optional runtime package dropped is pg-cloudflare (Cloudflare Workers shim).
# --ignore-scripts: skip `postinstall: prisma generate`; the generated client is already
#   compiled into dist/. argon2 ships prebuilt binaries, so it needs no install script.
RUN npm ci --omit=dev --omit=optional --omit=peer --ignore-scripts && npm cache clean --force \
 && mkdir -p /app/keys && chown node:node /app/keys && chmod 700 /app/keys
COPY --from=build /app/dist ./dist
USER node
EXPOSE 4001
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s \
  CMD wget -qO- "http://127.0.0.1:${PORT:-4001}/health/live" >/dev/null || exit 1
CMD ["node", "dist/server.js"]
