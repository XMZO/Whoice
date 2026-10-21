FROM node:24-alpine AS deps

WORKDIR /app
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY apps/web/package.json ./apps/web/package.json
RUN corepack enable && pnpm install --filter @whoice/web --frozen-lockfile

FROM node:24-alpine AS build

WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/apps/web/node_modules ./apps/web/node_modules
COPY package.json pnpm-workspace.yaml ./
COPY apps/web ./apps/web
RUN corepack enable && pnpm --dir apps/web build \
  # sharp and its 16MB libvips only serve next/image optimization, which
  # this app does not use; Next loads sharp lazily and only for that route.
  && rm -rf apps/web/.next/standalone/node_modules/.pnpm/sharp@* \
    apps/web/.next/standalone/node_modules/.pnpm/@img+* \
    apps/web/.next/standalone/node_modules/sharp \
    apps/web/.next/standalone/node_modules/@img

# Runtime: a plain Alpine with only the node binary and the two libraries it
# links (npm, corepack and yarn never enter the image), plus the standalone
# server Next traced from the build. Keep the Alpine release in step with
# the node:24-alpine base so libstdc++ matches.
FROM alpine:3.24 AS runner

RUN apk add --no-cache libstdc++ libgcc \
  && adduser -D -H -u 1000 node
COPY --from=build /usr/local/bin/node /usr/local/bin/node
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=8081 \
    HOSTNAME=0.0.0.0
COPY --from=build --chown=node:node /app/apps/web/.next/standalone ./
COPY --from=build --chown=node:node /app/apps/web/.next/static ./apps/web/.next/static
COPY --from=build --chown=node:node /app/apps/web/public ./apps/web/public
USER node

EXPOSE 8081
CMD ["node", "apps/web/server.js"]
