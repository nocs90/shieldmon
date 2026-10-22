# Multi-stage Node.js service on Red Hat UBI 9.
#
#   builder: full UBI 9 Node.js image with npm, installs production dependencies
#   runtime: UBI 9 Node.js *minimal* image (no npm, no compilers) + the app
#
# Base images are build arguments so that "remediation by rebuild" is just a
# newer base tag (see e2e.sh). Pin them by digest in real projects and let
# Renovate propose bumps.
ARG BUILDER_IMAGE=registry.access.redhat.com/ubi9/nodejs-20:1-1778648167
ARG RUNTIME_IMAGE=registry.access.redhat.com/ubi9/nodejs-20-minimal:1-1778604817
ARG APP_DIR=app

FROM ${BUILDER_IMAGE} AS builder
ARG APP_DIR
WORKDIR /opt/app-root/src
COPY --chown=1001:0 ${APP_DIR}/package.json ${APP_DIR}/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund
COPY --chown=1001:0 ${APP_DIR}/server.js ./

FROM ${RUNTIME_IMAGE}
WORKDIR /opt/app-root/src
COPY --from=builder --chown=1001:0 /opt/app-root/src ./
USER 1001
EXPOSE 8080
CMD ["node", "server.js"]
