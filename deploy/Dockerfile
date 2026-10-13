# ==============================================================================
# REA (Reverse Engineer Anything) Multi-Stage Dockerfile
# ==============================================================================
# Stages:
#   1. builder   - Compiles TypeScript runtime, packages skills, builds static site
#   2. core      - Lean runtime for REA CLI and MCP Server with RE tools
#   3. web       - High-performance Nginx server for Documentation & Showcases
#   4. inspector - MCP Inspector Web UI for testing and exploring REA tools
# ==============================================================================

# ------------------------------------------------------------------------------
# Stage 1: Build Environment
# ------------------------------------------------------------------------------
FROM node:22-bookworm-slim AS builder

WORKDIR /app

# Install build prerequisites and Python dependencies for site generation
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    libcairo2 \
    fonts-dejavu-core \
    build-essential \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy package descriptors and scripts needed for prepare script
COPY package.json package-lock.json ./
COPY scripts/prepare.mjs ./scripts/prepare.mjs

# Install node dependencies
RUN npm ci

# Copy full project source
COPY tsconfig*.json turbo.json ./
COPY scripts ./scripts
COPY src ./src
COPY bridge ./bridge
COPY native ./native
COPY website ./website
COPY .agents ./.agents
COPY README*.md DISCLAIMER.md LICENSE ./

# Build REA runtime and skill metadata
RUN npm run build:cached

# Install Python requirements and build static documentation site
RUN python3 -m pip install --no-cache-dir --break-system-packages -r website/requirements.txt \
    && python3 scripts/prepare-website.py

# ------------------------------------------------------------------------------
# Stage 2: REA Core Runtime (CLI & MCP Server)
# ------------------------------------------------------------------------------
FROM node:22-bookworm-slim AS core

# Label metadata
LABEL maintainer="morluto" \
      description="REA - Reverse Engineer Anything: Unified CLI and MCP Server" \
      version="6.4.0"

ENV DEBIAN_FRONTEND=noninteractive \
    NODE_ENV=production \
    REA_WORKSPACE=/workspace \
    REA_JADX_MCP_JAR=/opt/jadx/jadx-headless-mcp-0.7.1-all.jar \
    PATH="/app/node_modules/.bin:${PATH}"

# Install essential reverse engineering and system utilities including Java for Android/JADX
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    file \
    binutils \
    p7zip-full \
    unzip \
    curl \
    jq \
    ca-certificates \
    procps \
    default-jre-headless \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /opt/jadx \
    && curl -fsSL -o /opt/jadx/jadx-headless-mcp-0.7.1-all.jar \
       https://github.com/1013503897/jadx-headless-mcp/releases/download/v0.7.1/jadx-headless-mcp-0.7.1-all.jar \
    && printf 'NAME="Ubuntu"\nVERSION="24.04 LTS (Noble Numbat)"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\n' > /etc/os-release

WORKDIR /app

# Copy built runtime and dependencies from builder
COPY package.json package-lock.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/scripts ./scripts
COPY --from=builder /app/bridge ./bridge
COPY --from=builder /app/skills ./skills
COPY --from=builder /app/native ./native
COPY README*.md DISCLAIMER.md LICENSE ./

# Create global binary symlinks
RUN npm link

# Setup workspace and persistence volumes
RUN mkdir -p /workspace/targets /workspace/output /root/.rea \
    && chmod -R 777 /workspace

WORKDIR /workspace

# Healthcheck using rea --version
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD rea --version || exit 1

# Default command runs REA in MCP mode (can be overridden with tail -f /dev/null for daemon)
CMD ["rea", "mcp"]

# ------------------------------------------------------------------------------
# Stage 3: REA Documentation & Showcase Web Server
# ------------------------------------------------------------------------------
FROM nginx:alpine AS web

LABEL maintainer="morluto" \
      description="REA Documentation & Showcase Static Website"

# Copy custom Nginx configuration
COPY <<'EOF' /etc/nginx/conf.d/default.conf
server {
    listen 80;
    server_name localhost;
    root /usr/share/nginx/html;
    index index.html;

    # Gzip Compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_proxied any;
    gzip_types text/plain text/css text/xml application/json application/javascript application/xml+rss application/atom+xml image/svg+xml;

    location / {
        try_files $uri $uri/ $uri/index.html =404;
    }

    # Cache static assets
    location ~* \.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
        expires 7d;
        add_header Cache-Control "public, no-transform";
    }

    # Security headers
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options SAMEORIGIN always;
    add_header X-XSS-Protection "1; mode=block" always;
}
EOF

# Copy compiled static site from builder stage
COPY --from=builder /app/website/_site /usr/share/nginx/html

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://127.0.0.1/ || exit 1

CMD ["nginx", "-g", "daemon off;"]

# ------------------------------------------------------------------------------
# Stage 4: MCP Inspector Web UI
# ------------------------------------------------------------------------------
FROM node:22-bookworm-slim AS inspector

LABEL maintainer="morluto" \
      description="REA MCP Inspector Web UI for Interactive Exploration"

WORKDIR /app

# Install curl, ca-certificates, procps, and JRE for Java/Android analysis
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    procps \
    default-jre-headless \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /opt/jadx \
    && curl -fsSL -o /opt/jadx/jadx-headless-mcp-0.7.1-all.jar \
       https://github.com/1013503897/jadx-headless-mcp/releases/download/v0.7.1/jadx-headless-mcp-0.7.1-all.jar

# Install official MCP Inspector globally
RUN npm install -g @modelcontextprotocol/inspector

# Copy built runtime from builder
COPY package.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/scripts ./scripts
COPY --from=builder /app/bridge ./bridge
COPY --from=builder /app/skills ./skills

EXPOSE 6274 6275

# Run inspector serving REA MCP over web UI
ENV HOST=0.0.0.0 \
    DANGEROUSLY_BIND_ALL_INTERFACES=true \
    REA_JADX_MCP_JAR=/opt/jadx/jadx-headless-mcp-0.7.1-all.jar

CMD ["mcp-inspector", "--web", "node", "scripts/rea.mjs", "mcp"]
