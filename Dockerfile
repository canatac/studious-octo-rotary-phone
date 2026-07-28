# Dockerfile - DKIM Service (Node.js 22)
# studious-octo-rotary-phone

FROM node:22-bookworm-slim

WORKDIR /app

# Copy package files first for better layer caching
COPY package*.json ./

# Install production dependencies only
RUN npm ci --omit=dev || npm install --omit=dev

# Copy application code
COPY . .

# Create directory for DKIM keys (mounted from host at runtime)
RUN mkdir -p /app/dkim

# Expose the port the app runs on
EXPOSE 3000

# Production environment
ENV NODE_ENV=production

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1

CMD ["node", "app.js"]
