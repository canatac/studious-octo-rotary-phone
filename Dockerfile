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

# Health check (issue #718): use node instead of wget (not available in slim image)
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "const http=require('http');const req=http.get('http://127.0.0.1:3000/health',res=>{process.exit(res.statusCode===200?0:1)});req.on('error',()=>process.exit(1));"

CMD ["node", "app.js"]
