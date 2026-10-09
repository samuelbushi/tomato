FROM node:24-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends gosu ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json package-lock.json ./
COPY LICENSE NOTICE ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund && npm cache clean --force
COPY src/ ./src/
COPY public/ ./public/
COPY migrations/ ./migrations/
COPY container/app-entrypoint.sh /usr/local/bin/tomato-entrypoint
RUN chmod 755 /usr/local/bin/tomato-entrypoint
ENV NODE_ENV=production
EXPOSE 3000
ENTRYPOINT ["tomato-entrypoint"]
CMD ["node", "--import", "tsx", "src/server.ts"]
