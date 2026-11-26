# Pure JavaScript dependencies: the same npm install works on amd64 and arm64.
FROM node:22-bookworm-slim
WORKDIR /app
ENV NODE_ENV=production
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund
COPY server.js ./
USER node
EXPOSE 8080
CMD ["node", "server.js"]
