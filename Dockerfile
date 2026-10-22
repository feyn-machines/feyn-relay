FROM node:24-slim
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --omit=dev
COPY relay.mjs blobs.mjs oauth.mjs statement.mjs machines.mjs admin.mjs address.mjs ./
USER node
CMD ["node", "relay.mjs"]
