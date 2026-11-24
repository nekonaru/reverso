FROM node:24-bookworm-slim

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
COPY scripts ./scripts
COPY site ./site
RUN npm run build && npm run build:web

ENV PORT=3000
ENV HOST=0.0.0.0
ENV REVERSO_MAX_BODY_BYTES=8388608
EXPOSE 3000

CMD ["npm", "start"]
