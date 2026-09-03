FROM node:22-alpine
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
COPY index.js ./
RUN mkdir -p /app/data
ENV NODE_ENV=production
ENV PORT=8787
EXPOSE 8787
CMD ["node","index.js"]
