FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY server ./server
COPY public ./public
RUN mkdir -p courses/video courses/reading data
ENV NODE_ENV=production PORT=3100 COURSES_ROOT=/courses DATA_DIR=/data
VOLUME ["/courses", "/data"]
EXPOSE 3100
CMD ["node", "server/index.js"]
