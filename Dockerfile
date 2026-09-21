FROM node:22-alpine
WORKDIR /app
# docker CLI only (talks to the host daemon via the mounted socket) so the
# lab orchestrator can provision isolated lab networks/containers on demand.
RUN apk add --no-cache docker-cli
COPY package*.json ./
RUN npm ci --omit=dev
COPY server ./server
COPY public ./public
COPY labs ./labs
COPY lab-images ./lab-images
RUN mkdir -p courses/video courses/reading data
ENV NODE_ENV=production PORT=3100 COURSES_ROOT=/courses DATA_DIR=/data
VOLUME ["/courses", "/data"]
EXPOSE 3100
CMD ["node", "server/index.js"]
