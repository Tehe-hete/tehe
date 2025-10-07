FROM node:18-alpine
WORKDIR /app
COPY package.json ./
COPY proxy.js ./
RUN mkdir -p /var/log && chmod -R 755 /app
EXPOSE 8080
CMD ["node","proxy.js"]
