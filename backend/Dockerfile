FROM node:20-alpine
WORKDIR /app
COPY package.json .
RUN npm install --omit=dev
COPY server.js .
RUN mkdir -p /app/public && \
    printf 'VulnLab File Server\nVersion: 1.0\nContact: admin@corp.com\n' > /app/public/readme.txt && \
    printf 'notes: internal use only\nreport: /app/public/readme.txt\n' > /app/public/report.txt && \
    printf 'SECRET_FLAG=FLAG{path_traversal_lfi_success}\nAPI_KEY=sk-vulnlab-prod-7x9k2m\nDB_PASS=vulnlab\nADMIN_TOKEN=tok_admin_8f3k2j\n' > /app/.env.secret
EXPOSE 3000
CMD ["node", "server.js"]
