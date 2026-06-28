FROM ghcr.io/puppeteer/puppeteer:latest

WORKDIR /app
USER root
RUN chown -R pptruser:pptruser /app
USER pptruser

COPY --chown=pptruser:pptruser package*.json ./
RUN npm install

COPY --chown=pptruser:pptruser . .

EXPOSE 8080
CMD ["npm", "start"]
