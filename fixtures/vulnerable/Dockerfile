FROM node:20
WORKDIR /app
COPY . .
RUN npm install
ENV NODE_ENV=development
ENV STRIPE_SECRET_KEY=sk_live_51PreflightFakeKeyDoNotUse000000000000
EXPOSE 3000
CMD ["npm", "start"]
