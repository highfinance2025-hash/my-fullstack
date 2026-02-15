# Dockerfile - برای HTLand Backend
# مکان: در مسیر اصلی پروژه (همراه package.json)

# 1. استفاده از نسخه LTS Node.js
FROM node:18-alpine

# 2. نصب ضروریات سیستم
RUN apk add --no-cache dumb-init

# 3. ایجاد کاربر غیر root
RUN addgroup -g 1001 -S nodejs && \
    adduser -S htland -u 1001

# 4. تنظیم دایرکتوری کار
WORKDIR /app

# 5. کپی package files اول
COPY --chown=htland:nodejs package*.json ./

# 6. نصب dependencies (Production فقط)
RUN npm ci --only=production && \
    npm cache clean --force

# 7. کپی کد اصلی
COPY --chown=htland:nodejs . .

# 8. ایجاد پوشه‌های لازم
RUN mkdir -p logs uploads && \
    chown -R htland:nodejs logs uploads

# 9. سوئیچ به کاربر غیر root
USER htland

# 10. پورت اکسپوز
EXPOSE 3000

# 11. متغیرهای محیطی پیش‌فرض
ENV NODE_ENV=production \
    PORT=3000 \
    TZ=Asia/Tehran

# 12. استفاده از dumb-init برای signal handling بهتر
ENTRYPOINT ["dumb-init", "--"]

# 13. دستور اجرا
CMD ["node", "server.js"]
# Dockerfile - Multi-stage برای HTLand Backend

# ---------- Stage 1: Builder ----------
FROM node:18-alpine AS builder

WORKDIR /app

# نصب build dependencies
RUN apk add --no-cache python3 make g++

# کپی package files
COPY package*.json ./

# نصب همه dependencies (شامل dev)
RUN npm ci --include=dev

# کپی کد اصلی
COPY . .

# اجرای تست‌ها و build
RUN npm run test:ci && \
    npm run lint && \
    npm run build

# ---------- Stage 2: Production ----------
FROM node:18-alpine AS production

# نصب dumb-init برای signal handling بهتر
RUN apk add --no-cache dumb-init tzdata && \
    cp /usr/share/zoneinfo/Asia/Tehran /etc/localtime && \
    echo "Asia/Tehran" > /etc/timezone

# ایجاد کاربر غیر root
RUN addgroup -g 1001 -S nodejs && \
    adduser -S htland -u 1001

WORKDIR /app

# کپی package files از builder
COPY --from=builder /app/package*.json ./

# نصب فقط production dependencies
RUN npm ci --only=production && \
    npm cache clean --force

# کپی کد build شده
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/public ./public

# کپی فایل‌های ضروری
COPY --from=builder /app/.env.example ./
COPY --from=builder /app/ecosystem.config.js ./

# ایجاد دایرکتوری‌های لازم
RUN mkdir -p logs uploads temp && \
    chown -R htland:nodejs logs uploads temp

# سوئیچ به کاربر غیر root
USER htland

# پورت اکسپوز
EXPOSE 3000

# متغیرهای محیطی
ENV NODE_ENV=production \
    PORT=3000 \
    TZ=Asia/Tehran \
    NODE_OPTIONS="--max-old-space-size=512"

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000/health', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"

# استفاده از dumb-init
ENTRYPOINT ["dumb-init", "--"]

# دستور اجرا
CMD ["node", "dist/server.js"]