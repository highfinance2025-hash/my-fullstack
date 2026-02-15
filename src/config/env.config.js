const dotenv = require('dotenv');
const path = require('path');

// لود کردن متغیرهای محیطی از فایل .env
dotenv.config({ path: path.resolve(__dirname, '../../.env') });

const config = {
  // تنظیمات عمومی
  env: process.env.NODE_ENV || 'development',
  port: parseInt(process.env.PORT) || 3000,

  // تنظیمات اپلیکیشن
  app: {
    name: process.env.APP_NAME || 'HTLand',
    version: process.env.APP_VERSION || '1.0.0',
    url: process.env.APP_URL || `http://localhost:${process.env.PORT || 3000}`
  },

  // تنظیمات دیتابیس (MongoDB)
  mongoose: {
    url: process.env.MONGODB_URI || 'mongodb://localhost:27017/htland',
    options: {
      autoIndex: process.env.NODE_ENV !== 'production',
      maxPoolSize: 50,
      minPoolSize: 5,
      connectTimeoutMS: 10000,
      socketTimeoutMS: 45000,
      serverSelectionTimeoutMS: 5000
    }
  },

  // تنظیمات امنیت (JWT & Encryption)
  jwt: {
    secret: process.env.JWT_SECRET || 'default_secret_key_change_in_production_12345',
    expiresIn: process.env.JWT_EXPIRES_IN || '7d'
  },

  encryption: {
    key: process.env.ENCRYPTION_KEY || 'default_encryption_key_32_chars!',
    algorithm: 'aes-256-gcm'
  },

  // تنظیمات CORS
  cors: {
    allowedOrigins: process.env.ALLOWED_ORIGINS 
      ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
      : ['http://localhost:3000', 'http://localhost:8080'],
    credentials: true
  },

  // محدودیت درخواست (Rate Limiter)
  rateLimit: {
    windowMs: 15 * 60 * 1000, // 15 دقیقه
    maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100
  },

  // تنظیمات زرین‌پال
  zarinpal: {
    merchantId: process.env.ZARINPAL_MERCHANT_ID || 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx',
    sandbox: process.env.ZARINPAL_SANDBOX === 'true',
    callbackUrl: process.env.ZARINPAL_CALLBACK_URL || 'http://localhost:3000/api/v1/payment/verify'
  },

  // تنظیمات مالی
  financial: {
    taxRate: parseFloat(process.env.IRAN_TAX_RATE) || 0.09, // 9 درصد مالیات
    currency: 'IRR'
  }
};

// بررسی امنیتی در حالت Production
if (config.env === 'production') {
  const requiredEnvVars = ['MONGODB_URI', 'JWT_SECRET', 'ENCRYPTION_KEY', 'ZARINPAL_MERCHANT_ID'];
  const missing = requiredEnvVars.filter(key => !process.env[key] || process.env[key].includes('default'));

  if (missing.length > 0) {
    console.error(`CRITICAL ERROR: Missing required ENV vars in production: ${missing.join(', ')}`);
    process.exit(1);
  }
}

module.exports = config;