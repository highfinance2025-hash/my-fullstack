const winston = require('winston');
const path = require('path');
const fs = require('fs');

// مسیر پوشه لاگ‌ها
const logDir = path.join(__dirname, '../../logs');

// ساخت پوشه logs اگر وجود نداشته باشد
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir, { recursive: true });
}

// فرمت سفارشی برای نمایش در کنسول
const consoleFormat = winston.format.combine(
  winston.format.colorize({ all: true }),
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.printf(
    (info) => `${info.timestamp} [${info.level}]: ${info.message}`
  )
);

// فرمت استاندارد برای ذخیره در فایل
const fileFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.json()
);

// ساخت لاگر اصلی
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: fileFormat,
  transports: [
    // ذخیره تمام لاگ‌ها
    new winston.transports.File({ 
      filename: path.join(logDir, 'combined.log'),
      maxsize: 5242880, // 5MB
      maxFiles: 5
    }),
    // ذخیره فقط خطاها
    new winston.transports.File({ 
      filename: path.join(logDir, 'error.log'), 
      level: 'error',
      maxsize: 5242880, 
      maxFiles: 5
    })
  ],
  exitOnError: false // کرش نکردن برنامه در صورت خطا
});

// اگر در محیط توسعه هستیم، لاگ‌ها در کنسول هم نمایش داده شوند
if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: consoleFormat
  }));
}

// دسترسی به استریم برای استفاده در کتابخانه‌هایی مثل morgan
logger.stream = {
  write: (message) => {
    logger.info(message.trim());
  }
};

// ✅ تابع middleware اضافه شده برای حل مشکل app.js
logger.middleware = () => {
  return (req, res, next) => {
    logger.info(`${req.method} ${req.url}`, {
      ip: req.ip,
      status: res.statusCode
    });
    next();
  };
};

module.exports = logger;