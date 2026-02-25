const mongoose = require('mongoose');
const config = require('./config/env.config');
const logger = require('./utils/logger');

// ✅ ایمپورت اپلیکیشن کانفیگ شده از فایل app.js
const app = require('./app');

const startServer = async () => {
  try {
    // 1️⃣ اتصال به دیتابیس (الزامی برای پروژه واقعی)
    // اگر دیتابیس وصل نشود، به خطای catch می‌رود و پیام می‌دهد
    await mongoose.connect(config.mongoose.url, config.mongoose.options);
    
    // لاگ کردن موفقیت اتصال
    console.log('✅ MongoDB Connected Successfully');
    logger.info('✅ MongoDB Connected');

    // 2️⃣ روشن کردن سرور
    const PORT = config.port || 3000;
    
    app.listen(PORT, () => {
      console.log('------------------------------------------------');
      console.log(`🚀 Server is live at http://localhost:${PORT}`);
      console.log('------------------------------------------------');
      logger.info(`🚀 Server running on port ${PORT}`);
    });

  } catch (error) {
    // اگر خطایی در اتصال به دیتابیس یا استارتاپ رخ دهد
    console.error('❌ CRITICAL ERROR:', error.message);
    logger.error(`❌ Server startup failed: ${error.message}`);
    process.exit(1); // بستن برنامه
  }
};

// ⚠️ نکته امنیتی برای ویندوز (جلوگیری از کرش کردن توسط کاراکترهای فارسی در لاگ)
if (process.platform === 'win32') {
  const rl = require('readline').createInterface({
    input: process.stdin,
    output: process.stdout
  });
  rl.on('SIGINT', () => process.emit('SIGINT'));
}

// هندل کردن خاموش شدن صحیح
process.on('SIGINT', () => {
  mongoose.connection.close(false).then(() => {
    console.log('🔌 Server shut down gracefully');
    process.exit(0);
  });
});

startServer();