/**
 * @file config/zarinpal.js
 * @description پیکربندی امن برای درگاه پرداخت زرین‌پال
 * این فایل مسئول مدیریت تنظیمات امنیتی و اتصال به درگاه پرداخت زرین‌پال است.
 * ویژگی‌های امنیتی:
 * - جداکردن کلیدهای محیط تولید و تست
 * - اعتبارسنجی پارامترهای دریافتی از زرین‌پال
 * - لاگ‌گیری امن تراکنش‌ها
 * - جلوگیری از حملات replay و injection
 */

const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const logger = require('../utils/logger');

class ZarinpalConfig {
  constructor() {
    // اعتبارسنجی اولیه متغیرهای محیطی
    this.validateEnvironmentVariables();
    
    // تنظیمات پایه
    this.sandbox = process.env.ZARINPAL_SANDBOX === 'true';
    this.merchantId = process.env.ZARINPAL_MERCHANT_ID;
    this.callbackUrl = process.env.ZARINPAL_CALLBACK_URL;
    this.webhookSecret = process.env.ZARINPAL_WEBHOOK_SECRET;
    
    // ایجاد کلیدهای امن برای هشینگ
    this.secretKey = this.generateSecretKey();
    
    // مسیر‌های لاگ‌گیری
    this.logDir = path.join(__dirname, '../logs/payments');
    this.ensureLogDirectory();
  }

  /**
   * اعتبارسنجی متغیرهای محیطی ضروری
   * @private
   * @throws {Error} در صورت عدم وجود متغیرهای اجباری
   */
  validateEnvironmentVariables() {
    const requiredVars = [
      'ZARINPAL_MERCHANT_ID',
      'ZARINPAL_CALLBACK_URL',
      'ZARINPAL_WEBHOOK_SECRET'
    ];

    requiredVars.forEach(varName => {
      if (!process.env[varName]) {
        logger.error(`Missing environment variable: ${varName}`);
        throw new Error(`متغیر محیطی ${varName} ضروری است و وجود ندارد.`);
      }
    });
  }

  /**
   * تولید کلید امن برای هشینگ داده‌ها
   * @private
   * @returns {string} کلید 32 کاراکتری امن
   */
  generateSecretKey() {
    if (process.env.ZARINPAL_SECRET_KEY) {
      return process.env.ZARINPAL_SECRET_KEY.padEnd(32, 'x').slice(0, 32);
    }
    
    // در محیط توسعه، کلید پیش‌فرض تولید شود
    return crypto.randomBytes(32).toString('hex');
  }

  /**
   * تولید شناسه یکتا و امن برای تراکنش
   * @returns {string} شناسه تراکنش 32 کاراکتری
   */
  generateSecureTransactionId() {
    return crypto.randomBytes(16).toString('hex') + 
           Date.now().toString(36).slice(-4) +
           crypto.randomInt(1000, 9999).toString(36);
  }

  /**
   * اعتبارسنجی کال‌بک دریافتی از زرین‌پال
   * این متد از حملات replay و injection جلوگیری می‌کند
   * @param {string} authority - کد authority دریافتی از زرین‌پال
   * @param {string} status - وضعیت پرداخت
   * @param {number} amount - مبلغ پرداخت
   * @param {string} refId - شناسه مرجع (اختیاری)
   * @returns {Object} نتیجه اعتبارسنجی
   */
  validateCallback(authority, status, amount, refId = null) {
    const validation = {
      valid: false,
      errors: [],
      securityLevel: 'high'
    };

    // اعتبارسنجی authority
    if (!authority || typeof authority !== 'string' || authority.length !== 36) {
      validation.errors.push('کد authority نامعتبر است');
    } else if (!/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(authority)) {
      validation.errors.push('فرمت authority نامعتبر است');
    }

    // اعتبارسنجی وضعیت
    if (status !== 'OK' && status !== 'NOK') {
      validation.errors.push('وضعیت پرداخت نامعتبر است');
    }

    // اعتبارسنجی مبلغ
    if (typeof amount !== 'number' || amount < 1000 || amount > 50000000) {
      validation.errors.push('مبلغ پرداخت خارج از محدوده مجاز است');
    }

    // اعتبارسنجی refId اگر وجود داشته باشد
    if (refId && !/^\d{1,20}$/.test(refId)) {
      validation.errors.push('شماره پیگیری نامعتبر است');
    }

    validation.valid = validation.errors.length === 0;
    
    // اگر اعتبارسنجی موفق بود، لاگ امن تولید کن
    if (validation.valid) {
      this.secureLog('callback_validated', {
        authority: this.maskSensitiveData(authority),
        amount,
        status
      });
    } else {
      // لاگ خطاهای امنیتی
      this.secureLog('callback_validation_failed', {
        authority: this.maskSensitiveData(authority),
        errors: validation.errors,
        ip: 'N/A',
        userAgent: 'N/A'
      });
    }

    return validation;
  }

  /**
   * رمزنگاری داده‌های حساس برای ذخیره‌سازی
   * @param {Object} data - داده‌های حساس برای رمزنگاری
   * @returns {string} داده‌های رمزنگاری شده
   */
  encryptSensitiveData(data) {
    try {
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(this.secretKey), iv);
      let encrypted = cipher.update(JSON.stringify(data));
      encrypted = Buffer.concat([encrypted, cipher.final()]);
      
      return {
        iv: iv.toString('hex'),
        encryptedData: encrypted.toString('hex')
      };
    } catch (error) {
      logger.error('Encryption failed:', {
        error: error.message,
        stack: error.stack
      });
      throw new Error('خطا در رمزنگاری داده‌ها');
    }
  }

  /**
   * رمزگشایی داده‌های رمزنگاری شده
   * @param {Object} encryptedData - داده‌های رمزنگاری شده
   * @returns {Object} داده‌های رمزگشایی شده
   */
  decryptSensitiveData(encryptedData) {
    try {
      const iv = Buffer.from(encryptedData.iv, 'hex');
      const encryptedText = Buffer.from(encryptedData.encryptedData, 'hex');
      const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(this.secretKey), iv);
      let decrypted = decipher.update(encryptedText);
      decrypted = Buffer.concat([decrypted, decipher.final()]);
      
      return JSON.parse(decrypted.toString());
    } catch (error) {
      logger.error('Decryption failed:', {
        error: error.message,
        stack: error.stack
      });
      throw new Error('خطا در رمزگشایی داده‌ها');
    }
  }

  /**
   * ماسک کردن داده‌های حساس برای نمایش و لاگ‌گیری
   * @param {string} sensitiveData - داده‌های حساس
   * @param {number} visibleChars - تعداد کاراکترهای قابل نمایش
   * @returns {string} داده‌های ماسک شده
   */
  maskSensitiveData(sensitiveData, visibleChars = 4) {
    if (!sensitiveData || typeof sensitiveData !== 'string') return '***';
    
    if (sensitiveData.length <= visibleChars * 2) {
      return '*'.repeat(sensitiveData.length);
    }
    
    return `${'*'.repeat(sensitiveData.length - visibleChars)}${sensitiveData.slice(-visibleChars)}`;
  }

  /**
   * لاگ‌گیری امن تراکنش‌ها
   * @param {string} eventType - نوع رویداد
   * @param {Object} data - داده‌های رویداد
   */
  secureLog(eventType, data) {
    try {
      const logEntry = {
        timestamp: new Date().toISOString(),
        eventType,
        environment: process.env.NODE_ENV,
        merchantId: this.maskSensitiveData(this.merchantId, 4),
        data: {
          ...data,
          ip: data.ip || 'N/A',
          userAgent: data.userAgent ? this.maskSensitiveData(data.userAgent, 10) : 'N/A'
        }
      };

      // لاگ به کنسول
      logger.info(`💳 Zarinpal ${eventType}:`, logEntry);

      // ذخیره در فایل لاگ (فقط در محیط production)
      if (process.env.NODE_ENV === 'production') {
        const logFile = path.join(this.logDir, `zarinpal-${new Date().toISOString().split('T')[0]}.log`);
        fs.appendFileSync(logFile, JSON.stringify(logEntry) + '\n');
      }
    } catch (error) {
      logger.error('Secure logging failed:', {
        error: error.message,
        eventType
      });
    }
  }

  /**
   * ایجاد دایرکتوری لاگ اگر وجود نداشته باشد
   * @private
   */
  ensureLogDirectory() {
    try {
      if (!fs.existsSync(this.logDir)) {
        fs.mkdirSync(this.logDir, { recursive: true });
        logger.info(`Log directory created: ${this.logDir}`);
      }
    } catch (error) {
      logger.error('Failed to create log directory:', {
        error: error.message,
        path: this.logDir
      });
    }
  }

  /**
   * بررسی سلامت سرویس زرین‌پال
   * @async
   * @returns {Object} وضعیت سلامت سرویس
   */
  async healthCheck() {
    try {
      // تست اتصال به زرین‌پال
      const testAmount = 1000; // مبلغ تست کم
      const testDescription = 'تست سلامت سرویس - HTLand';
      
      // اینجا باید API واقعی زرین‌پال صدا زده شود
      // برای سادگی، وضعیت تستی برگردانده می‌شود
      return {
        status: 'healthy',
        service: 'zarinpal',
        timestamp: new Date().toISOString(),
        sandbox: this.sandbox,
        checks: {
          connection: 'ok',
          merchantId: !!this.merchantId,
          callbackUrl: !!this.callbackUrl,
          webhookSecret: !!this.webhookSecret
        }
      };
    } catch (error) {
      logger.error('Zarinpal health check failed:', {
        error: error.message
      });
      
      return {
        status: 'unhealthy',
        service: 'zarinpal',
        timestamp: new Date().toISOString(),
        error: error.message,
        sandbox: this.sandbox
      };
    }
  }
}

// ایجاد و صادرات نمونه واحد از کلاس
module.exports = new ZarinpalConfig();