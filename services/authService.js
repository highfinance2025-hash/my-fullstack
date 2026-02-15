/**
 * @file سرویس احراز هویت HTLand
 * @description عملیات مرتبط با ارسال OTP، rate limiting و مدیریت سشن‌ها
 * @since 1.0.0
 */

const crypto = require('crypto');
const Redis = require('ioredis');
const logger = require('../config/logger');
const SMSProvider = require('./smsProvider');

/**
 * @class AuthService
 * @description سرویس مدیریت عملیات احراز هویت
 */
class AuthService {
  constructor() {
    // اتصال به Redis برای rate limiting
    this.redisClient = new Redis({
      host: process.env.REDIS_HOST || 'localhost',
      port: process.env.REDIS_PORT || 6379,
      password: process.env.REDIS_PASSWORD,
      retryStrategy: times => Math.min(times * 50, 2000)
    });
    
    // سرویس ارسال پیامک
    this.smsProvider = new SMSProvider();
    
    // تنظیمات rate limiting
    this.rateLimits = {
      send_otp: { window: 900, max: 3 }, // 15 دقیقه، ۳ بار
      verify_otp: { window: 300, max: 5 }, // 5 دقیقه، ۵ بار
      forgot_password: { window: 3600, max: 3 } // 1 ساعت، ۳ بار
    };
  }
  
  /**
   * بررسی rate limiting برای عملیات مختلف
   * @param {string} identifier - شناسه (معمولا شماره موبایل)
   * @param {string} action - نوع عملیات
   * @returns {Promise<boolean>} - آیا مجاز است یا نه
   */
  async checkRateLimit(identifier, action) {
    try {
      const limitConfig = this.rateLimits[action];
      if (!limitConfig) return true;
      
      const key = `rate_limit:${action}:${identifier}`;
      const now = Date.now();
      const windowSize = limitConfig.window * 1000; // به میلی‌ثانیه
      
      // دریافت درخواست‌های قبلی
      const requests = await this.redisClient.lrange(key, 0, -1);
      const recentRequests = requests
        .map(timestamp => parseInt(timestamp))
        .filter(timestamp => now - timestamp < windowSize);
      
      // اگر بیش از حد مجاز باشد
      if (recentRequests.length >= limitConfig.max) {
        return false;
      }
      
      // اضافه کردن درخواست جدید
      await this.redisClient.lpush(key, now.toString());
      await this.redisClient.ltrim(key, 0, limitConfig.max - 1);
      await this.redisClient.expire(key, limitConfig.window);
      
      return true;
      
    } catch (error) {
      logger.error('Error in checkRateLimit:', error);
      // در صورت خطا در Redis، rate limiting غیرفعال می‌شود
      return true;
    }
  }
  
  /**
   * ارسال کد OTP از طریق پیامک
   * @param {string} phone - شماره موبایل
   * @param {string} otpCode - کد OTP
   * @returns {Promise<boolean>} - موفقیت آمیز بودن ارسال
   */
  async sendOTPSMS(phone, otpCode) {
    try {
      // در محیط توسعه، فقط لاگ می‌کنیم
      if (process.env.NODE_ENV !== 'production') {
        logger.info(`[DEV] OTP for ${phone}: ${otpCode}`);
        return true;
      }
      
      // در محیط production از سرویس واقعی استفاده می‌کنیم
      const message = `کد تأیید HTLand: ${otpCode}
این کد ۵ دقیقه اعتبار دارد.
www.htland.ir`;
      
      const result = await this.smsProvider.sendSMS(phone, message);
      
      logger.info(`SMS sent to ${phone}: ${result ? 'success' : 'failed'}`);
      return result;
      
    } catch (error) {
      logger.error('Error sending OTP SMS:', error);
      return false;
    }
  }
  
  /**
   * ارسال پیامک بازیابی رمز عبور
   * @param {string} phone - شماره موبایل
   * @param {string} otpCode - کد OTP
   * @returns {Promise<boolean>} - موفقیت آمیز بودن ارسال
   */
  async sendPasswordResetSMS(phone, otpCode) {
    try {
      // در محیط توسعه، فقط لاگ می‌کنیم
      if (process.env.NODE_ENV !== 'production') {
        logger.info(`[DEV] Password reset OTP for ${phone}: ${otpCode}`);
        return true;
      }
      
      // در محیط production از سرویس واقعی استفاده می‌کنیم
      const message = `کد بازیابی رمز عبور HTLand: ${otpCode}
این کد ۵ دقیقه اعتبار دارد.
www.htland.ir`;
      
      const result = await this.smsProvider.sendSMS(phone, message);
      
      logger.info(`Password reset SMS sent to ${phone}: ${result ? 'success' : 'failed'}`);
      return result;
      
    } catch (error) {
      logger.error('Error sending password reset SMS:', error);
      return false;
    }
  }
  
  /**
   * ارسال پیامک خوش‌آمدگویی
   * @param {string} phone - شماره موبایل
   * @param {string} firstName - نام کاربر
   * @returns {Promise<boolean>} - موفقیت آمیز بودن ارسال
   */
  async sendWelcomeSMS(phone, firstName = 'کاربر') {
    try {
      if (process.env.NODE_ENV !== 'production') {
        logger.info(`[DEV] Welcome SMS for ${phone}`);
        return true;
      }
      
      const message = `${firstName} عزیز، به خانواده HTLand خوش آمدید!
سفارش‌های خود را با اطمینان از کیفیت محصولات ارگانیک شمال ثبت کنید.
www.htland.ir`;
      
      const result = await this.smsProvider.sendSMS(phone, message);
      
      logger.info(`Welcome SMS sent to ${phone}`);
      return result;
      
    } catch (error) {
      logger.error('Error sending welcome SMS:', error);
      return false;
    }
  }
  
  /**
   * تولید کد معرف
   * @returns {string} - کد معرف ۸ رقمی
   */
  generateReferralCode() {
    return crypto.randomBytes(4).toString('hex').toUpperCase();
  }
  
  /**
   * بررسی اعتبار شماره موبایل ایرانی
   * @param {string} phone - شماره موبایل
   * @returns {boolean} - معتبر بودن
   */
  validateIranianPhone(phone) {
    return /^09[0-9]{9}$/.test(phone);
  }
  
  /**
   * رمزنگاری داده‌های حساس
   * @param {string} data - داده برای رمزنگاری
   * @returns {string} - داده رمزنگاری شده
   */
  encryptData(data) {
    if (!process.env.ENCRYPTION_KEY) {
      return data;
    }
    
    const algorithm = 'aes-256-gcm';
    const key = crypto.scryptSync(process.env.ENCRYPTION_KEY, 'salt', 32);
    const iv = crypto.randomBytes(16);
    
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
  }
  
  /**
   * رمزگشایی داده‌های حساس
   * @param {string} encryptedData - داده رمزنگاری شده
   * @returns {string} - داده اصلی
   */
  decryptData(encryptedData) {
    if (!process.env.ENCRYPTION_KEY || !encryptedData.includes(':')) {
      return encryptedData;
    }
    
    try {
      const [ivHex, authTagHex, encrypted] = encryptedData.split(':');
      const algorithm = 'aes-256-gcm';
      const key = crypto.scryptSync(process.env.ENCRYPTION_KEY, 'salt', 32);
      const iv = Buffer.from(ivHex, 'hex');
      const authTag = Buffer.from(authTagHex, 'hex');
      
      const decipher = crypto.createDecipheriv(algorithm, key, iv);
      decipher.setAuthTag(authTag);
      
      let decrypted = decipher.update(encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      
      return decrypted;
    } catch (error) {
      logger.error('Error decrypting data:', error);
      throw new Error('رمزگشایی ناموفق بود');
    }
  }
  
  /**
   * تولید هش برای داده‌ها
   * @param {string} data - داده برای هش کردن
   * @returns {string} - هش SHA256
   */
  generateHash(data) {
    return crypto
      .createHash('sha256')
      .update(data + (process.env.HASH_SALT || ''))
      .digest('hex');
  }
  
  /**
   * پاکسازی ورودی کاربر
   * @param {string} input - ورودی کاربر
   * @returns {string} - ورودی پاکسازی شده
   */
  sanitizeInput(input) {
    if (typeof input !== 'string') return input;
    
    return input
      .replace(/[<>]/g, '') // حذف تگ‌های HTML
      .replace(/javascript:/gi, '') // حذف جاوااسکریپت
      .trim();
  }
  
  /**
   * اعتبارسنجی ایمیل
   * @param {string} email - آدرس ایمیل
   * @returns {boolean} - معتبر بودن ایمیل
   */
  validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }
  
  /**
   * بررسی قدرت رمز عبور
   * @param {string} password - رمز عبور
   * @returns {Object} - نتیجه بررسی
   */
  checkPasswordStrength(password) {
    const checks = {
      length: password.length >= 8,
      hasLower: /[a-z]/.test(password),
      hasUpper: /[A-Z]/.test(password),
      hasNumber: /\d/.test(password),
      hasSpecial: /[!@#$%^&*(),.?":{}|<>]/.test(password)
    };
    
    const score = Object.values(checks).filter(Boolean).length;
    let strength = 'ضعیف';
    
    if (score >= 4) strength = 'قوی';
    else if (score >= 3) strength = 'متوسط';
    
    return {
      isValid: score >= 3,
      strength,
      score,
      checks
    };
  }
  
  /**
   * تولید کد تأیید ایمیل
   * @returns {string} - کد ۶ رقمی
   */
  generateEmailVerificationCode() {
    return Math.floor(100000 + Math.random() * 900000).toString();
  }
  
  /**
   * بستن اتصال Redis
   */
  async disconnect() {
    try {
      await this.redisClient.quit();
      logger.info('Redis connection closed');
    } catch (error) {
      logger.error('Error closing Redis connection:', error);
    }
  }
}

// Singleton instance
module.exports = new AuthService();