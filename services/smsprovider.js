/**
 * @file سرویس ارسال پیامک HTLand
 * @description ارسال پیامک‌های OTP و اطلاع‌رسانی
 * @since 1.0.0
 */

const axios = require('axios');
const logger = require('../config/logger');

/**
 * @class SMSProvider
 * @description سرویس ارسال پیامک با پنل‌های مختلف
 */
class SMSProvider {
  constructor() {
    // انتخاب پنل پیامک بر اساس تنظیمات
    this.provider = process.env.SMS_PROVIDER || 'kavenegar'; // kavenegar, ghasedak, etc.
    
    // تنظیمات پنل‌های مختلف
    this.providers = {
      kavenegar: {
        baseURL: 'https://api.kavenegar.com/v1',
        sendEndpoint: '/sms/send.json',
        lookupEndpoint: '/verify/lookup.json'
      },
      ghasedak: {
        baseURL: 'https://api.ghasedak.me/v2',
        sendEndpoint: '/sms/send/simple',
        lookupEndpoint: '/verification/send/simple'
      },
      // در محیط توسعه از سرویس mock استفاده می‌کنیم
      mock: {
        baseURL: 'http://localhost:3000/mock',
        sendEndpoint: '/sms'
      }
    };
    
    // کلید API
    this.apiKey = process.env.SMS_API_KEY;
    
    // ایجاد HTTP client
    this.client = axios.create({
      timeout: 10000,
      headers: {
        'Content-Type': 'application/json'
      }
    });
  }
  
  /**
   * ارسال پیامک معمولی
   * @param {string} phone - شماره موبایل
   * @param {string} message - متن پیامک
   * @returns {Promise<boolean>} - موفقیت آمیز بودن ارسال
   */
  async sendSMS(phone, message) {
    try {
      // در محیط توسعه یا بدون کلید API، mock می‌شود
      if (process.env.NODE_ENV !== 'production' || !this.apiKey || this.provider === 'mock') {
        logger.info(`[MOCK SMS] To: ${phone}, Message: ${message}`);
        return true;
      }
      
      const providerConfig = this.providers[this.provider];
      if (!providerConfig) {
        throw new Error(`SMS provider '${this.provider}' not configured`);
      }
      
      let response;
      
      switch (this.provider) {
        case 'kavenegar':
          response = await this.client.post(
            `${providerConfig.baseURL}/${this.apiKey}${providerConfig.sendEndpoint}`,
            {
              receptor: phone,
              message: message
            }
          );
          break;
          
        case 'ghasedak':
          response = await this.client.post(
            `${providerConfig.baseURL}${providerConfig.sendEndpoint}`,
            {
              receptor: phone,
              message: message,
              linenumber: process.env.SMS_LINE_NUMBER || '300077329'
            },
            {
              headers: {
                'apikey': this.apiKey
              }
            }
          );
          break;
          
        default:
          throw new Error(`Unsupported SMS provider: ${this.provider}`);
      }
      
      const success = response.status === 200;
      
      if (!success) {
        logger.error(`SMS sending failed: ${response.status}`, {
          phone,
          provider: this.provider,
          status: response.status
        });
      }
      
      return success;
      
    } catch (error) {
      logger.error('Error sending SMS:', {
        error: error.message,
        phone,
        provider: this.provider
      });
      return false;
    }
  }
  
  /**
   * ارسال پیامک OTP با تمپلیت
   * @param {string} phone - شماره موبایل
   * @param {string} otpCode - کد OTP
   * @param {string} template - نام تمپلیت
   * @returns {Promise<boolean>} - موفقیت آمیز بودن ارسال
   */
  async sendOTP(phone, otpCode, template = 'otp') {
    try {
      if (process.env.NODE_ENV !== 'production' || !this.apiKey || this.provider === 'mock') {
        logger.info(`[MOCK OTP] To: ${phone}, Code: ${otpCode}`);
        return true;
      }
      
      const providerConfig = this.providers[this.provider];
      if (!providerConfig) {
        throw new Error(`SMS provider '${this.provider}' not configured`);
      }
      
      let response;
      
      switch (this.provider) {
        case 'kavenegar':
          response = await this.client.post(
            `${providerConfig.baseURL}/${this.apiKey}${providerConfig.lookupEndpoint}`,
            {
              receptor: phone,
              token: otpCode,
              template: template
            }
          );
          break;
          
        case 'ghasedak':
          response = await this.client.post(
            `${providerConfig.baseURL}${providerConfig.lookupEndpoint}`,
            {
              receptor: phone,
              type: '1',
              template: template,
              param1: otpCode
            },
            {
              headers: {
                'apikey': this.apiKey
              }
            }
          );
          break;
          
        default:
          // اگر پنل از تمپلیت پشتیبانی نمی‌کند، پیامک معمولی بفرست
          const message = `کد تأیید HTLand: ${otpCode}
این کد ۵ دقیقه اعتبار دارد.`;
          return await this.sendSMS(phone, message);
      }
      
      const success = response.status === 200;
      
      if (!success) {
        logger.error(`OTP sending failed: ${response.status}`, {
          phone,
          provider: this.provider,
          status: response.status
        });
      }
      
      return success;
      
    } catch (error) {
      logger.error('Error sending OTP:', {
        error: error.message,
        phone,
        provider: this.provider
      });
      return false;
    }
  }
  
  /**
   * ارسال پیامک اطلاع‌رسانی سفارش
   * @param {string} phone - شماره موبایل
   * @param {string} orderId - شناسه سفارش
   * @param {string} status - وضعیت سفارش
   * @returns {Promise<boolean>} - موفقیت آمیز بودن ارسال
   */
  async sendOrderNotification(phone, orderId, status) {
    const messages = {
      pending: `سفارش شما در HTLand ثبت شد. شماره سفارش: ${orderId}`,
      processing: `سفارش شما در حال آماده‌سازی است. شماره سفارش: ${orderId}`,
      shipped: `سفارش شما ارسال شد. شماره سفارش: ${orderId}`,
      delivered: `سفارش شما تحویل داده شد. شماره سفارش: ${orderId}`,
      cancelled: `سفارش شما لغو شد. شماره سفارش: ${orderId}`
    };
    
    const message = messages[status] || `وضعیت سفارش شما تغییر کرد. شماره سفارش: ${orderId}`;
    
    return await this.sendSMS(phone, message);
  }
  
  /**
   * ارسال پیامک شارژ کیف پول
   * @param {string} phone - شماره موبایل
   * @param {number} amount - مبلغ شارژ
   * @param {string} transactionId - شناسه تراکنش
   * @returns {Promise<boolean>} - موفقیت آمیز بودن ارسال
   */
  async sendWalletChargeNotification(phone, amount, transactionId) {
    const formattedAmount = new Intl.NumberFormat('fa-IR').format(amount);
    const message = `کیف پول HTLand شما به مبلغ ${formattedAmount} تومان شارژ شد.
شناسه تراکنش: ${transactionId}`;
    
    return await this.sendSMS(phone, message);
  }
  
  /**
   * تست اتصال به سرویس پیامک
   * @returns {Promise<Object>} - نتیجه تست
   */
  async testConnection() {
    try {
      if (!this.apiKey || this.provider === 'mock') {
        return {
          success: true,
          provider: this.provider,
          status: 'mock_mode'
        };
      }
      
      const providerConfig = this.providers[this.provider];
      if (!providerConfig) {
        return {
          success: false,
          error: `Provider ${this.provider} not configured`
        };
      }
      
      let response;
      
      switch (this.provider) {
        case 'kavenegar':
          response = await this.client.get(
            `${providerConfig.baseURL}/${this.apiKey}/account/info.json`
          );
          break;
          
        case 'ghasedak':
          response = await this.client.get(
            `${providerConfig.baseURL}/account/info`,
            {
              headers: {
                'apikey': this.apiKey
              }
            }
          );
          break;
          
        default:
          return {
            success: false,
            error: `Test not implemented for ${this.provider}`
          };
      }
      
      return {
        success: response.status === 200,
        provider: this.provider,
        status: response.status,
        data: response.data
      };
      
    } catch (error) {
      return {
        success: false,
        provider: this.provider,
        error: error.message
      };
    }
  }
}

module.exports = SMSProvider;