/**
 * @file تست‌های احراز هویت HTLand
 * @description تست واحد و یکپارچگی ماژول احراز هویت
 * @since 1.0.0
 */

const mongoose = require('mongoose');
const request = require('supertest');
const app = require('../app');
const User = require('../models/User.model');
const authService = require('../services/authService');

/**
 * قبل از اجرای تست‌ها
 */
beforeAll(async () => {
  // اتصال به دیتابیس تست
  await mongoose.connect(process.env.TEST_MONGODB_URI || 'mongodb://localhost:27017/htland_test');
});

/**
 * بعد از هر تست
 */
afterEach(async () => {
  // پاک کردن تمام کاربران
  await User.deleteMany({});
});

/**
 * بعد از اتمام تست‌ها
 */
afterAll(async () => {
  // بستن اتصال دیتابیس
  await mongoose.connection.close();
  await authService.disconnect();
});

describe('ماژول احراز هویت HTLand', () => {
  
  describe('مدل User', () => {
    test('ایجاد کاربر جدید با شماره موبایل معتبر', async () => {
      const userData = {
        phone: '09123456789',
        firstName: 'علی',
        lastName: 'محمدی',
        email: 'ali@example.com'
      };
      
      const user = new User(userData);
      const savedUser = await user.save();
      
      expect(savedUser._id).toBeDefined();
      expect(savedUser.phone).toBe('09123456789');
      expect(savedUser.isPhoneVerified).toBe(false);
      expect(savedUser.isActive).toBe(true);
    });
    
    test('شماره موبایل تکراری نباید ذخیره شود', async () => {
      const user1 = new User({ phone: '09123456789' });
      await user1.save();
      
      const user2 = new User({ phone: '09123456789' });
      
      await expect(user2.save()).rejects.toThrow();
    });
    
    test('تولید OTP برای کاربر', async () => {
      const user = new User({ phone: '09123456789' });
      const otpCode = user.generateOTP();
      
      expect(otpCode).toHaveLength(6);
      expect(user.otp.code).toBe(otpCode);
      expect(user.otp.used).toBe(false);
      expect(user.otp.expiresAt).toBeInstanceOf(Date);
    });
    
    test('اعتبارسنجی OTP معتبر', async () => {
      const user = new User({ phone: '09123456789' });
      const otpCode = user.generateOTP();
      await user.save();
      
      const result = user.validateOTP(otpCode);
      
      expect(result.isValid).toBe(true);
      expect(user.otp.used).toBe(true);
      expect(user.isPhoneVerified).toBe(true);
    });
    
    test('اعتبارسنجی OTP نامعتبر', async () => {
      const user = new User({ phone: '09123456789' });
      user.generateOTP();
      
      const result = user.validateOTP('000000');
      
      expect(result.isValid).toBe(false);
      expect(result.reason).toBe('کد OTP نادرست است');
    });
    
    test('تولید توکن JWT', () => {
      const user = new User({ 
        phone: '09123456789',
        _id: new mongoose.Types.ObjectId(),
        isAdmin: false
      });
      
      const tokenData = user.generateAuthToken('Test Device', '127.0.0.1');
      
      expect(tokenData.token).toBeDefined();
      expect(tokenData.expiresAt).toBeInstanceOf(Date);
      expect(tokenData.sessionId).toBeDefined();
      expect(user.sessions).toHaveLength(1);
    });
  });
  
  describe('API Auth Endpoints', () => {
    test('ارسال OTP برای شماره جدید', async () => {
      const response = await request(app)
        .post('/api/auth/send-otp')
        .send({ phone: '09123456789' })
        .expect('Content-Type', /json/)
        .expect(200);
      
      expect(response.body.success).toBe(true);
      expect(response.body.message).toContain('کد تأیید');
      expect(response.body.data.isNewUser).toBe(true);
    });
    
    test('تأیید OTP و ورود موفق', async () => {
      // ارسال OTP
      await request(app)
        .post('/api/auth/send-otp')
        .send({ phone: '09123456789' });
      
      // تأیید OTP (در محیط توسعه کد 123456 است)
      const response = await request(app)
        .post('/api/auth/verify-otp')
        .send({ 
          phone: '09123456789',
          otpCode: '123456',
          acceptedTerms: true,
          acceptedPrivacy: true
        })
        .expect(200);
      
      expect(response.body.success).toBe(true);
      expect(response.body.data.token).toBeDefined();
      expect(response.body.data.user.phone).toBe('09123456789');
    });
    
    test('تأیید OTP با کد نادرست', async () => {
      await request(app)
        .post('/api/auth/send-otp')
        .send({ phone: '09123456789' });
      
      const response = await request(app)
        .post('/api/auth/verify-otp')
        .send({ 
          phone: '09123456789',
          otpCode: '000000'
        })
        .expect(400);
      
      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('کد OTP نادرست');
    });
    
    test('دریافت پروفایل با توکن معتبر', async () => {
      // ثبت‌نام و دریافت توکن
      const registerResponse = await request(app)
        .post('/api/auth/send-otp')
        .send({ phone: '09123456789' });
      
      const loginResponse = await request(app)
        .post('/api/auth/verify-otp')
        .send({ 
          phone: '09123456789',
          otpCode: '123456'
        });
      
      const token = loginResponse.body.data.token;
      
      // دریافت پروفایل
      const profileResponse = await request(app)
        .get('/api/auth/profile')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);
      
      expect(profileResponse.body.success).toBe(true);
      expect(profileResponse.body.data.user.phone).toBe('09123456789');
    });
    
    test('دریافت پروفایل بدون توکن', async () => {
      await request(app)
        .get('/api/auth/profile')
        .expect(401);
    });
    
    test('افزودن آدرس جدید', async () => {
      // ورود و دریافت توکن
      await request(app)
        .post('/api/auth/send-otp')
        .send({ phone: '09123456789' });
      
      const loginResponse = await request(app)
        .post('/api/auth/verify-otp')
        .send({ 
          phone: '09123456789',
          otpCode: '123456'
        });
      
      const token = loginResponse.body.data.token;
      
      // افزودن آدرس
      const addressData = {
        title: 'خانه',
        province: 'مازندران',
        city: 'ساری',
        postalCode: '4816698765',
        address: 'بلوار طالقانی، برج پاسارگاد',
        receiverName: 'علی محمدی',
        receiverPhone: '09123456789',
        isDefault: true
      };
      
      const response = await request(app)
        .post('/api/auth/addresses')
        .set('Authorization', `Bearer ${token}`)
        .send(addressData)
        .expect(201);
      
      expect(response.body.success).toBe(true);
      expect(response.body.data.address.title).toBe('خانه');
      expect(response.body.data.address.isDefault).toBe(true);
    });
  });
  
  describe('سرویس AuthService', () => {
    test('بررسی اعتبار شماره موبایل ایرانی', () => {
      expect(authService.validateIranianPhone('09123456789')).toBe(true);
      expect(authService.validateIranianPhone('9123456789')).toBe(false);
      expect(authService.validateIranianPhone('02123456789')).toBe(false);
    });
    
    test('بررسی قدرت رمز عبور', () => {
      const weakPass = authService.checkPasswordStrength('123456');
      expect(weakPass.isValid).toBe(false);
      expect(weakPass.strength).toBe('ضعیف');
      
      const strongPass = authService.checkPasswordStrength('Ali@123456');
      expect(strongPass.isValid).toBe(true);
      expect(strongPass.strength).toBe('قوی');
    });
    
    test('پاکسازی ورودی کاربر', () => {
      const dangerousInput = '<script>alert("xss")</script>سلام';
      const sanitized = authService.sanitizeInput(dangerousInput);
      
      expect(sanitized).not.toContain('<script>');
      expect(sanitized).not.toContain('alert');
    });
  });
});