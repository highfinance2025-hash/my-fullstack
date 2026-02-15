// tests/integration/auth.integration.test.js
const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../../app');
const User = require('../../models/User.model');
const Token = require('../../models/Token.model');
const { redisClient } = require('../../config/redis.config');

describe('🔐 Auth Integration Tests', () => {
  beforeAll(async () => {
    await mongoose.connect(process.env.MONGODB_TEST_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    await redisClient.connect();
  });

  afterAll(async () => {
    await mongoose.connection.close();
    await redisClient.disconnect();
  });

  beforeEach(async () => {
    await User.deleteMany({});
    await Token.deleteMany({});
    await redisClient.flushAll();
  });

  describe('ثبت‌نام و احراز هویت', () => {
    it('باید کاربر جدید ثبت‌نام کند و توکن بازگرداند', async () => {
      const userData = {
        phone: '09123456789',
        firstName: 'علی',
        lastName: 'محمدی',
        password: 'StrongPass@123',
        confirmPassword: 'StrongPass@123'
      };

      const response = await request(app)
        .post('/api/v1/auth/register')
        .send(userData)
        .expect(201);

      expect(response.body.success).toBe(true);
      expect(response.body.data.token).toBeDefined();
      expect(response.body.data.user.phone).toBe(userData.phone);
      expect(response.body.data.user.password).toBeUndefined();

      // بررسی ذخیره شدن در دیتابیس
      const user = await User.findOne({ phone: userData.phone });
      expect(user).toBeTruthy();
      expect(user.isPhoneVerified).toBe(true);

      // بررسی ذخیره شدن توکن در Redis
      const tokenKey = `auth:token:${response.body.data.token}`;
      const cachedToken = await redisClient.get(tokenKey);
      expect(cachedToken).toBeTruthy();
    });

    it('باید خطای تکراری بودن شماره موبایل بدهد', async () => {
      await User.create({
        phone: '09123456789',
        firstName: 'قدیمی',
        lastName: 'کاربر'
      });

      const response = await request(app)
        .post('/api/v1/auth/register')
        .send({
          phone: '09123456789',
          firstName: 'جدید',
          lastName: 'کاربر'
        })
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('تکراری');
    });

    it('باید خطای رمز عبور ضعیف بدهد', async () => {
      const response = await request(app)
        .post('/api/v1/auth/register')
        .send({
          phone: '09123456789',
          password: '123'
        })
        .expect(400);

      expect(response.body.details).toBeDefined();
      expect(response.body.details[0].field).toBe('password');
    });
  });

  describe('ورود و مدیریت نشست', () => {
    let user;
    let loginResponse;

    beforeEach(async () => {
      user = await User.create({
        phone: '09123456789',
        firstName: 'تست',
        lastName: 'کاربر',
        password: 'StrongPass@123'
      });

      loginResponse = await request(app)
        .post('/api/v1/auth/login')
        .send({
          phone: '09123456789',
          password: 'StrongPass@123'
        })
        .expect(200);
    });

    it('باید با اطلاعات صحیح وارد شود', async () => {
      expect(loginResponse.body.success).toBe(true);
      expect(loginResponse.body.data.token).toBeDefined();
      expect(loginResponse.body.data.refreshToken).toBeDefined();
    });

    it('باید با توکن معتبر به پروفایل دسترسی داشته باشد', async () => {
      const token = loginResponse.body.data.token;

      const profileResponse = await request(app)
        .get('/api/v1/auth/profile')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(profileResponse.body.data.user.phone).toBe(user.phone);
    });

    it('باید با توکن نامعتبر دسترسی رد کند', async () => {
      const response = await request(app)
        .get('/api/v1/auth/profile')
        .set('Authorization', 'Bearer invalid-token')
        .expect(401);

      expect(response.body.error).toContain('دسترسی');
    });

    it('باید توکن را refresh کند', async () => {
      const refreshToken = loginResponse.body.data.refreshToken;

      const refreshResponse = await request(app)
        .post('/api/v1/auth/refresh')
        .set('Authorization', `Bearer ${refreshToken}`)
        .expect(200);

      expect(refreshResponse.body.data.token).toBeDefined();
      expect(refreshResponse.body.data.token).not.toBe(loginResponse.body.data.token);
    });

    it('باید با logout از همه دستگاه‌ها خارج شود', async () => {
      const token = loginResponse.body.data.token;

      // ایجاد یک نشست دیگر
      await request(app)
        .post('/api/v1/auth/login')
        .send({
          phone: '09123456789',
          password: 'StrongPass@123'
        });

      // logout از همه دستگاه‌ها
      await request(app)
        .post('/api/v1/auth/logout-all')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      // بررسی اینکه توکن قبلی کار نکند
      await request(app)
        .get('/api/v1/auth/profile')
        .set('Authorization', `Bearer ${token}`)
        .expect(401);

      // بررسی تعداد نشست‌های فعال
      const sessions = await Token.find({ user: user._id, revoked: false });
      expect(sessions.length).toBe(0);
    });
  });

  describe('Rate Limiting و Brute Force Protection', () => {
    it('باید پس از ۵ تلاش ناموفق حساب را قفل کند', async () => {
      for (let i = 0; i < 5; i++) {
        await request(app)
          .post('/api/v1/auth/login')
          .send({
            phone: '09123456789',
            password: 'wrong-password'
          })
          .expect(401);
      }

      // تلاش ششم باید حساب قفل شده باشد
      const response = await request(app)
        .post('/api/v1/auth/login')
        .send({
          phone: '09123456789',
          password: 'wrong-password'
        })
        .expect(429);

      expect(response.body.error).toContain('قفل');
    });

    it('باید Rate Limiting را روی endpointهای حساس اعمال کند', async () => {
      const requests = Array.from({ length: 101 }, () =>
        request(app)
          .post('/api/v1/auth/login')
          .send({
            phone: '09111111111',
            password: 'test'
          })
      );

      const responses = await Promise.all(requests);
      const rateLimited = responses.filter(r => r.status === 429);
      
      expect(rateLimited.length).toBeGreaterThan(0);
    });
  });

  describe('امنیت و حمله‌های رایج', () => {
    it('باید در برابر SQL Injection محافظت کند', async () => {
      const maliciousInput = {
        phone: "09123456789' OR '1'='1",
        password: "anything' OR '1'='1"
      };

      const response = await request(app)
        .post('/api/v1/auth/login')
        .send(maliciousInput)
        .expect(400);

      expect(response.body.success).toBe(false);
    });

    it('باید در برابر XSS محافظت کند', async () => {
      const xssPayload = {
        firstName: "<script>alert('xss')</script>",
        lastName: "<img src=x onerror=alert(1)>",
        phone: '09123456789',
        password: 'Test@123'
      };

      const response = await request(app)
        .post('/api/v1/auth/register')
        .send(xssPayload)
        .expect(201);

      // بررسی اینکه payloadهای خطرناک ذخیره نشده‌اند
      const user = await User.findOne({ phone: '09123456789' });
      expect(user.firstName).not.toContain('<script>');
      expect(user.lastName).not.toContain('onerror');
    });

    it('باید از CSRF محافظت کند', async () => {
      // درخواست بدون توکن باید رد شود
      const response = await request(app)
        .post('/api/v1/auth/logout')
        .expect(401);

      expect(response.body.error).toContain('توکن');
    });
  });

  describe('حالت‌های خطا و بازیابی', () => {
    it('باید کاربر غیرفعال نتواند وارد شود', async () => {
      await User.create({
        phone: '09123456789',
        firstName: 'غیرفعال',
        lastName: 'کاربر',
        isActive: false
      });

      const response = await request(app)
        .post('/api/v1/auth/login')
        .send({
          phone: '09123456789',
          password: 'Test@123'
        })
        .expect(403);

      expect(response.body.error).toContain('غیرفعال');
    });

    it('باید بازیابی رمز عبور کار کند', async () => {
      const user = await User.create({
        phone: '09123456789',
        email: 'test@example.com',
        firstName: 'تست'
      });

      // درخواست OTP
      const otpResponse = await request(app)
        .post('/api/v1/auth/forgot-password')
        .send({ phone: '09123456789' })
        .expect(200);

      expect(otpResponse.body.success).toBe(true);

      // بازیابی رمز عبور با OTP
      const resetResponse = await request(app)
        .post('/api/v1/auth/reset-password')
        .send({
          phone: '09123456789',
          otp: '123456', // در تست کد ثابت است
          newPassword: 'NewPass@123'
        })
        .expect(200);

      expect(resetResponse.body.success).toBe(true);

      // ورود با رمز عبور جدید
      const loginResponse = await request(app)
        .post('/api/v1/auth/login')
        .send({
          phone: '09123456789',
          password: 'NewPass@123'
        })
        .expect(200);

      expect(loginResponse.body.data.token).toBeDefined();
    });
  });
});