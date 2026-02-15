// tests/error-handling.test.js - Production Error Handling Tests
const request = require('supertest');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const { MongoMemoryServer } = require('mongodb-memory-server');
const app = require('../src/app');
const config = require('../src/config/env.config');
const { ErrorBuilder } = require('../src/utils/error-builder');

describe('🎯 Production Error Handling', () => {
  let mongoServer;
  let authToken;
  let invalidToken;

  beforeAll(async () => {
    // 🗄️ In-memory MongoDB for testing
    mongoServer = await MongoMemoryServer.create();
    const mongoUri = mongoServer.getUri();
    
    process.env.MONGODB_URI = mongoUri;
    process.env.NODE_ENV = 'test';
    process.env.JWT_SECRET = 'test-secret-minimum-32-chars-long-here';
    
    // 🔐 Generate test tokens
    authToken = jwt.sign(
      { userId: 'test-user-id', type: 'access' },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    
    invalidToken = 'invalid.jwt.token.here';
  });

  afterAll(async () => {
    await mongoose.disconnect();
    await mongoServer.stop();
  });

  describe('🔐 Authentication Errors', () => {
    test('should return 401 for missing token', async () => {
      const response = await request(app)
        .get('/api/v1/wallet/balance')
        .expect(401);
      
      expect(response.body.success).toBe(false);
      expect(response.body.error.message).toBe('توکن احراز هویت ارسال نشده');
      expect(response.body.error.code).toBe('AUTH_REQUIRED');
      expect(response.body.error.stack).toBeUndefined(); // 🛡️ No stack trace
    });

    test('should return 401 for invalid token', async () => {
      const response = await request(app)
        .get('/api/v1/wallet/balance')
        .set('Authorization', `Bearer ${invalidToken}`)
        .expect(401);
      
      expect(response.body.success).toBe(false);
      expect(response.body.error.message).toBe('توکن نامعتبر یا منقضی شده');
      expect(response.body.error.code).toBe('INVALID_TOKEN');
      expect(response.body.error.details).toBeUndefined(); // 🛡️ No JWT details
    });

    test('should return 401 for expired token', async () => {
      const expiredToken = jwt.sign(
        { userId: 'test-user-id', type: 'access' },
        process.env.JWT_SECRET,
        { expiresIn: '-1h' } // Already expired
      );
      
      const response = await request(app)
        .get('/api/v1/wallet/balance')
        .set('Authorization', `Bearer ${expiredToken}`)
        .expect(401);
      
      expect(response.body.success).toBe(false);
      expect(response.body.error.message).toBe('توکن نامعتبر یا منقضی شده');
      expect(response.body.error.code).toBe('INVALID_TOKEN');
    });
  });

  describe('📝 Validation Errors', () => {
    test('should return 400 for invalid product creation', async () => {
      const invalidProduct = {
        name: 'AB', // Too short
        price: -100, // Negative price
        category: 'invalid-category'
      };
      
      const response = await request(app)
        .post('/api/v1/products')
        .set('Authorization', `Bearer ${authToken}`)
        .send(invalidProduct)
        .expect(400);
      
      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('VALIDATION_ERROR');
      expect(response.body.error.validation).toBeDefined();
      expect(response.body.error.validation.length).toBeGreaterThan(0);
      
      // 🎯 Verify user-friendly messages
      const validationErrors = response.body.error.validation;
      expect(validationErrors).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            field: 'name',
            message: expect.stringContaining('حداقل ۳ کاراکتر')
          }),
          expect.objectContaining({
            field: 'price',
            message: expect.stringContaining('کمتر از ۱۰۰۰ تومان')
          }),
          expect.objectContaining({
            field: 'category',
            message: expect.stringContaining('دسته‌بندی نامعتبر')
          })
        ])
      );
    });

    test('should return 400 for malformed JSON', async () => {
      const response = await request(app)
        .post('/api/v1/products')
        .set('Authorization', `Bearer ${authToken}`)
        .set('Content-Type', 'application/json')
        .send('{"invalid": json,}')
        .expect(400);
      
      expect(response.body.success).toBe(false);
      expect(response.body.error.message).toBe('JSON ارسالی نامعتبر است');
      expect(response.body.error.code).toBe('INVALID_JSON');
    });

    test('should return 400 for invalid MongoDB ID', async () => {
      const response = await request(app)
        .get('/api/v1/products/invalid-id-format')
        .expect(400);
      
      expect(response.body.success).toBe(false);
      expect(response.body.error.message).toContain('شناسه');
      expect(response.body.error.message).toContain('نامعتبر');
      expect(response.body.error.code).toBe('INVALID_ID');
    });
  });

  describe('🔍 Authorization Errors', () => {
    test('should return 403 for insufficient permissions', async () => {
      // Mock user with limited permissions
      const userToken = jwt.sign(
        { 
          userId: 'regular-user-id', 
          type: 'access',
          role: 'user' // Not admin
        },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );
      
      const response = await request(app)
        .delete('/api/v1/products/some-product-id')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(403);
      
      expect(response.body.success).toBe(false);
      expect(response.body.error.message).toBe('دسترسی غیرمجاز');
      expect(response.body.error.code).toBe('FORBIDDEN');
    });
  });

  describe('🔎 Not Found Errors', () => {
    test('should return 404 for non-existent route', async () => {
      const response = await request(app)
        .get('/api/v1/non-existent-route')
        .expect(404);
      
      expect(response.body.success).toBe(false);
      expect(response.body.error.message).toContain('پیدا نشد');
      expect(response.body.error.code).toBe('NOT_FOUND');
      expect(response.body.error.requestId).toBeDefined();
    });

    test('should return 404 for non-existent resource', async () => {
      const validId = new mongoose.Types.ObjectId();
      
      const response = await request(app)
        .get(`/api/v1/products/${validId}`)
        .expect(404);
      
      expect(response.body.success).toBe(false);
      expect(response.body.error.message).toContain('یافت نشد');
      expect(response.body.error.code).toBe('NOT_FOUND');
    });
  });

  describe('⏱️ Rate Limiting Errors', () => {
    test('should return 429 for too many requests', async () => {
      const requests = Array(6).fill().map(() => 
        request(app)
          .post('/api/v1/auth/login')
          .send({
            email: 'test@example.com',
            password: 'wrongpassword'
          })
      );
      
      // Execute first 5 requests (should succeed)
      const results = await Promise.all(requests.slice(0, 5));
      results.forEach(res => {
        expect(res.status).not.toBe(429);
      });
      
      // 6th request should be rate limited
      const response = await requests[5];
      expect(response.status).toBe(429);
      expect(response.body.success).toBe(false);
      expect(response.body.error.message).toContain('تعداد درخواست‌های شما');
      expect(response.body.error.code).toBe('RATE_LIMIT_EXCEEDED');
    });
  });

  describe('💳 Business Logic Errors', () => {
    test('should return 400 for insufficient balance', async () => {
      const response = await request(app)
        .post('/api/v1/wallet/withdraw')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          amount: 1000000, // Large amount
          currency: 'IRR'
        })
        .expect(400);
      
      expect(response.body.success).toBe(false);
      expect(response.body.error.message).toBe('موجودی کافی نیست');
      expect(response.body.error.code).toBe('INSUFFICIENT_BALANCE');
      expect(response.body.error.details).toBeDefined();
    });

    test('should return 402 for payment failure', async () => {
      const response = await request(app)
        .post('/api/v1/payments/process')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          amount: 50000,
          gateway: 'zarinpal'
        })
        .expect(402);
      
      expect(response.body.success).toBe(false);
      expect(response.body.error.message).toBe('پرداخت ناموفق بود');
      expect(response.body.error.code).toBe('PAYMENT_FAILED');
    });
  });

  describe('🛡️ Security & Error Exposure', () => {
    test('should not expose stack traces in production', async () => {
      // Simulate production environment
      process.env.NODE_ENV = 'production';
      
      const response = await request(app)
        .get('/api/v1/wallet/balance')
        .expect(401); // No auth token
      
      expect(response.body.success).toBe(false);
      expect(response.body.error.stack).toBeUndefined();
      expect(response.body.error.details).toBeUndefined();
      
      // Reset to test environment
      process.env.NODE_ENV = 'test';
    });

    test('should include request ID in all error responses', async () => {
      const response = await request(app)
        .get('/non-existent')
        .expect(404);
      
      expect(response.body.success).toBe(false);
      expect(response.body.error.requestId).toBeDefined();
      expect(typeof response.body.error.requestId).toBe('string');
    });

    test('should mask sensitive error details', async () => {
      // Test that database errors don't expose internal info
      const response = await request(app)
        .post('/api/v1/products')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          name: 'Test Product',
          price: 1000,
          category: 'rice',
          sku: 'TEST-123' // Might cause duplicate error
        });
      
      if (response.status === 409) {
        // Duplicate key error
        expect(response.body.error.message).not.toContain('MongoError');
        expect(response.body.error.message).not.toContain('E11000');
        expect(response.body.error.code).toBe('DUPLICATE_KEY_ERROR');
      }
    });
  });

  describe('📊 Error Response Structure Consistency', () => {
    test('all error responses should have consistent structure', async () => {
      const testCases = [
        { method: 'GET', path: '/api/v1/wallet/balance', expectedStatus: 401 },
        { method: 'GET', path: '/non-existent-route', expectedStatus: 404 },
        { method: 'POST', path: '/api/v1/products', body: {}, expectedStatus: 400 }
      ];
      
      for (const testCase of testCases) {
        const response = await request(app)[testCase.method.toLowerCase()](testCase.path)
          .send(testCase.body || {})
          .expect(testCase.expectedStatus);
        
        // 🎯 Verify consistent structure
        expect(response.body).toHaveProperty('success', false);
        expect(response.body).toHaveProperty('error');
        expect(response.body.error).toHaveProperty('message');
        expect(response.body.error).toHaveProperty('code');
        expect(response.body.error).toHaveProperty('timestamp');
        expect(response.body.error).toHaveProperty('requestId');
        
        // 🛡️ No internal details
        expect(response.body.error).not.toHaveProperty('stack');
        expect(response.body.error).not.toHaveProperty('originalError');
      }
    });
  });
});

// 🧪 Helper function tests
describe('ErrorBuilder Utility', () => {
  test('should create validation error with proper structure', () => {
    const errors = [
      { field: 'email', message: 'ایمیل نامعتبر است', type: 'string.email' }
    ];
    
    const error = ErrorBuilder.validationError(errors);
    
    expect(error.statusCode).toBe(400);
    expect(error.code).toBe('VALIDATION_ERROR');
    expect(error.details).toEqual({ validationErrors: errors });
    expect(error.isOperational).toBe(true);
  });

  test('should create not found error with ID', () => {
    const error = ErrorBuilder.notFound('کاربر', '12345');
    
    expect(error.statusCode).toBe(404);
    expect(error.code).toBe('NOT_FOUND');
    expect(error.message).toContain('کاربر');
    expect(error.message).toContain('12345');
  });

  test('should mask internal errors in production', () => {
    process.env.NODE_ENV = 'production';
    
    const originalError = new Error('Database connection failed');
    const error = ErrorBuilder.fromUnknown(originalError);
    
    expect(error.message).toBe('خطای داخلی سرور');
    expect(error.details).toBeNull();
    
    process.env.NODE_ENV = 'test';
  });
});