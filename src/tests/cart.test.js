/**
 * تست‌های واحد برای سبد خرید HTLand
 */

const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../app');
const Cart = require('../models/Cart.model');
const Product = require('../models/Product.model');
const User = require('../models/User.model');

let userToken;
let testUser;
let testProduct1;
let testProduct2;

describe('سیستم سبد خرید HTLand', () => {
  beforeAll(async () => {
    await mongoose.connect(process.env.MONGODB_TEST_URI);
    
    // ایجاد کاربر تستی
    testUser = await User.create({
      name: 'کاربر تست سبد خرید',
      email: 'cart@test.com',
      password: 'password123',
      phone: '09123456789',
      active: true
    });
    
    // دریافت توکن
    const loginRes = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'cart@test.com', password: 'password123' });
    
    userToken = loginRes.body.token;
    
    // ایجاد محصولات تستی
    testProduct1 = await Product.create({
      name: 'برنج تستی ۱',
      description: 'برنج تستی برای سبد خرید',
      price: 50000,
      discountPrice: 45000,
      category: 'rice',
      categoryFa: 'برنج شمال',
      image: 'https://test.com/rice1.jpg',
      stock: 100,
      active: true,
      createdBy: testUser._id
    });
    
    testProduct2 = await Product.create({
      name: 'خاویار تستی',
      description: 'خاویار تستی برای سبد خرید',
      price: 400000,
      category: 'caviar',
      categoryFa: 'خاویار ایرانی',
      image: 'https://test.com/caviar.jpg',
      stock: 50,
      active: true,
      createdBy: testUser._id
    });
  });
  
  afterAll(async () => {
    await mongoose.connection.dropDatabase();
    await mongoose.connection.close();
  });
  
  beforeEach(async () => {
    await Cart.deleteMany({});
  });
  
  describe('GET /api/v1/cart', () => {
    it('باید سبد خرید کاربر را برگرداند', async () => {
      const res = await request(app)
        .get('/api/v1/cart')
        .set('Authorization', `Bearer ${userToken}`);
      
      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveProperty('totalItems');
      expect(res.body.data).toHaveProperty('totalAmount');
    });
    
    it('باید سبد خرید جدید ایجاد کند اگر وجود نداشته باشد', async () => {
      await Cart.deleteMany({ user: testUser._id });
      
      const res = await request(app)
        .get('/api/v1/cart')
        .set('Authorization', `Bearer ${userToken}`);
      
      expect(res.statusCode).toBe(200);
      expect(res.body.data.totalItems).toBe(0);
      expect(res.body.data.totalAmount).toBe(0);
    });
  });
  
  describe('POST /api/v1/cart/items', () => {
    it('باید محصول را به سبد خرید اضافه کند', async () => {
      const res = await request(app)
        .post('/api/v1/cart/items')
        .set('Authorization', `Bearer ${userToken}`)
        .send({ productId: testProduct1._id, quantity: 2 });
      
      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.addedProduct.productId).toBe(testProduct1._id.toString());
      expect(res.body.data.addedProduct.quantity).toBe(2);
    });
    
    it('باید خطا بدهد اگر محصول موجود نباشد', async () => {
      const res = await request(app)
        .post('/api/v1/cart/items')
        .set('Authorization', `Bearer ${userToken}`)
        .send({ productId: new mongoose.Types.ObjectId(), quantity: 1 });
      
      expect(res.statusCode).toBe(404);
    });
    
    it('باید خطا بدهد اگر موجودی کافی نباشد', async () => {
      // کاهش موجودی محصول
      await Product.findByIdAndUpdate(testProduct1._id, { stock: 0, inStock: false });
      
      const res = await request(app)
        .post('/api/v1/cart/items')
        .set('Authorization', `Bearer ${userToken}`)
        .send({ productId: testProduct1._id, quantity: 1 });
      
      expect(res.statusCode).toBe(400);
      
      // بازگرداندن موجودی
      await Product.findByIdAndUpdate(testProduct1._id, { stock: 100, inStock: true });
    });
  });
  
  describe('PUT /api/v1/cart/items/{productId}', () => {
    beforeEach(async () => {
      // اضافه کردن محصول به سبد برای تست
      await request(app)
        .post('/api/v1/cart/items')
        .set('Authorization', `Bearer ${userToken}`)
        .send({ productId: testProduct1._id, quantity: 1 });
    });
    
    it('باید تعداد محصول را به‌روزرسانی کند', async () => {
      const res = await request(app)
        .put(`/api/v1/cart/items/${testProduct1._id}`)
        .set('Authorization', `Bearer ${userToken}`)
        .send({ quantity: 3 });
      
      expect(res.statusCode).toBe(200);
      expect(res.body.data.newQuantity).toBe(3);
    });
    
    it('باید محصول را حذف کند اگر تعداد صفر باشد', async () => {
      const res = await request(app)
        .put(`/api/v1/cart/items/${testProduct1._id}`)
        .set('Authorization', `Bearer ${userToken}`)
        .send({ quantity: 0 });
      
      expect(res.statusCode).toBe(200);
      expect(res.body.data.removed).toBe(true);
    });
    
    it('باید خطا بدهد اگر تعداد نامعتبر باشد', async () => {
      const res = await request(app)
        .put(`/api/v1/cart/items/${testProduct1._id}`)
        .set('Authorization', `Bearer ${userToken}`)
        .send({ quantity: 100 }); // بیش از حد مجاز
      
      expect(res.statusCode).toBe(400);
    });
  });
  
  describe('DELETE /api/v1/cart/items/{productId}', () => {
    beforeEach(async () => {
      await request(app)
        .post('/api/v1/cart/items')
        .set('Authorization', `Bearer ${userToken}`)
        .send({ productId: testProduct1._id, quantity: 1 });
    });
    
    it('باید محصول را از سبد خرید حذف کند', async () => {
      const res = await request(app)
        .delete(`/api/v1/cart/items/${testProduct1._id}`)
        .set('Authorization', `Bearer ${userToken}`);
      
      expect(res.statusCode).toBe(200);
      expect(res.body.data.removed).toBe(true);
    });
    
    it('باید خطا بدهد اگر محصول در سبد نباشد', async () => {
      const res = await request(app)
        .delete(`/api/v1/cart/items/${testProduct2._id}`)
        .set('Authorization', `Bearer ${userToken}`);
      
      expect(res.statusCode).toBe(404);
    });
  });
  
  describe('DELETE /api/v1/cart', () => {
    beforeEach(async () => {
      // اضافه کردن چند محصول به سبد
      await request(app)
        .post('/api/v1/cart/items')
        .set('Authorization', `Bearer ${userToken}`)
        .send({ productId: testProduct1._id, quantity: 2 });
      
      await request(app)
        .post('/api/v1/cart/items')
        .set('Authorization', `Bearer ${userToken}`)
        .send({ productId: testProduct2._id, quantity: 1 });
    });
    
    it('باید سبد خرید را خالی کند', async () => {
      const res = await request(app)
        .delete('/api/v1/cart')
        .set('Authorization', `Bearer ${userToken}`);
      
      expect(res.statusCode).toBe(200);
      expect(res.body.data.cleared).toBe(true);
      
      // بررسی سبد خرید خالی
      const cartRes = await request(app)
        .get('/api/v1/cart')
        .set('Authorization', `Bearer ${userToken}`);
      
      expect(cartRes.body.data.totalItems).toBe(0);
    });
  });
  
  describe('POST /api/v1/cart/sync', () => {
    it('باید سبد خرید را با اطلاعات محصولات همگام کند', async () => {
      // اضافه کردن محصول
      await request(app)
        .post('/api/v1/cart/items')
        .set('Authorization', `Bearer ${userToken}`)
        .send({ productId: testProduct1._id, quantity: 1 });
      
      // غیرفعال کردن محصول
      await Product.findByIdAndUpdate(testProduct1._id, { active: false });
      
      const res = await request(app)
        .post('/api/v1/cart/sync')
        .set('Authorization', `Bearer ${userToken}`);
      
      expect(res.statusCode).toBe(200);
      expect(res.body.data.synced).toBe(true);
      
      // بررسی سبد خرید پس از همگام‌سازی
      const cartRes = await request(app)
        .get('/api/v1/cart')
        .set('Authorization', `Bearer ${userToken}`);
      
      expect(cartRes.body.data.totalItems).toBe(0);
    });
  });
});