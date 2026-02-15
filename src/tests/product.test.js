/**
 * تست‌های واحد برای محصولات
 */
const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../app');
const Product = require('../models/Product.model');
const User = require('../models/User.model');

let adminToken;
let adminUser;
let testProduct;

describe('سیستم مدیریت محصولات HTLand', () => {
  beforeAll(async () => {
    // اتصال به دیتابیس تست
    await mongoose.connect(process.env.MONGODB_TEST_URI);
    
    // ایجاد کاربر ادمین برای تست
    adminUser = await User.create({
      name: 'ادمین تست',
      email: 'admin@test.com',
      password: 'password123',
      phone: '09123456789',
      isAdmin: true,
      active: true
    });
    
    // دریافت توکن
    const loginRes = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'admin@test.com', password: 'password123' });
    
    adminToken = loginRes.body.token;
  });
  
  afterAll(async () => {
    await mongoose.connection.dropDatabase();
    await mongoose.connection.close();
  });
  
  beforeEach(async () => {
    await Product.deleteMany({});
    
    testProduct = await Product.create({
      name: 'برنج هاشمی تست',
      description: 'برنج هاشمی درجه یک برای تست',
      price: 85000,
      discountPrice: 75000,
      category: 'rice',
      categoryFa: 'برنج شمال',
      image: 'https://test.com/rice.jpg',
      stock: 100,
      createdBy: adminUser._id,
      updatedBy: adminUser._id
    });
  });
  
  describe('GET /api/v1/products', () => {
    it('باید لیست محصولات را با موفقیت برگرداند', async () => {
      const res = await request(app).get('/api/v1/products');
      
      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toBeInstanceOf(Array);
      expect(res.body.pagination).toBeDefined();
    });
    
    it('باید محصولات را بر اساس دسته‌بندی فیلتر کند', async () => {
      const res = await request(app)
        .get('/api/v1/products')
        .query({ category: 'rice' });
      
      expect(res.statusCode).toBe(200);
      expect(res.body.data.every(p => p.category === 'rice')).toBe(true);
    });
    
    it('باید جستجوی متنی کار کند', async () => {
      const res = await request(app)
        .get('/api/v1/products')
        .query({ search: 'هاشمی' });
      
      expect(res.statusCode).toBe(200);
      expect(res.body.data.length).toBeGreaterThan(0);
    });
  });
  
  describe('GET /api/v1/products/:id', () => {
    it('باید یک محصول را با موفقیت برگرداند', async () => {
      const res = await request(app)
        .get(`/api/v1/products/${testProduct._id}`);
      
      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.name).toBe(testProduct.name);
    });
    
    it('باید با slug نیز کار کند', async () => {
      const res = await request(app)
        .get(`/api/v1/products/${testProduct.slug}`);
      
      expect(res.statusCode).toBe(200);
      expect(res.body.data._id).toBe(testProduct._id.toString());
    });
    
    it('باید برای محصول ناموجود 404 برگرداند', async () => {
      const res = await request(app)
        .get('/api/v1/products/507f1f77bcf86cd799439011'); // ObjectId تصادفی
      
      expect(res.statusCode).toBe(404);
    });
  });
  
  describe('POST /api/v1/products', () => {
    it('باید محصول جدید ایجاد کند (ادمین)', async () => {
      const newProduct = {
        name: 'خاویار طلایی',
        description: 'خاویار طلایی ممتاز دریای خزر',
        price: 450000,
        discountPrice: 420000,
        category: 'caviar',
        categoryFa: 'خاویار ایرانی',
        stock: 50,
        tags: ['خاویار', 'طلایی', 'دریای خزر']
      };
      
      const res = await request(app)
        .post('/api/v1/products')
        .set('Authorization', `Bearer ${adminToken}`)
        .field('name', newProduct.name)
        .field('description', newProduct.description)
        .field('price', newProduct.price)
        .field('category', newProduct.category)
        .field('categoryFa', newProduct.categoryFa)
        .field('stock', newProduct.stock)
        .field('tags', JSON.stringify(newProduct.tags))
        .attach('image', 'tests/fixtures/test-image.jpg');
      
      expect(res.statusCode).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.name).toBe(newProduct.name);
      expect(res.body.data.slug).toBeDefined();
    });
    
    it('باید برای کاربر غیرادمین 403 برگرداند', async () => {
      // ایجاد کاربر عادی
      const normalUser = await User.create({
        name: 'کاربر عادی',
        email: 'user@test.com',
        password: 'password123',
        phone: '09123456780'
      });
      
      const loginRes = await request(app)
        .post('/api/v1/auth/login')
        .send({ email: 'user@test.com', password: 'password123' });
      
      const userToken = loginRes.body.token;
      
      const res = await request(app)
        .post('/api/v1/products')
        .set('Authorization', `Bearer ${userToken}`)
        .send({ name: 'محصول تست' });
      
      expect(res.statusCode).toBe(403);
    });
    
    it('باید خطای اعتبارسنجی برگرداند', async () => {
      const res = await request(app)
        .post('/api/v1/products')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ name: '' }); // نام خالی
      
      expect(res.statusCode).toBe(400);
    });
  });
  
  describe('PUT /api/v1/products/:id', () => {
    it('باید محصول را به‌روزرسانی کند', async () => {
      const updates = {
        name: 'برنج هاشمی ویرایش شده',
        price: 90000
      };
      
      const res = await request(app)
        .put(`/api/v1/products/${testProduct._id}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .field('name', updates.name)
        .field('price', updates.price)
        .field('description', testProduct.description)
        .field('category', testProduct.category)
        .field('categoryFa', testProduct.categoryFa);
      
      expect(res.statusCode).toBe(200);
      expect(res.body.data.name).toBe(updates.name);
      expect(res.body.data.price).toBe(updates.price);
    });
  });
  
  describe('DELETE /api/v1/products/:id', () => {
    it('باید محصول را غیرفعال کند', async () => {
      const res = await request(app)
        .delete(`/api/v1/products/${testProduct._id}`)
        .set('Authorization', `Bearer ${adminToken}`);
      
      expect(res.statusCode).toBe(200);
      
      // بررسی غیرفعال شدن
      const deletedProduct = await Product.findById(testProduct._id);
      expect(deletedProduct.active).toBe(false);
    });
  });
  
  describe('POST /api/v1/products/:id/check-stock', () => {
    it('باید موجودی کافی را تأیید کند', async () => {
      const res = await request(app)
        .post(`/api/v1/products/${testProduct._id}/check-stock`)
        .send({ quantity: 5 });
      
      expect(res.statusCode).toBe(200);
      expect(res.body.data.available).toBe(true);
    });
    
    it('باید موجودی ناکافی را تشخیص دهد', async () => {
      const res = await request(app)
        .post(`/api/v1/products/${testProduct._id}/check-stock`)
        .send({ quantity: 150 }); // بیشتر از موجودی
      
      expect(res.statusCode).toBe(200);
      expect(res.body.data.available).toBe(false);
    });
  });
});