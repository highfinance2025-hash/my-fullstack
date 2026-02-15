/**
 * تست‌های واحد برای سفارشات HTLand
 */

const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../app');
const Order = require('../models/Order.model');
const Cart = require('../models/Cart.model');
const Product = require('../models/Product.model');
const User = require('../models/User.model');

let userToken;
let adminToken;
let testUser;
let testAdmin;
let testProduct1;
let testProduct2;
let testCart;

describe('سیستم سفارشات HTLand', () => {
  beforeAll(async () => {
    await mongoose.connect(process.env.MONGODB_TEST_URI);
    
    // ایجاد کاربر تستی
    testUser = await User.create({
      name: 'کاربر تست سفارش',
      email: 'order@test.com',
      password: 'password123',
      phone: '09123456789',
      active: true
    });
    
    // ایجاد ادمین تستی
    testAdmin = await User.create({
      name: 'ادمین تست سفارش',
      email: 'admin-order@test.com',
      password: 'password123',
      phone: '09123456780',
      isAdmin: true,
      active: true
    });
    
    // دریافت توکن کاربر
    const userLoginRes = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'order@test.com', password: 'password123' });
    
    userToken = userLoginRes.body.token;
    
    // دریافت توکن ادمین
    const adminLoginRes = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'admin-order@test.com', password: 'password123' });
    
    adminToken = adminLoginRes.body.token;
    
    // ایجاد محصولات تستی
    testProduct1 = await Product.create({
      name: 'برنج سفارشی ۱',
      description: 'برنج تستی برای سفارش',
      price: 50000,
      discountPrice: 45000,
      category: 'rice',
      categoryFa: 'برنج شمال',
      image: 'https://test.com/rice-order.jpg',
      stock: 100,
      active: true,
      createdBy: testUser._id
    });
    
    testProduct2 = await Product.create({
      name: 'خاویار سفارشی',
      description: 'خاویار تستی برای سفارش',
      price: 400000,
      category: 'caviar',
      categoryFa: 'خاویار ایرانی',
      image: 'https://test.com/caviar-order.jpg',
      stock: 50,
      active: true,
      createdBy: testUser._id
    });
    
    // ایجاد سبد خرید تستی
    testCart = await Cart.create({
      user: testUser._id,
      items: [
        {
          productId: testProduct1._id,
          quantity: 2,
          priceAtTime: testProduct1.price,
          productName: testProduct1.name,
          productImage: testProduct1.image,
          category: testProduct1.category,
          finalPriceAtTime: testProduct1.discountPrice,
          productAvailable: true,
          productActive: true
        }
      ]
    });
  });
  
  afterAll(async () => {
    await mongoose.connection.dropDatabase();
    await mongoose.connection.close();
  });
  
  beforeEach(async () => {
    await Order.deleteMany({});
    await Cart.findByIdAndUpdate(testCart._id, {
      items: [
        {
          productId: testProduct1._id,
          quantity: 2,
          priceAtTime: testProduct1.price,
          productName: testProduct1.name,
          productImage: testProduct1.image,
          category: testProduct1.category,
          finalPriceAtTime: testProduct1.discountPrice,
          productAvailable: true,
          productActive: true
        }
      ]
    });
  });
  
  describe('POST /api/v1/orders', () => {
    it('باید سفارش جدید ایجاد کند', async () => {
      const res = await request(app)
        .post('/api/v1/orders')
        .set('Authorization', `Bearer ${userToken}`)
        .send({
          shippingAddressId: '507f1f77bcf86cd799439011',
          paymentMethod: 'wallet',
          notes: 'تست سفارش'
        });
      
      expect(res.statusCode).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveProperty('orderId');
      expect(res.body.data).toHaveProperty('orderNumber');
      expect(res.body.data.status).toBe('paid'); // با کیف پول پرداخت می‌شود
    });
    
    it('باید خطا بدهد اگر سبد خرید خالی باشد', async () => {
      // خالی کردن سبد خرید
      await Cart.findByIdAndUpdate(testCart._id, { items: [] });
      
      const res = await request(app)
        .post('/api/v1/orders')
        .set('Authorization', `Bearer ${userToken}`)
        .send({
          shippingAddressId: '507f1f77bcf86cd799439011',
          paymentMethod: 'wallet'
        });
      
      expect(res.statusCode).toBe(400);
      
      // بازگرداندن سبد خرید
      await Cart.findByIdAndUpdate(testCart._id, {
        items: [
          {
            productId: testProduct1._id,
            quantity: 2,
            priceAtTime: testProduct1.price,
            productName: testProduct1.name,
            productImage: testProduct1.image,
            category: testProduct1.category,
            finalPriceAtTime: testProduct1.discountPrice,
            productAvailable: true,
            productActive: true
          }
        ]
      });
    });
    
    it('باید خطا بدهد اگر موجودی کافی نباشد', async () => {
      // کاهش موجودی محصول
      await Product.findByIdAndUpdate(testProduct1._id, { stock: 1 });
      
      const res = await request(app)
        .post('/api/v1/orders')
        .set('Authorization', `Bearer ${userToken}`)
        .send({
          shippingAddressId: '507f1f77bcf86cd799439011',
          paymentMethod: 'wallet'
        });
      
      expect(res.statusCode).toBe(400);
      
      // بازگرداندن موجودی
      await Product.findByIdAndUpdate(testProduct1._id, { stock: 100 });
    });
  });
  
  describe('GET /api/v1/orders', () => {
    it('باید لیست سفارشات کاربر را برگرداند', async () => {
      // ایجاد یک سفارش تستی
      await Order.create({
        user: testUser._id,
        orderNumber: 'HT-20231201-12345',
        items: [
          {
            product: testProduct1._id,
            productName: testProduct1.name,
            productImage: testProduct1.image,
            category: testProduct1.category,
            categoryFa: testProduct1.categoryFa,
            quantity: 1,
            unitPrice: testProduct1.price,
            finalUnitPrice: testProduct1.discountPrice,
            totalPrice: testProduct1.discountPrice
          }
        ],
        shippingAddress: {
          recipientName: 'کاربر تست',
          recipientPhone: '09123456789',
          province: 'مازندران',
          city: 'ساری',
          address: 'آدرس تست',
          postalCode: '4816612345'
        },
        payment: {
          method: 'wallet',
          amount: 45000,
          status: 'completed'
        },
        subtotal: 45000,
        totalAmount: 45000,
        status: 'paid'
      });
      
      const res = await request(app)
        .get('/api/v1/orders')
        .set('Authorization', `Bearer ${userToken}`);
      
      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toBeInstanceOf(Array);
      expect(res.body.pagination).toBeDefined();
    });
  });
  
  describe('GET /api/v1/orders/:id', () => {
    let testOrder;
    
    beforeEach(async () => {
      testOrder = await Order.create({
        user: testUser._id,
        orderNumber: 'HT-20231201-12346',
        items: [
          {
            product: testProduct1._id,
            productName: testProduct1.name,
            productImage: testProduct1.image,
            category: testProduct1.category,
            categoryFa: testProduct1.categoryFa,
            quantity: 1,
            unitPrice: testProduct1.price,
            finalUnitPrice: testProduct1.discountPrice,
            totalPrice: testProduct1.discountPrice
          }
        ],
        shippingAddress: {
          recipientName: 'کاربر تست',
          recipientPhone: '09123456789',
          province: 'مازندران',
          city: 'ساری',
          address: 'آدرس تست',
          postalCode: '4816612345'
        },
        payment: {
          method: 'wallet',
          amount: 45000,
          status: 'completed'
        },
        subtotal: 45000,
        totalAmount: 45000,
        status: 'paid'
      });
    });
    
    it('باید جزئیات سفارش را برگرداند', async () => {
      const res = await request(app)
        .get(`/api/v1/orders/${testOrder._id}`)
        .set('Authorization', `Bearer ${userToken}`);
      
      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.order.orderNumber).toBe(testOrder.orderNumber);
    });
    
    it('باید برای سفارش دیگر کاربران خطا بدهد', async () => {
      // ایجاد کاربر دیگر
      const otherUser = await User.create({
        name: 'کاربر دیگر',
        email: 'other@test.com',
        password: 'password123',
        phone: '09123456777'
      });
      
      const otherLoginRes = await request(app)
        .post('/api/v1/auth/login')
        .send({ email: 'other@test.com', password: 'password123' });
      
      const otherToken = otherLoginRes.body.token;
      
      const res = await request(app)
        .get(`/api/v1/orders/${testOrder._id}`)
        .set('Authorization', `Bearer ${otherToken}`);
      
      expect(res.statusCode).toBe(404);
    });
    
    it('باید به ادمین اجازه دهد هر سفارشی را ببیند', async () => {
      const res = await request(app)
        .get(`/api/v1/orders/${testOrder._id}`)
        .set('Authorization', `Bearer ${adminToken}`);
      
      expect(res.statusCode).toBe(200);
      expect(res.body.data.order.orderNumber).toBe(testOrder.orderNumber);
    });
  });
  
  describe('POST /api/v1/orders/:id/cancel', () => {
    let testOrder;
    
    beforeEach(async () => {
      testOrder = await Order.create({
        user: testUser._id,
        orderNumber: 'HT-20231201-12347',
        items: [
          {
            product: testProduct1._id,
            productName: testProduct1.name,
            productImage: testProduct1.image,
            category: testProduct1.category,
            categoryFa: testProduct1.categoryFa,
            quantity: 1,
            unitPrice: testProduct1.price,
            finalUnitPrice: testProduct1.discountPrice,
            totalPrice: testProduct1.discountPrice
          }
        ],
        shippingAddress: {
          recipientName: 'کاربر تست',
          recipientPhone: '09123456789',
          province: 'مازندران',
          city: 'ساری',
          address: 'آدرس تست',
          postalCode: '4816612345'
        },
        payment: {
          method: 'wallet',
          amount: 45000,
          status: 'completed'
        },
        subtotal: 45000,
        totalAmount: 45000,
        status: 'paid'
      });
    });
    
    it('باید سفارش را لغو کند', async () => {
      const res = await request(app)
        .post(`/api/v1/orders/${testOrder._id}/cancel`)
        .set('Authorization', `Bearer ${userToken}`)
        .send({ reason: 'تست لغو' });
      
      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      
      // بررسی به‌روزرسانی سفارش
      const updatedOrder = await Order.findById(testOrder._id);
      expect(updatedOrder.status).toBe('cancelled');
    });
    
    it('باید برای سفارش تحویل داده شده خطا بدهد', async () => {
      // تغییر وضعیت به تحویل داده شده
      await Order.findByIdAndUpdate(testOrder._id, { status: 'delivered' });
      
      const res = await request(app)
        .post(`/api/v1/orders/${testOrder._id}/cancel`)
        .set('Authorization', `Bearer ${userToken}`)
        .send({ reason: 'تست لغو' });
      
      expect(res.statusCode).toBe(400);
    });
  });
  
  describe('GET /api/v1/orders/track/:orderNumber', () => {
    let testOrder;
    
    beforeEach(async () => {
      testOrder = await Order.create({
        user: testUser._id,
        orderNumber: 'HT-20231201-12348',
        items: [
          {
            product: testProduct1._id,
            productName: testProduct1.name,
            productImage: testProduct1.image,
            category: testProduct1.category,
            categoryFa: testProduct1.categoryFa,
            quantity: 1,
            unitPrice: testProduct1.price,
            finalUnitPrice: testProduct1.discountPrice,
            totalPrice: testProduct1.discountPrice
          }
        ],
        shippingAddress: {
          recipientName: 'کاربر تست',
          recipientPhone: '09123456789',
          province: 'مازندران',
          city: 'ساری',
          address: 'آدرس تست',
          postalCode: '4816612345'
        },
        payment: {
          method: 'wallet',
          amount: 45000,
          status: 'completed'
        },
        subtotal: 45000,
        totalAmount: 45000,
        status: 'shipped',
        trackingCode: 'TRACK12345'
      });
    });
    
    it('باید اطلاعات پیگیری سفارش را برگرداند', async () => {
      const res = await request(app)
        .get(`/api/v1/orders/track/${testOrder.orderNumber}`);
      
      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.orderNumber).toBe(testOrder.orderNumber);
      expect(res.body.data.tracking.code).toBe('TRACK12345');
    });
    
    it('باید با تأیید شماره تلفن اطلاعات کامل‌تری برگرداند', async () => {
      const res = await request(app)
        .get(`/api/v1/orders/track/${testOrder.orderNumber}?phone=09123456789`);
      
      expect(res.statusCode).toBe(200);
      expect(res.body.data.shippingInfo.recipientName).toBe('کاربر تست');
    });
    
    it('باید برای شماره تلفن نامطابق خطا بدهد', async () => {
      const res = await request(app)
        .get(`/api/v1/orders/track/${testOrder.orderNumber}?phone=09111111111`);
      
      expect(res.statusCode).toBe(403);
    });
  });
});