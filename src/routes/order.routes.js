/**
 * @file روت‌های سفارشات HTLand
 * @description مستندسازی کامل API سفارشات
 */

const express = require('express');
const router = express.Router();
const orderController = require('../controllers/order.controller');
const orderMiddleware = require('../middlewares/order.middleware');
const authMiddleware = require('../middlewares/auth.middleware');

/**
 * @swagger
 * tags:
 *   name: Orders
 *   description: مدیریت سفارشات کاربران
 */

/**
 * @swagger
 * components:
 *   schemas:
 *     Order:
 *       type: object
 *       required:
 *         - shippingAddress
 *         - paymentMethod
 *       properties:
 *         shippingAddress:
 *           type: object
 *           properties:
 *             recipientName:
 *               type: string
 *             recipientPhone:
 *               type: string
 *             province:
 *               type: string
 *             city:
 *               type: string
 *             address:
 *               type: string
 *             postalCode:
 *               type: string
 *         paymentMethod:
 *           type: string
 *           enum: [wallet, zarinpal, bank_transfer, cash_on_delivery]
 *         notes:
 *           type: string
 *     OrderResponse:
 *       type: object
 *       properties:
 *         success:
 *           type: boolean
 *         message:
 *           type: string
 *         data:
 *           type: object
 *           properties:
 *             orderId:
 *               type: string
 *             orderNumber:
 *               type: string
 *             status:
 *               type: string
 *             totalAmount:
 *               type: number
 *   securitySchemes:
 *     bearerAuth:
 *       type: http
 *       scheme: bearer
 *       bearerFormat: JWT
 */

// Routes عمومی (بدون احراز هویت)
/**
 * @swagger
 * /api/v1/orders/track/{orderNumber}:
 *   get:
 *     summary: پیگیری سفارش
 *     tags: [Orders]
 *     parameters:
 *       - in: path
 *         name: orderNumber
 *         required: true
 *         schema:
 *           type: string
 *       - in: query
 *         name: phone
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: اطلاعات پیگیری سفارش
 *       404:
 *         description: سفارش یافت نشد
 */
router.get('/track/:orderNumber', orderController.trackOrder);

/**
 * @swagger
 * /api/v1/orders/payment/verify:
 *   get:
 *     summary: تایید پرداخت زرین‌پال
 *     tags: [Orders]
 *     parameters:
 *       - in: query
 *         name: Authority
 *         required: true
 *         schema:
 *           type: string
 *       - in: query
 *         name: Status
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: پرداخت تایید شد
 *       400:
 *         description: پرداخت ناموفق بود
 */
router.get('/payment/verify', orderController.verifyPayment);

// Routes خصوصی (نیاز به احراز هویت)
router.use(authMiddleware.protect);

/**
 * @swagger
 * /api/v1/orders:
 *   get:
 *     summary: دریافت لیست سفارشات کاربر
 *     tags: [Orders]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           default: 1
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 10
 *       - in: query
 *         name: status
 *         schema:
 *           type: string
 *           enum: [pending, paid, processing, shipped, delivered, cancelled, refunded]
 *       - in: query
 *         name: startDate
 *         schema:
 *           type: string
 *           format: date
 *       - in: query
 *         name: endDate
 *         schema:
 *           type: string
 *           format: date
 *     responses:
 *       200:
 *         description: لیست سفارشات
 */
router.get('/', orderController.getUserOrders);

/**
 * @swagger
 * /api/v1/orders/stats:
 *   get:
 *     summary: دریافت آمار سفارشات
 *     tags: [Orders]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: آمار سفارشات
 */
router.get('/stats', orderController.getOrderStats);

/**
 * @swagger
 * /api/v1/orders/recent:
 *   get:
 *     summary: دریافت سفارشات اخیر
 *     tags: [Orders]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 5
 *     responses:
 *       200:
 *         description: سفارشات اخیر
 */
router.get('/recent', orderController.getRecentOrders);

/**
 * @swagger
 * /api/v1/orders:
 *   post:
 *     summary: ایجاد سفارش جدید
 *     tags: [Orders]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/Order'
 *     responses:
 *       201:
 *         description: سفارش ایجاد شد
 *       400:
 *         description: خطای اعتبارسنجی یا موجودی
 */
router.post(
  '/',
  orderMiddleware.validateOrderInput,
  orderMiddleware.checkStockAvailability,
  orderController.createOrder
);

/**
 * @swagger
 * /api/v1/orders/{id}:
 *   get:
 *     summary: دریافت جزئیات یک سفارش
 *     tags: [Orders]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: جزئیات سفارش
 *       404:
 *         description: سفارش یافت نشد
 */
router.get('/:id', orderController.getOrder);

/**
 * @swagger
 * /api/v1/orders/{id}/cancel:
 *   post:
 *     summary: لغو سفارش
 *     tags: [Orders]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               reason:
 *                 type: string
 *     responses:
 *       200:
 *         description: سفارش لغو شد
 *       400:
 *         description: سفارش قابل لغو نیست
 */
router.post('/:id/cancel', orderController.cancelOrder);

// Routes ادمین
router.use(authMiddleware.restrictTo('admin'));

/**
 * @swagger
 * /api/v1/orders/{id}/status:
 *   put:
 *     summary: به‌روزرسانی وضعیت سفارش (ادمین)
 *     tags: [Orders]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - status
 *             properties:
 *               status:
 *                 type: string
 *                 enum: [paid, processing, shipped, delivered, cancelled, refunded]
 *               notes:
 *                 type: string
 *               trackingCode:
 *                 type: string
 *               shippingProvider:
 *                 type: string
 *               trackingUrl:
 *                 type: string
 *     responses:
 *       200:
 *         description: وضعیت به‌روزرسانی شد
 *       403:
 *         description: دسترسی غیرمجاز
 */
router.put('/:id/status', orderController.updateOrderStatus);

module.exports = router;