/**
 * @file روت‌های محصولات HTLand
 * @description مستندسازی کامل API با Swagger
 */

const express = require('express');
const router = express.Router();
const productController = require('../controllers/product.controller');
const productMiddleware = require('../middlewares/product.middleware');
const authMiddleware = require('../middlewares/auth.middleware');

/**
 * @swagger
 * tags:
 *   name: Products
 *   description: مدیریت محصولات ارگانیک شمال ایران
 */

/**
 * @swagger
 * components:
 *   schemas:
 *     Product:
 *       type: object
 *       required:
 *         - name
 *         - description
 *         - price
 *         - category
 *         - categoryFa
 *         - image
 *       properties:
 *         name:
 *           type: string
 *           example: "برنج هاشمی ممتاز شمال"
 *         description:
 *           type: string
 *           example: "برنج هاشمی درجه یک شمال با عطر و طعم بی‌نظیر"
 *         price:
 *           type: number
 *           example: 85000
 *         discountPrice:
 *           type: number
 *           example: 75000
 *         category:
 *           type: string
 *           enum: [rice, caviar, fish, honey, chicken, souvenir]
 *         categoryFa:
 *           type: string
 *           enum: [برنج شمال, خاویار ایرانی, ماهی تازه, عسل طبیعی, مرغ محلی, سوغات شمال]
 *         image:
 *           type: string
 *           format: uri
 *         stock:
 *           type: number
 *           example: 100
 *         featured:
 *           type: boolean
 *           example: true
 *         tags:
 *           type: array
 *           items:
 *             type: string
 *           example: ["برنج", "هاشمی", "ارگانیک", "شمال"]
 *     ProductResponse:
 *       type: object
 *       properties:
 *         success:
 *           type: boolean
 *         message:
 *           type: string
 *         data:
 *           $ref: '#/components/schemas/Product'
 *   securitySchemes:
 *     bearerAuth:
 *       type: http
 *       scheme: bearer
 *       bearerFormat: JWT
 */

/**
 * @swagger
 * /api/v1/products:
 *   get:
 *     summary: دریافت لیست محصولات
 *     tags: [Products]
 *     parameters:
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           default: 1
 *         description: شماره صفحه
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 12
 *         description: تعداد در هر صفحه
 *       - in: query
 *         name: category
 *         schema:
 *           type: string
 *           enum: [rice, caviar, fish, honey, chicken, souvenir]
 *         description: فیلتر بر اساس دسته‌بندی انگلیسی
 *       - in: query
 *         name: categoryFa
 *         schema:
 *           type: string
 *           enum: [برنج شمال, خاویار ایرانی, ماهی تازه, عسل طبیعی, مرغ محلی, سوغات شمال]
 *         description: فیلتر بر اساس دسته‌بندی فارسی
 *       - in: query
 *         name: search
 *         schema:
 *           type: string
 *         description: جستجوی متنی در نام و توضیحات
 *       - in: query
 *         name: minPrice
 *         schema:
 *           type: number
 *         description: حداقل قیمت
 *       - in: query
 *         name: maxPrice
 *         schema:
 *           type: number
 *         description: حداکثر قیمت
 *       - in: query
 *         name: featured
 *         schema:
 *           type: boolean
 *         description: فیلتر محصولات ویژه
 *       - in: query
 *         name: inStock
 *         schema:
 *           type: boolean
 *         description: فیلتر بر اساس موجودی
 *       - in: query
 *         name: sort
 *         schema:
 *           type: string
 *           default: "-createdAt"
 *           enum: [createdAt, -createdAt, price, -price, rating, -rating]
 *         description: مرتب‌سازی
 *     responses:
 *       200:
 *         description: لیست محصولات با صفحه‌بندی
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 message:
 *                   type: string
 *                 data:
 *                   type: array
 *                   items:
 *                     $ref: '#/components/schemas/Product'
 *                 pagination:
 *                   type: object
 *                   properties:
 *                     total:
 *                       type: integer
 *                     page:
 *                       type: integer
 *                     pages:
 *                       type: integer
 *                     hasNext:
 *                       type: boolean
 *                     hasPrev:
 *                       type: boolean
 */
router.get('/', productController.getAllProducts);

/**
 * @swagger
 * /api/v1/products/featured:
 *   get:
 *     summary: دریافت محصولات ویژه
 *     tags: [Products]
 *     parameters:
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 8
 *         description: تعداد محصولات
 *     responses:
 *       200:
 *         description: لیست محصولات ویژه
 */
router.get('/featured', productController.getFeaturedProducts);

/**
 * @swagger
 * /api/v1/products/search:
 *   get:
 *     summary: جستجوی پیشرفته محصولات
 *     tags: [Products]
 *     parameters:
 *       - in: query
 *         name: q
 *         required: true
 *         schema:
 *           type: string
 *         description: عبارت جستجو
 *       - in: query
 *         name: category
 *         schema:
 *           type: string
 *         description: فیلتر دسته‌بندی
 *     responses:
 *       200:
 *         description: نتایج جستجو
 */
router.get('/search', productController.searchProducts);

/**
 * @swagger
 * /api/v1/products/categories/stats:
 *   get:
 *     summary: دریافت آمار دسته‌بندی‌ها
 *     tags: [Products]
 *     responses:
 *       200:
 *         description: تعداد محصولات هر دسته‌بندی
 */
router.get('/categories/stats', productController.getCategoryStats);

/**
 * @swagger
 * /api/v1/products/{id}:
 *   get:
 *     summary: دریافت یک محصول
 *     tags: [Products]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: شناسه یا slug محصول
 *     responses:
 *       200:
 *         description: اطلاعات کامل محصول
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ProductResponse'
 *       404:
 *         description: محصول یافت نشد
 */
router.get('/:id', productController.getProductById);

/**
 * @swagger
 * /api/v1/products/{id}/check-stock:
 *   post:
 *     summary: بررسی موجودی محصول
 *     tags: [Products]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: شناسه محصول
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               quantity:
 *                 type: number
 *                 default: 1
 *     responses:
 *       200:
 *         description: وضعیت موجودی
 */
router.post('/:id/check-stock', productController.checkStock);

// 🔐 Routes زیر فقط برای ادمین قابل دسترسی هستند
router.use(authMiddleware.protect);

/**
 * @swagger
 * /api/v1/products:
 *   post:
 *     summary: ایجاد محصول جدید (فقط ادمین)
 *     tags: [Products]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             required:
 *               - name
 *               - description
 *               - price
 *               - category
 *               - categoryFa
 *             properties:
 *               name:
 *                 type: string
 *               description:
 *                 type: string
 *               price:
 *                 type: number
 *               category:
 *                 type: string
 *               categoryFa:
 *                 type: string
 *               image:
 *                 type: string
 *                 format: binary
 *               gallery:
 *                 type: array
 *                 items:
 *                   type: string
 *                   format: binary
 *     responses:
 *       201:
 *         description: محصول ایجاد شد
 *       401:
 *         description: عدم احراز هویت
 *       403:
 *         description: دسترسی غیرمجاز
 */
router.post(
  '/',
  authMiddleware.restrictTo('admin'),
  productMiddleware.uploadProductImages,
  productMiddleware.validateProduct,
  productController.createProduct
);

/**
 * @swagger
 * /api/v1/products/{id}:
 *   put:
 *     summary: به‌روزرسانی محصول (فقط ادمین)
 *     tags: [Products]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: شناسه محصول
 *     requestBody:
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               price:
 *                 type: number
 *               image:
 *                 type: string
 *                 format: binary
 *     responses:
 *       200:
 *         description: محصول به‌روزرسانی شد
 *       404:
 *         description: محصول یافت نشد
 */
router.put(
  '/:id',
  authMiddleware.restrictTo('admin'),
  productMiddleware.uploadProductImages,
  productMiddleware.validateProduct,
  productController.updateProduct
);

/**
 * @swagger
 * /api/v1/products/{id}:
 *   delete:
 *     summary: حذف محصول (فقط ادمین)
 *     tags: [Products]
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
 *         description: محصول حذف شد
 *       404:
 *         description: محصول یافت نشد
 */
router.delete(
  '/:id',
  authMiddleware.restrictTo('admin'),
  productController.deleteProduct
);

/**
 * @swagger
 * /api/v1/products/{id}/decrease-stock:
 *   post:
 *     summary: کاهش موجودی محصول (برای سیستم سفارشات)
 *     tags: [Products]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - quantity
 *             properties:
 *               quantity:
 *                 type: number
 *     responses:
 *       200:
 *         description: موجودی کاهش یافت
 */
router.post(
  '/:id/decrease-stock',
  authMiddleware.restrictTo('admin', 'order-system'),
  productController.decreaseStock
);

module.exports = router;