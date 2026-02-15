/**
 * @file مسیرهای مدیریت آدرس‌های کاربران HTLand
 * @description مسیرهای API برای عملیات CRUD آدرس‌ها
 * @since 1403/10/01
 */

const express = require('express');
const router = express.Router();
const addressController = require('../controllers/address.controller');
const { protect } = require('../middlewares/auth.middleware');
const { checkAddressOwnership } = require('../middlewares/address.middleware');

// تمام مسیرها نیاز به احراز هویت دارند
router.use(protect);

/**
 * @swagger
 * tags:
 *   name: Addresses
 *   description: مدیریت آدرس‌های کاربران
 */

/**
 * @swagger
 * /api/v1/addresses:
 *   get:
 *     summary: دریافت لیست آدرس‌های کاربر
 *     tags: [Addresses]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: لیست آدرس‌های کاربر
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 count:
 *                   type: integer
 *                   example: 2
 *                 data:
 *                   type: array
 *                   items:
 *                     $ref: '#/components/schemas/Address'
 *       401:
 *         description: کاربر لاگین نکرده است
 */
router.get('/', addressController.getAddresses);

/**
 * @swagger
 * /api/v1/addresses/default:
 *   get:
 *     summary: دریافت آدرس پیش‌فرض کاربر
 *     tags: [Addresses]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: آدرس پیش‌فرض کاربر
 *       404:
 *         description: آدرس پیش‌فرضی پیدا نشد
 */
router.get('/default', addressController.getDefaultAddress);

/**
 * @swagger
 * /api/v1/addresses/{id}:
 *   get:
 *     summary: دریافت یک آدرس خاص
 *     tags: [Addresses]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: شناسه آدرس
 *     responses:
 *       200:
 *         description: اطلاعات آدرس
 *       404:
 *         description: آدرس پیدا نشد
 */
router.get('/:id', checkAddressOwnership, addressController.getAddressById);

/**
 * @swagger
 * /api/v1/addresses:
 *   post:
 *     summary: ایجاد آدرس جدید
 *     tags: [Addresses]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/AddressInput'
 *     responses:
 *       201:
 *         description: آدرس با موفقیت ایجاد شد
 *       400:
 *         description: داده‌های ورودی معتبر نیست
 *       409:
 *         description: کاربر قبلاً حداکثر آدرس مجاز را دارد
 */
router.post('/', addressController.createAddress);

/**
 * @swagger
 * /api/v1/addresses/{id}:
 *   put:
 *     summary: ویرایش آدرس
 *     tags: [Addresses]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: شناسه آدرس
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/AddressInput'
 *     responses:
 *       200:
 *         description: آدرس با موفقیت ویرایش شد
 *       404:
 *         description: آدرس پیدا نشد
 */
router.put('/:id', checkAddressOwnership, addressController.updateAddress);

/**
 * @swagger
 * /api/v1/addresses/{id}:
 *   delete:
 *     summary: حذف آدرس
 *     tags: [Addresses]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: شناسه آدرس
 *     responses:
 *       200:
 *         description: آدرس با موفقیت حذف شد
 *       400:
 *         description: نمی‌توان آدرس پیش‌فرض را حذف کرد
 *       404:
 *         description: آدرس پیدا نشد
 */
router.delete('/:id', checkAddressOwnership, addressController.deleteAddress);

/**
 * @swagger
 * /api/v1/addresses/{id}/set-default:
 *   post:
 *     summary: تنظیم آدرس به عنوان پیش‌فرض
 *     tags: [Addresses]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: شناسه آدرس
 *     responses:
 *       200:
 *         description: آدرس با موفقیت پیش‌فرض شد
 *       404:
 *         description: آدرس پیدا نشد
 */
router.post('/:id/set-default', checkAddressOwnership, addressController.setDefaultAddress);

/**
 * @swagger
 * /api/v1/addresses/{id}/validate-for-order:
 *   post:
 *     summary: بررسی اعتبار آدرس برای سفارش
 *     tags: [Addresses]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: شناسه آدرس
 *     responses:
 *       200:
 *         description: آدرس برای سفارش معتبر است
 *       400:
 *         description: آدرس برای سفارش معتبر نیست
 */
router.post('/:id/validate-for-order', checkAddressOwnership, addressController.validateForOrder);

// تعریف схем‌های Swagger
/**
 * @swagger
 * components:
 *   schemas:
 *     Address:
 *       type: object
 *       properties:
 *         _id:
 *           type: string
 *           example: "60d21b4667d0d8992e610c85"
 *         user:
 *           type: string
 *           example: "60d21b4667d0d8992e610c84"
 *         fullName:
 *           type: string
 *           example: "علی رضایی"
 *         phone:
 *           type: string
 *           example: "09123456789"
 *         province:
 *           type: string
 *           example: "مازندران"
 *         city:
 *           type: string
 *           example: "ساری"
 *         address:
 *           type: string
 *           example: "بلوار طالقانی، برج پاسارگاد، طبقه ۴، واحد ۴۰۲"
 *         postalCode:
 *           type: string
 *           example: "4816653157"
 *         isDefault:
 *           type: boolean
 *           example: true
 *         label:
 *           type: string
 *           enum: [خانه, کار, فامیل, دیگر]
 *           example: "خانه"
 *         buildingNumber:
 *           type: string
 *           example: "۱۲"
 *         unit:
 *           type: string
 *           example: "۴۰۲"
 *         floor:
 *           type: string
 *           example: "۴"
 *         description:
 *           type: string
 *           example: "زنگ بزنید و تحویل بگیرید"
 *         formattedAddress:
 *           type: string
 *           example: "بلوار طالقانی، برج پاسارگاد، طبقه ۴، واحد ۴۰۲، پلاک ۱۲، ساری، مازندران، کد پستی: 4816653157 (زنگ بزنید و تحویل بگیرید)"
 *         createdAt:
 *           type: string
 *           format: date-time
 *         updatedAt:
 *           type: string
 *           format: date-time
 * 
 *     AddressInput:
 *       type: object
 *       required:
 *         - fullName
 *         - phone
 *         - province
 *         - city
 *         - address
 *         - postalCode
 *       properties:
 *         fullName:
 *           type: string
 *           minLength: 3
 *           maxLength: 100
 *           example: "علی رضایی"
 *         phone:
 *           type: string
 *           pattern: "^09[0-9]{9}$"
 *           example: "09123456789"
 *         province:
 *           type: string
 *           enum: [مازندران, گیلان, گلستان, ...]
 *           example: "مازندران"
 *         city:
 *           type: string
 *           minLength: 2
 *           maxLength: 50
 *           example: "ساری"
 *         address:
 *           type: string
 *           minLength: 10
 *           maxLength: 500
 *           example: "بلوار طالقانی، برج پاسارگاد، طبقه ۴"
 *         postalCode:
 *           type: string
 *           pattern: "^\d{10}$"
 *           example: "4816653157"
 *         isDefault:
 *           type: boolean
 *           default: false
 *         label:
 *           type: string
 *           enum: [خانه, کار, فامیل, دیگر]
 *           default: "خانه"
 *         buildingNumber:
 *           type: string
 *           maxLength: 20
 *           example: "۱۲"
 *         unit:
 *           type: string
 *           maxLength: 10
 *           example: "۴"
 *         floor:
 *           type: string
 *           maxLength: 10
 *           example: "۲"
 *         description:
 *           type: string
 *           maxLength: 200
 *           example: "زنگ بزنید و تحویل بگیرید"
 * 
 *   securitySchemes:
 *     bearerAuth:
 *       type: http
 *       scheme: bearer
 *       bearerFormat: JWT
 */

module.exports = router;