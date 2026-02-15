/**
 * @file مسیرهای مدیریت پروفایل کاربران HTLand
 * @description مسیرهای API برای مدیریت اطلاعات شخصی کاربران
 * @since 1403/10/01
 */

const express = require('express');
const router = express.Router();
const profileController = require('../controllers/profile.controller');
const { protect } = require('../middlewares/auth.middleware');

// تمام مسیرها نیاز به احراز هویت دارند
router.use(protect);

/**
 * @swagger
 * tags:
 *   name: Profile
 *   description: مدیریت پروفایل کاربران
 */

/**
 * @swagger
 * /api/v1/profile:
 *   get:
 *     summary: دریافت اطلاعات پروفایل کاربر
 *     tags: [Profile]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: اطلاعات پروفایل کاربر
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 data:
 *                   $ref: '#/components/schemas/UserProfile'
 *       401:
 *         description: کاربر لاگین نکرده است
 */
router.get('/', profileController.getProfile);

/**
 * @swagger
 * /api/v1/profile/stats:
 *   get:
 *     summary: دریافت آمار پروفایل کاربر
 *     tags: [Profile]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: آمار پروفایل کاربر
 */
router.get('/stats', profileController.getProfileStats);

/**
 * @swagger
 * /api/v1/profile:
 *   put:
 *     summary: ویرایش اطلاعات پروفایل
 *     tags: [Profile]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/ProfileUpdate'
 *     responses:
 *       200:
 *         description: پروفایل با موفقیت ویرایش شد
 *       400:
 *         description: داده‌های ورودی معتبر نیست
 */
router.put('/', profileController.updateProfile);

/**
 * @swagger
 * /api/v1/profile/upload-image:
 *   post:
 *     summary: آپلود تصویر پروفایل
 *     tags: [Profile]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             properties:
 *               profileImage:
 *                 type: string
 *                 format: binary
 *     responses:
 *       200:
 *         description: تصویر پروفایل با موفقیت آپلود شد
 *       400:
 *         description: فایل معتبر نیست
 */
router.post('/upload-image', profileController.uploadProfileImageHandler);

/**
 * @swagger
 * /api/v1/profile/remove-image:
 *   delete:
 *     summary: حذف تصویر پروفایل
 *     tags: [Profile]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: تصویر پروفایل با موفقیت حذف شد
 */
router.delete('/remove-image', profileController.removeProfileImage);

/**
 * @swagger
 * /api/v1/profile/notifications:
 *   put:
 *     summary: تغییر تنظیمات اعلان‌ها
 *     tags: [Profile]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/NotificationSettings'
 *     responses:
 *       200:
 *         description: تنظیمات اعلان‌ها با موفقیت ویرایش شد
 */
router.put('/notifications', profileController.updateNotificationSettings);

/**
 * @swagger
 * /api/v1/profile/change-password:
 *   put:
 *     summary: تغییر رمز عبور
 *     tags: [Profile]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - currentPassword
 *               - newPassword
 *             properties:
 *               currentPassword:
 *                 type: string
 *               newPassword:
 *                 type: string
 *     responses:
 *       200:
 *         description: رمز عبور با موفقیت تغییر کرد
 *       400:
 *         description: رمز عبور فعلی نادرست است
 */
router.put('/change-password', profileController.changePassword);

/**
 * @swagger
 * /api/v1/profile/toggle-active:
 *   put:
 *     summary: فعال‌سازی یا غیرفعال‌سازی حساب کاربری
 *     tags: [Profile]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: وضعیت حساب کاربری تغییر کرد
 */
router.put('/toggle-active', profileController.toggleAccountActive);

// تعریف схем‌های Swagger
/**
 * @swagger
 * components:
 *   schemas:
 *     UserProfile:
 *       type: object
 *       properties:
 *         _id:
 *           type: string
 *           example: "60d21b4667d0d8992e610c84"
 *         phone:
 *           type: string
 *           example: "09123456789"
 *         fullName:
 *           type: string
 *           example: "علی رضایی"
 *         email:
 *           type: string
 *           example: "ali.rezaei@example.com"
 *         profileImage:
 *           type: string
 *           example: "https://res.cloudinary.com/htland/image/upload/v1/avatar.jpg"
 *         isActive:
 *           type: boolean
 *           example: true
 *         isVerified:
 *           type: boolean
 *           example: true
 *         role:
 *           type: string
 *           enum: [user, admin, seller]
 *           example: "user"
 *         emailVerified:
 *           type: boolean
 *           example: false
 *         phoneVerified:
 *           type: boolean
 *           example: true
 *         notifications:
 *           $ref: '#/components/schemas/NotificationSettings'
 *         language:
 *           type: string
 *           enum: [fa, en]
 *           example: "fa"
 *         currency:
 *           type: string
 *           enum: [IRR, IRT]
 *           example: "IRT"
 *         lastLogin:
 *           type: string
 *           format: date-time
 *         loginCount:
 *           type: integer
 *           example: 42
 *         walletBalance:
 *           type: number
 *           example: 500000
 *         referralCode:
 *           type: string
 *           example: "HTABC12345"
 *         birthDate:
 *           type: string
 *           format: date
 *           example: "1990-01-01"
 *         gender:
 *           type: string
 *           enum: [male, female, other]
 *           example: "male"
 *         nationalCode:
 *           type: string
 *           example: "1234567890"
 *         favoriteCategories:
 *           type: array
 *           items:
 *             type: string
 *             enum: [rice, caviar, fish, honey, chicken, souvenirs]
 *           example: ["rice", "fish"]
 *         stats:
 *           $ref: '#/components/schemas/UserStats'
 *         safeInfo:
 *           type: object
 *           properties:
 *             phone:
 *               type: string
 *               example: "0912***6789"
 *             email:
 *               type: string
 *               example: "al***@example.com"
 *             nationalCode:
 *               type: string
 *               example: "123***890"
 *         createdAt:
 *           type: string
 *           format: date-time
 *         updatedAt:
 *           type: string
 *           format: date-time
 * 
 *     ProfileUpdate:
 *       type: object
 *       properties:
 *         fullName:
 *           type: string
 *           minLength: 3
 *           maxLength: 100
 *           example: "علی رضایی"
 *         email:
 *           type: string
 *           format: email
 *           example: "ali.rezaei@example.com"
 *         birthDate:
 *           type: string
 *           format: date
 *           example: "1990-01-01"
 *         gender:
 *           type: string
 *           enum: [male, female, other]
 *         nationalCode:
 *           type: string
 *           pattern: "^\d{10}$"
 *           example: "1234567890"
 *         language:
 *           type: string
 *           enum: [fa, en]
 *         currency:
 *           type: string
 *           enum: [IRR, IRT]
 * 
 *     NotificationSettings:
 *       type: object
 *       properties:
 *         sms:
 *           type: boolean
 *           example: true
 *         email:
 *           type: boolean
 *           example: false
 *         push:
 *           type: boolean
 *           example: true
 * 
 *     UserStats:
 *       type: object
 *       properties:
 *         orders:
 *           type: object
 *           properties:
 *             total:
 *               type: integer
 *               example: 15
 *             completed:
 *               type: integer
 *               example: 12
 *             pending:
 *               type: integer
 *               example: 3
 *         spending:
 *           type: object
 *           properties:
 *             total:
 *               type: number
 *               example: 3500000
 *             averagePerOrder:
 *               type: number
 *               example: 291666.67
 *         reviews:
 *           type: object
 *           properties:
 *             total:
 *               type: integer
 *               example: 8
 *             averageRating:
 *               type: string
 *               example: "4.5"
 *         wallet:
 *           type: object
 *           properties:
 *             balance:
 *               type: number
 *               example: 500000
 *             formattedBalance:
 *               type: string
 *               example: "۵۰۰,۰۰۰ تومان"
 *         wishlist:
 *           type: object
 *           properties:
 *             count:
 *               type: integer
 *               example: 7
 *         addresses:
 *           type: object
 *           properties:
 *             count:
 *               type: integer
 *               example: 2
 *         membership:
 *           type: object
 *           properties:
 *             duration:
 *               type: string
 *               example: "۶ ماه"
 *             level:
 *               type: string
 *               example: "نقره‌ای"
 * 
 *   securitySchemes:
 *     bearerAuth:
 *       type: http
 *       scheme: bearer
 *       bearerFormat: JWT
 */

module.exports = router;