/**
 * @file روت‌های احراز هویت HTLand
 * @description مدیریت مسیرهای API مربوط به ثبت‌نام، ورود و پروفایل کاربر
 * @since 1.0.0
 */

const express = require('express');
const router = express.Router();
const authController = require('../controllers/auth.controller');
const authMiddleware = require('../middlewares/auth.middleware');
const { body, param, query } = require('express-validator');
const rateLimit = require('express-rate-limit');

/**
 * Rate limiting برای درخواست‌های OTP
 */
const otpRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 دقیقه
  max: 3, // ۳ درخواست در هر پنجره زمانی
  message: {
    success: false,
    message: 'تعداد درخواست‌های شما بیش از حد مجاز است. لطفا ۱۵ دقیقه دیگر تلاش کنید.'
  },
  standardHeaders: true,
  legacyHeaders: false
});

/**
 * Rate limiting برای ورود
 */
const loginRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 دقیقه
  max: 5, // ۵ درخواست در هر پنجره زمانی
  message: {
    success: false,
    message: 'تعداد درخواست‌های ورود شما بیش از حد مجاز است. لطفا ۱۵ دقیقه دیگر تلاش کنید.'
  },
  standardHeaders: true,
  legacyHeaders: false
});

/**
 * اعتبارسنجی‌های مشترک
 */
const phoneValidation = body('phone')
  .notEmpty().withMessage('شماره موبایل الزامی است')
  .matches(/^09[0-9]{9}$/).withMessage('شماره موبایل معتبر نیست')
  .trim();

const otpValidation = body('otpCode')
  .notEmpty().withMessage('کد تأیید الزامی است')
  .isLength({ min: 6, max: 6 }).withMessage('کد تأیید باید ۶ رقمی باشد')
  .isNumeric().withMessage('کد تأیید باید عددی باشد');

const passwordValidation = body('password')
  .notEmpty().withMessage('رمز عبور الزامی است')
  .isLength({ min: 6 }).withMessage('رمز عبور باید حداقل ۶ کاراکتر باشد');

const newPasswordValidation = body('newPassword')
  .notEmpty().withMessage('رمز عبور جدید الزامی است')
  .isLength({ min: 6 }).withMessage('رمز عبور جدید باید حداقل ۶ کاراکتر باشد')
  .custom((value, { req }) => {
    if (value === req.body.currentPassword) {
      throw new Error('رمز عبور جدید باید با رمز عبور فعلی متفاوت باشد');
    }
    return true;
  });

/**
 * روت‌های عمومی (بدون نیاز به احراز هویت)
 */

// ارسال OTP
router.post(
  '/send-otp',
  otpRateLimiter,
  [
    phoneValidation,
    body('deviceInfo').optional().trim(),
    body('ipAddress').optional().isIP().withMessage('آدرس IP معتبر نیست')
  ],
  authController.sendOTP
);

// تأیید OTP و ورود/ثبت‌نام
router.post(
  '/verify-otp',
  loginRateLimiter,
  [
    phoneValidation,
    otpValidation,
    body('deviceInfo').optional().trim(),
    body('ipAddress').optional().isIP().withMessage('آدرس IP معتبر نیست'),
    body('acceptedTerms').optional().isBoolean().withMessage('قبول قوانین باید true/false باشد'),
    body('acceptedPrivacy').optional().isBoolean().withMessage('قبول حریم خصوصی باید true/false باشد')
  ],
  authController.verifyOTP
);

// فراموشی رمز عبور
router.post(
  '/forgot-password',
  otpRateLimiter,
  [phoneValidation],
  authController.forgotPassword
);

// بازیابی رمز عبور
router.post(
  '/reset-password',
  [
    phoneValidation,
    otpValidation,
    newPasswordValidation
  ],
  authController.resetPassword
);

/**
 * روت‌های احراز شده (نیاز به توکن JWT)
 */

// دریافت پروفایل کاربر
router.get(
  '/profile',
  authMiddleware.authenticate,
  authController.getProfile
);

// به‌روزرسانی پروفایل
router.put(
  '/profile',
  authMiddleware.authenticate,
  [
    body('firstName').optional().trim().isLength({ max: 50 }).withMessage('نام نمی‌تواند بیشتر از ۵۰ کاراکتر باشد'),
    body('lastName').optional().trim().isLength({ max: 50 }).withMessage('نام خانوادگی نمی‌تواند بیشتر از ۵۰ کاراکتر باشد'),
    body('email').optional().isEmail().withMessage('ایمیل معتبر نیست').normalizeEmail(),
    body('nationalCode').optional().matches(/^\d{10}$/).withMessage('کد ملی باید ۱۰ رقمی باشد'),
    body('birthDate').optional().isISO8601().withMessage('تاریخ تولد معتبر نیست'),
    body('gender').optional().isIn(['male', 'female', 'other']).withMessage('جنسیت معتبر نیست'),
    body('settings.notifications.sms').optional().isBoolean(),
    body('settings.notifications.email').optional().isBoolean(),
    body('settings.notifications.push').optional().isBoolean(),
    body('settings.theme').optional().isIn(['light', 'dark', 'auto']),
    body('settings.language').optional().isIn(['fa', 'en'])
  ],
  authController.updateProfile
);

// تغییر رمز عبور
router.post(
  '/change-password',
  authMiddleware.authenticate,
  [
    passwordValidation.custom((value, { req }) => {
      if (value === req.body.newPassword) {
        throw new Error('رمز عبور جدید باید با رمز عبور فعلی متفاوت باشد');
      }
      return true;
    }),
    newPasswordValidation
  ],
  authController.changePassword
);

// مدیریت آدرس‌ها

// افزودن آدرس جدید
router.post(
  '/addresses',
  authMiddleware.authenticate,
  [
    body('title').notEmpty().withMessage('عنوان آدرس الزامی است').trim(),
    body('province').notEmpty().withMessage('استان الزامی است').trim(),
    body('city').notEmpty().withMessage('شهر الزامی است').trim(),
    body('postalCode').matches(/^\d{10}$/).withMessage('کد پستی باید ۱۰ رقمی باشد'),
    body('address').notEmpty().withMessage('آدرس الزامی است').trim(),
    body('receiverName').notEmpty().withMessage('نام تحویل‌گیرنده الزامی است').trim(),
    body('receiverPhone').matches(/^09[0-9]{9}$/).withMessage('شماره موبایل تحویل‌گیرنده معتبر نیست'),
    body('isDefault').optional().isBoolean()
  ],
  authController.addAddress
);

// دریافت لیست آدرس‌ها
router.get(
  '/addresses',
  authMiddleware.authenticate,
  authController.getAddresses
);

// به‌روزرسانی آدرس
router.put(
  '/addresses/:addressId',
  authMiddleware.authenticate,
  [
    param('addressId').isMongoId().withMessage('شناسه آدرس معتبر نیست'),
    body('title').optional().trim(),
    body('province').optional().trim(),
    body('city').optional().trim(),
    body('postalCode').optional().matches(/^\d{10}$/).withMessage('کد پستی باید ۱۰ رقمی باشد'),
    body('address').optional().trim(),
    body('receiverName').optional().trim(),
    body('receiverPhone').optional().matches(/^09[0-9]{9}$/).withMessage('شماره موبایل تحویل‌گیرنده معتبر نیست'),
    body('isDefault').optional().isBoolean()
  ],
  authController.updateAddress
);

// حذف آدرس
router.delete(
  '/addresses/:addressId',
  authMiddleware.authenticate,
  [
    param('addressId').isMongoId().withMessage('شناسه آدرس معتبر نیست')
  ],
  authController.deleteAddress
);

// مدیریت سشن‌ها

// دریافت سشن‌های فعال
router.get(
  '/sessions',
  authMiddleware.authenticate,
  authController.getActiveSessions
);

// حذف سشن خاص
router.delete(
  '/sessions/:sessionId',
  authMiddleware.authenticate,
  [
    param('sessionId').isMongoId().withMessage('شناسه سشن معتبر نیست')
  ],
  authController.revokeSession
);

// خروج از سیستم (سشن جاری)
router.post(
  '/logout',
  authMiddleware.authenticate,
  authController.logout
);

// خروج از تمام دستگاه‌ها
router.post(
  '/logout-all',
  authMiddleware.authenticate,
  authController.logoutAll
);

// حذف حساب کاربری
router.delete(
  '/account',
  authMiddleware.authenticate,
  [
    body('password').notEmpty().withMessage('رمز عبور برای حذف حساب الزامی است')
  ],
  authController.deleteAccount
);

/**
 * روت‌های مدیریتی (فقط ادمین)
 */

// دریافت لیست کاربران (ادمین)
router.get(
  '/admin/users',
  authMiddleware.authenticate,
  authMiddleware.authorize(['admin']),
  [
    query('page').optional().isInt({ min: 1 }).withMessage('شماره صفحه باید عدد مثبت باشد'),
    query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('تعداد آیتم‌ها باید بین ۱ تا ۱۰۰ باشد'),
    query('search').optional().trim(),
    query('isActive').optional().isBoolean(),
    query('isVerified').optional().isBoolean()
  ],
  async (req, res, next) => {
    // پیاده‌سازی در کنترلر جداگانه ادمین
    res.status(200).json({
      success: true,
      message: 'این روت نیاز به پیاده‌سازی دارد'
    });
  }
);

// غیرفعال کردن کاربر (ادمین)
router.put(
  '/admin/users/:userId/disable',
  authMiddleware.authenticate,
  authMiddleware.authorize(['admin']),
  [
    param('userId').isMongoId().withMessage('شناسه کاربر معتبر نیست')
  ],
  async (req, res, next) => {
    // پیاده‌سازی در کنترلر جداگانه ادمین
    res.status(200).json({
      success: true,
      message: 'این روت نیاز به پیاده‌سازی دارد'
    });
  }
);

/**
 * روت‌های تستی (فقط در محیط توسعه)
 */

if (process.env.NODE_ENV === 'development') {
  // تولید توکن تستی
  router.post(
    '/dev/generate-test-token',
    [
      body('phone').matches(/^09[0-9]{9}$/).withMessage('شماره موبایل معتبر نیست'),
      body('isAdmin').optional().isBoolean()
    ],
    async (req, res) => {
      try {
        const jwt = require('jsonwebtoken');
        const User = require('../models/User.model');
        
        const { phone, isAdmin = false } = req.body;
        
        let user = await User.findOne({ phone });
        if (!user) {
          user = new User({
            phone,
            isPhoneVerified: true,
            isAdmin
          });
          await user.save();
        }
        
        const token = user.generateAuthToken('Test Device', '127.0.0.1');
        await user.save();
        
        res.status(200).json({
          success: true,
          data: {
            token: token.token,
            userId: user._id,
            phone: user.phone,
            isAdmin: user.isAdmin
          }
        });
      } catch (error) {
        res.status(500).json({
          success: false,
          message: error.message
        });
      }
    }
  );
}

module.exports = router;