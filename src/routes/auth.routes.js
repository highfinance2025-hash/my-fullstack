/**
 * @file روت‌های احراز هویت HTLand
 */

const express = require('express');
const router = express.Router();
const authController = require('../controllers/auth.controller');
const authMiddleware = require('../middlewares/auth.middleware');
const { body, param, query } = require('express-validator');
const rateLimit = require('express-rate-limit');

// Rate limiters
const otpRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10, 
  message: { success: false, message: 'تعداد درخواست‌ها زیاد است' }
});

const loginRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { success: false, message: 'تعداد درخواست‌ها زیاد است' }
});

// Validations
const phoneValidation = body('phone')
  .notEmpty().withMessage('شماره موبایل الزامی است')
  .matches(/^09[0-9]{9}$/).withMessage('شماره موبایل معتبر نیست');

const otpValidation = body('otpCode')
  .notEmpty().withMessage('کد تأیید الزامی است')
  .isLength({ min: 6, max: 6 }).withMessage('کد تأیید باید ۶ رقمی باشد');

/**
 * ✅ تست ساده
 */
router.get('/test-me', (req, res) => {
  res.json({ success: true, message: 'Auth routes are working!' });
});

/**
 * روت‌های عمومی
 */
router.post('/send-otp', otpRateLimiter, [phoneValidation], authController.sendOTP);
router.post('/verify-otp', loginRateLimiter, [phoneValidation, otpValidation], authController.verifyOTP);
router.post('/forgot-password', otpRateLimiter, [phoneValidation], authController.forgotPassword);

/**
 * روت‌های خصوصی (نیاز به توکن)
 * نکته: حتماً باید () بعد از authenticate باشد
 */
router.get('/profile', authMiddleware.authenticate(), authController.getProfile);
router.put('/profile', authMiddleware.authenticate(), authController.updateProfile);
router.post('/change-password', authMiddleware.authenticate(), authController.changePassword);
router.post('/logout', authMiddleware.authenticate(), authController.logout);

// Addresses
router.post('/addresses', authMiddleware.authenticate(), authController.addAddress);
router.get('/addresses', authMiddleware.authenticate(), authController.getAddresses);
router.put('/addresses/:addressId', authMiddleware.authenticate(), authController.updateAddress);
router.delete('/addresses/:addressId', authMiddleware.authenticate(), authController.deleteAddress);

// Sessions
router.get('/sessions', authMiddleware.authenticate(), authController.getActiveSessions);
router.delete('/sessions/:sessionId', authMiddleware.authenticate(), authController.revokeSession);

// Admin
router.get('/admin/users', authMiddleware.authenticate(), authMiddleware.authorize(['admin']), (req, res) => {
  res.json({ success: true, message: 'Admin Panel - Users List' });
});

module.exports = router;