/**
 * @file کنترلر مدیریت پروفایل کاربران HTLand
 * @description عملیات مدیریت اطلاعات شخصی و پروفایل کاربران
 * @since 1403/10/01
 */

const asyncHandler = require('express-async-handler');
const multer = require('multer');
const profileService = require('../services/profileService');
const { uploadProfileImage } = require('../utils/upload');

/**
 * @desc    دریافت اطلاعات پروفایل کاربر
 * @route   GET /api/v1/profile
 * @access  Private
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
 *       401:
 *         description: کاربر لاگین نکرده است
 */
const getProfile = asyncHandler(async (req, res) => {
  const userId = req.user._id;
  
  const profile = await profileService.getUserProfile(userId);
  
  res.status(200).json({
    success: true,
    data: profile
  });
});

/**
 * @desc    ویرایش اطلاعات پروفایل
 * @route   PUT /api/v1/profile
 * @access  Private
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
 *             type: object
 *             properties:
 *               fullName:
 *                 type: string
 *                 example: "علی رضایی"
 *               email:
 *                 type: string
 *                 example: "ali.rezaei@example.com"
 *               birthDate:
 *                 type: string
 *                 format: date
 *                 example: "1990-01-01"
 *               gender:
 *                 type: string
 *                 enum: [male, female, other]
 *               nationalCode:
 *                 type: string
 *                 example: "1234567890"
 *               language:
 *                 type: string
 *                 enum: [fa, en]
 *               currency:
 *                 type: string
 *                 enum: [IRR, IRT]
 *               notifications:
 *                 type: object
 *                 properties:
 *                   sms:
 *                     type: boolean
 *                   email:
 *                     type: boolean
 *                   push:
 *                     type: boolean
 *     responses:
 *       200:
 *         description: پروفایل با موفقیت ویرایش شد
 *       400:
 *         description: داده‌های ورودی معتبر نیست
 */
const updateProfile = asyncHandler(async (req, res) => {
  const userId = req.user._id;
  const updateData = req.body;
  
  // اعتبارسنجی تاریخ تولد
  if (updateData.birthDate) {
    const birthDate = new Date(updateData.birthDate);
    const today = new Date();
    
    if (birthDate > today) {
      return res.status(400).json({
        success: false,
        error: 'تاریخ تولد نمی‌تواند در آینده باشد'
      });
    }
    
    const age = today.getFullYear() - birthDate.getFullYear();
    if (age < 13) {
      return res.status(400).json({
        success: false,
        error: 'حداقل سن برای ثبت نام ۱۳ سال است'
      });
    }
  }
  
  const profile = await profileService.updateUserProfile(userId, updateData);
  
  res.status(200).json({
    success: true,
    message: 'اطلاعات پروفایل با موفقیت ویرایش شد',
    data: profile
  });
});

/**
 * @desc    آپلود تصویر پروفایل
 * @route   POST /api/v1/profile/upload-image
 * @access  Private
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
 *                 description: تصویر پروفایل (حداکثر 5MB، فرمت‌های مجاز: jpg, jpeg, png, webp)
 *     responses:
 *       200:
 *         description: تصویر پروفایل با موفقیت آپلود شد
 *       400:
 *         description: فایل معتبر نیست یا حجم آن زیاد است
 *       500:
 *         description: خطا در آپلود تصویر
 */
const uploadProfileImageHandler = [
  uploadProfileImage.single('profileImage'),
  asyncHandler(async (req, res) => {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        error: 'لطفاً یک تصویر انتخاب کنید'
      });
    }
    
    const userId = req.user._id;
    const imageUrl = req.file.path;
    const publicId = req.file.filename;
    
    const user = await profileService.updateProfileImage(
      userId, 
      imageUrl, 
      publicId
    );
    
    // حذف فایل موقت از سرور
    if (req.file.path && !req.file.path.startsWith('http')) {
      const fs = require('fs');
      fs.unlinkSync(req.file.path);
    }
    
    res.status(200).json({
      success: true,
      message: 'تصویر پروفایل با موفقیت آپلود شد',
      data: {
        profileImage: imageUrl,
        fullName: user.fullName
      }
    });
  })
];

/**
 * @desc    حذف تصویر پروفایل
 * @route   DELETE /api/v1/profile/remove-image
 * @access  Private
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
 *       404:
 *         description: کاربر پیدا نشد
 */
const removeProfileImage = asyncHandler(async (req, res) => {
  const userId = req.user._id;
  
  const user = await profileService.removeProfileImage(userId);
  
  res.status(200).json({
    success: true,
    message: 'تصویر پروفایل با موفقیت حذف شد',
    data: {
      profileImage: user.profileImage,
      fullName: user.fullName
    }
  });
});

/**
 * @desc    تغییر تنظیمات اعلان‌ها
 * @route   PUT /api/v1/profile/notifications
 * @access  Private
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
 *             type: object
 *             properties:
 *               sms:
 *                 type: boolean
 *                 example: true
 *               email:
 *                 type: boolean
 *                 example: false
 *               push:
 *                 type: boolean
 *                 example: true
 *     responses:
 *       200:
 *         description: تنظیمات اعلان‌ها با موفقیت ویرایش شد
 */
const updateNotificationSettings = asyncHandler(async (req, res) => {
  const userId = req.user._id;
  const { sms, email, push } = req.body;
  
  const user = await profileService.updateNotificationSettings(
    userId, 
    { sms, email, push }
  );
  
  res.status(200).json({
    success: true,
    message: 'تنظیمات اعلان‌ها با موفقیت ویرایش شد',
    data: {
      notifications: user.notifications
    }
  });
});

/**
 * @desc    تغییر رمز عبور
 * @route   PUT /api/v1/profile/change-password
 * @access  Private
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
 *                 example: "oldPassword123"
 *               newPassword:
 *                 type: string
 *                 example: "newPassword456"
 *     responses:
 *       200:
 *         description: رمز عبور با موفقیت تغییر کرد
 *       400:
 *         description: رمز عبور فعلی نادرست است
 */
const changePassword = asyncHandler(async (req, res) => {
  const userId = req.user._id;
  const { currentPassword, newPassword } = req.body;
  
  if (newPassword.length < 6) {
    return res.status(400).json({
      success: false,
      error: 'رمز عبور جدید باید حداقل ۶ کاراکتر باشد'
    });
  }
  
  const result = await profileService.changePassword(
    userId, 
    currentPassword, 
    newPassword
  );
  
  if (!result) {
    return res.status(400).json({
      success: false,
      error: 'رمز عبور فعلی نادرست است'
    });
  }
  
  res.status(200).json({
    success: true,
    message: 'رمز عبور با موفقیت تغییر کرد'
  });
});

/**
 * @desc    دریافت آمار پروفایل کاربر
 * @route   GET /api/v1/profile/stats
 * @access  Private
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
const getProfileStats = asyncHandler(async (req, res) => {
  const userId = req.user._id;
  
  const stats = await profileService.getUserStats(userId);
  
  res.status(200).json({
    success: true,
    data: stats
  });
});

/**
 * @desc    فعال‌سازی یا غیرفعال‌سازی حساب کاربری
 * @route   PUT /api/v1/profile/toggle-active
 * @access  Private
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
const toggleAccountActive = asyncHandler(async (req, res) => {
  const userId = req.user._id;
  
  const user = await profileService.toggleAccountActive(userId);
  
  res.status(200).json({
    success: true,
    message: `حساب کاربری ${user.isActive ? 'فعال' : 'غیرفعال'} شد`,
    data: {
      isActive: user.isActive
    }
  });
});

module.exports = {
  getProfile,
  updateProfile,
  uploadProfileImageHandler,
  removeProfileImage,
  updateNotificationSettings,
  changePassword,
  getProfileStats,
  toggleAccountActive
};