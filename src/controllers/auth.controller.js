/**
 * @file کنترلر احراز هویت HTLand
 * @description مدیریت ثبت‌نام، ورود، OTP و پروفایل کاربر
 * @since 1.0.0
 */

const User = require('../models/User.model');
const Wallet = require('../models/Wallet.model');
const authService = require('../services/authService');
const { validationResult } = require('express-validator');
const logger = require('../config/logger');

/**
 * @class AuthController
 * @description کنترلر مدیریت عملیات احراز هویت
 */
class AuthController {
  
  /**
   * ارسال کد OTP برای ثبت‌نام/ورود
   * @param {Object} req - درخواست Express
   * @param {Object} res - پاسخ Express
   * @param {Function} next - تابع بعدی
   */
  async sendOTP(req, res, next) {
    try {
      // اعتبارسنجی ورودی‌ها
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          errors: errors.array()
        });
      }
      
      const { phone } = req.body;
      
      // بررسی rate limiting
      const canSend = await authService.checkRateLimit(phone, 'send_otp');
      if (!canSend) {
        return res.status(429).json({
          success: false,
          message: 'تعداد درخواست‌های شما بیش از حد مجاز است. لطفا ۱۵ دقیقه دیگر تلاش کنید.'
        });
      }
      
      // بررسی وجود کاربر
      let user = await User.findOne({ phone });
      const isNewUser = !user;
      
      if (isNewUser) {
        // کاربر جدید
        user = new User({
          phone,
          acceptedTerms: false,
          acceptedPrivacy: false
        });
      } else if (user.isLocked) {
        return res.status(423).json({
          success: false,
          message: 'حساب کاربری شما به دلیل تلاش‌های ناموفق قفل شده است. لطفا ۱۵ دقیقه دیگر تلاش کنید.'
        });
      }
      
      // تولید و ذخیره OTP
      const otpCode = user.generateOTP();
      await user.save();
      
      // ارسال OTP (در محیط production واقعی ارسال می‌شود)
      await authService.sendOTPSMS(phone, otpCode);
      
      // لاگ کردن فعالیت
      logger.info(`OTP sent to ${phone}`, {
        phone,
        isNewUser,
        otpCode: process.env.NODE_ENV === 'production' ? '******' : otpCode
      });
      
      res.status(200).json({
        success: true,
        message: 'کد تأیید به شماره موبایل شما ارسال شد',
        data: {
          phone,
          isNewUser,
          expiresIn: 300, // 5 دقیقه
          // در محیط توسعه کد OTP برمی‌گردانیم
          ...(process.env.NODE_ENV !== 'production' && { otpCode })
        }
      });
      
    } catch (error) {
      logger.error('Error in sendOTP:', error);
      next(error);
    }
  }
  
  /**
   * تأیید OTP و ورود/ثبت‌نام
   * @param {Object} req - درخواست Express
   * @param {Object} res - پاسخ Express
   * @param {Function} next - تابع بعدی
   */
  async verifyOTP(req, res, next) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          errors: errors.array()
        });
      }
      
      const { phone, otpCode, deviceInfo, ipAddress, acceptedTerms, acceptedPrivacy } = req.body;
      
      // بررسی rate limiting
      const canVerify = await authService.checkRateLimit(phone, 'verify_otp');
      if (!canVerify) {
        return res.status(429).json({
          success: false,
          message: 'تعداد درخواست‌های شما بیش از حد مجاز است. لطفا ۱۵ دقیقه دیگر تلاش کنید.'
        });
      }
      
      // پیدا کردن کاربر
      const user = await User.findOne({ phone });
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'کاربری با این شماره موبایل یافت نشد'
        });
      }
      
      if (user.isLocked) {
        return res.status(423).json({
          success: false,
          message: 'حساب کاربری شما به دلیل تلاش‌های ناموفق قفل شده است. لطفا ۱۵ دقیقه دیگر تلاش کنید.'
        });
      }
      
      // اعتبارسنجی OTP
      const validationResult = user.validateOTP(otpCode);
      if (!validationResult.isValid) {
        // افزایش تلاش‌های ناموفق
        user.incLoginAttempts();
        await user.save();
        
        return res.status(400).json({
          success: false,
          message: validationResult.reason
        });
      }
      
      // برای کاربران جدید، شرایط استفاده را ذخیره می‌کنیم
      if (acceptedTerms !== undefined) user.acceptedTerms = acceptedTerms;
      if (acceptedPrivacy !== undefined) user.acceptedPrivacy = acceptedPrivacy;
      
      // ایجاد کیف پول اگر وجود ندارد
      if (!user.walletId) {
        const wallet = new Wallet({
          userId: user._id,
          balance: 0,
          currency: 'IRT'
        });
        await wallet.save();
        user.walletId = wallet._id;
      }
      
      // ریست کردن تلاش‌های ورود
      user.resetLoginAttempts();
      
      // تولید توکن JWT
      const tokenData = user.generateAuthToken(
        deviceInfo || req.headers['user-agent'],
        ipAddress || req.ip
      );
      
      await user.save();
      
      // ساخت پاسخ
      const userResponse = user.toObject();
      delete userResponse.password;
      delete userResponse.otp;
      delete userResponse.sessions;
      
      logger.info(`User ${user._id} logged in successfully`, {
        userId: user._id,
        phone
      });
      
      res.status(200).json({
        success: true,
        message: 'ورود موفقیت‌آمیز بود',
        data: {
          user: userResponse,
          token: tokenData.token,
          expiresAt: tokenData.expiresAt,
          sessionId: tokenData.sessionId
        }
      });
      
    } catch (error) {
      logger.error('Error in verifyOTP:', error);
      next(error);
    }
  }
  
  /**
   * دریافت اطلاعات پروفایل کاربر جاری
   * @param {Object} req - درخواست Express
   * @param {Object} res - پاسخ Express
   * @param {Function} next - تابع بعدی
   */
  async getProfile(req, res, next) {
    try {
      const user = await User.findById(req.user.userId)
        .select('-password -otp -sessions')
        .populate('walletId', 'balance currency');
      
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'کاربر یافت نشد'
        });
      }
      
      res.status(200).json({
        success: true,
        data: { user }
      });
      
    } catch (error) {
      logger.error('Error in getProfile:', error);
      next(error);
    }
  }
  
  /**
   * به‌روزرسانی پروفایل کاربر
   * @param {Object} req - درخواست Express
   * @param {Object} res - پاسخ Express
   * @param {Function} next - تابع بعدی
   */
  async updateProfile(req, res, next) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          errors: errors.array()
        });
      }
      
      const updates = req.body;
      const userId = req.user.userId;
      
      // فیلدهای غیرقابل ویرایش
      const restrictedFields = ['phone', 'isAdmin', 'walletId', 'loginAttempts', 'lockUntil'];
      restrictedFields.forEach(field => delete updates[field]);
      
      // اگر ایمیل تغییر کرده، وضعیت تأیید را ریست کن
      if (updates.email) {
        const existingUser = await User.findOne({ 
          email: updates.email, 
          _id: { $ne: userId } 
        });
        
        if (existingUser) {
          return res.status(400).json({
            success: false,
            message: 'این ایمیل قبلا ثبت شده است'
          });
        }
        
        updates.isEmailVerified = false;
      }
      
      // اگر کد ملی تغییر کرده، اعتبارسنجی کن
      if (updates.nationalCode) {
        if (!/^\d{10}$/.test(updates.nationalCode)) {
          return res.status(400).json({
            success: false,
            message: 'کد ملی باید ۱۰ رقمی باشد'
          });
        }
      }
      
      const user = await User.findByIdAndUpdate(
        userId,
        { $set: updates },
        { new: true, runValidators: true }
      ).select('-password -otp -sessions');
      
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'کاربر یافت نشد'
        });
      }
      
      logger.info(`User ${userId} updated profile`);
      
      res.status(200).json({
        success: true,
        message: 'پروفایل با موفقیت به‌روزرسانی شد',
        data: { user }
      });
      
    } catch (error) {
      logger.error('Error in updateProfile:', error);
      next(error);
    }
  }
  
  /**
   * تغییر رمز عبور
   * @param {Object} req - درخواست Express
   * @param {Object} res - پاسخ Express
   * @param {Function} next - تابع بعدی
   */
  async changePassword(req, res, next) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          errors: errors.array()
        });
      }
      
      const { currentPassword, newPassword } = req.body;
      const userId = req.user.userId;
      
      const user = await User.findById(userId).select('+password');
      
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'کاربر یافت نشد'
        });
      }
      
      // بررسی رمز عبور فعلی
      const isMatch = await user.comparePassword(currentPassword);
      if (!isMatch) {
        return res.status(400).json({
          success: false,
          message: 'رمز عبور فعلی نادرست است'
        });
      }
      
      // بررسی مشابهت رمز عبور جدید با قبلی
      if (await user.comparePassword(newPassword)) {
        return res.status(400).json({
          success: false,
          message: 'رمز عبور جدید باید با رمز عبور فعلی متفاوت باشد'
        });
      }
      
      // بروزرسانی رمز عبور
      user.password = newPassword;
      await user.save();
      
      // باطل کردن تمام سشن‌ها به جز جاری
      const currentToken = req.headers.authorization?.replace('Bearer ', '');
      user.sessions = user.sessions.filter(session => session.token === currentToken);
      await user.save();
      
      logger.info(`User ${userId} changed password`);
      
      res.status(200).json({
        success: true,
        message: 'رمز عبور با موفقیت تغییر کرد. لطفا مجددا وارد شوید.'
      });
      
    } catch (error) {
      logger.error('Error in changePassword:', error);
      next(error);
    }
  }
  
  /**
   * افزودن آدرس جدید
   * @param {Object} req - درخواست Express
   * @param {Object} res - پاسخ Express
   * @param {Function} next - تابع بعدی
   */
  async addAddress(req, res, next) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          errors: errors.array()
        });
      }
      
      const userId = req.user.userId;
      const addressData = req.body;
      
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'کاربر یافت نشد'
        });
      }
      
      // اعتبارسنجی کد پستی
      if (addressData.postalCode && !/^\d{10}$/.test(addressData.postalCode)) {
        return res.status(400).json({
          success: false,
          message: 'کد پستی باید ۱۰ رقمی باشد'
        });
      }
      
      // اعتبارسنجی شماره موبایل تحویل‌گیرنده
      if (addressData.receiverPhone && !/^09[0-9]{9}$/.test(addressData.receiverPhone)) {
        return res.status(400).json({
          success: false,
          message: 'شماره موبایل تحویل‌گیرنده معتبر نیست'
        });
      }
      
      // اضافه کردن آدرس
      const newAddress = user.addAddress(addressData);
      await user.save();
      
      logger.info(`User ${userId} added new address`, {
        addressId: newAddress._id
      });
      
      res.status(201).json({
        success: true,
        message: 'آدرس با موفقیت اضافه شد',
        data: { address: newAddress }
      });
      
    } catch (error) {
      logger.error('Error in addAddress:', error);
      next(error);
    }
  }
  
  /**
   * به‌روزرسانی آدرس
   * @param {Object} req - درخواست Express
   * @param {Object} res - پاسخ Express
   * @param {Function} next - تابع بعدی
   */
  async updateAddress(req, res, next) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          errors: errors.array()
        });
      }
      
      const { addressId } = req.params;
      const addressData = req.body;
      const userId = req.user.userId;
      
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'کاربر یافت نشد'
        });
      }
      
      // بررسی وجود آدرس
      if (!user.hasAddress(addressId)) {
        return res.status(404).json({
          success: false,
          message: 'آدرس یافت نشد'
        });
      }
      
      // اعتبارسنجی کد پستی
      if (addressData.postalCode && !/^\d{10}$/.test(addressData.postalCode)) {
        return res.status(400).json({
          success: false,
          message: 'کد پستی باید ۱۰ رقمی باشد'
        });
      }
      
      // اعتبارسنجی شماره موبایل تحویل‌گیرنده
      if (addressData.receiverPhone && !/^09[0-9]{9}$/.test(addressData.receiverPhone)) {
        return res.status(400).json({
          success: false,
          message: 'شماره موبایل تحویل‌گیرنده معتبر نیست'
        });
      }
      
      // به‌روزرسانی آدرس
      const updatedAddress = user.updateAddress(addressId, addressData);
      await user.save();
      
      logger.info(`User ${userId} updated address ${addressId}`);
      
      res.status(200).json({
        success: true,
        message: 'آدرس با موفقیت به‌روزرسانی شد',
        data: { address: updatedAddress }
      });
      
    } catch (error) {
      logger.error('Error in updateAddress:', error);
      next(error);
    }
  }
  
  /**
   * حذف آدرس
   * @param {Object} req - درخواست Express
   * @param {Object} res - پاسخ Express
   * @param {Function} next - تابع بعدی
   */
  async deleteAddress(req, res, next) {
    try {
      const { addressId } = req.params;
      const userId = req.user.userId;
      
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'کاربر یافت نشد'
        });
      }
      
      // بررسی وجود آدرس
      if (!user.hasAddress(addressId)) {
        return res.status(404).json({
          success: false,
          message: 'آدرس یافت نشد'
        });
      }
      
      // حذف آدرس
      const removedAddress = user.removeAddress(addressId);
      await user.save();
      
      logger.info(`User ${userId} deleted address ${addressId}`);
      
      res.status(200).json({
        success: true,
        message: 'آدرس با موفقیت حذف شد',
        data: { address: removedAddress }
      });
      
    } catch (error) {
      logger.error('Error in deleteAddress:', error);
      next(error);
    }
  }
  
  /**
   * دریافت لیست آدرس‌ها
   * @param {Object} req - درخواست Express
   * @param {Object} res - پاسخ Express
   * @param {Function} next - تابع بعدی
   */
  async getAddresses(req, res, next) {
    try {
      const userId = req.user.userId;
      
      const user = await User.findById(userId).select('addresses');
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'کاربر یافت نشد'
        });
      }
      
      res.status(200).json({
        success: true,
        data: { addresses: user.addresses }
      });
      
    } catch (error) {
      logger.error('Error in getAddresses:', error);
      next(error);
    }
  }
  
  /**
   * خروج از سیستم (سشن جاری)
   * @param {Object} req - درخواست Express
   * @param {Object} res - پاسخ Express
   * @param {Function} next - تابع بعدی
   */
  async logout(req, res, next) {
    try {
      const userId = req.user.userId;
      const token = req.headers.authorization?.replace('Bearer ', '');
      
      const user = await User.findById(userId);
      if (user && token) {
        user.invalidateToken(token);
        await user.save();
      }
      
      logger.info(`User ${userId} logged out`);
      
      res.status(200).json({
        success: true,
        message: 'با موفقیت از سیستم خارج شدید'
      });
      
    } catch (error) {
      logger.error('Error in logout:', error);
      next(error);
    }
  }
  
  /**
   * خروج از تمام دستگاه‌ها
   * @param {Object} req - درخواست Express
   * @param {Object} res - پاسخ Express
   * @param {Function} next - تابع بعدی
   */
  async logoutAll(req, res, next) {
    try {
      const userId = req.user.userId;
      
      const user = await User.findById(userId);
      if (user) {
        user.invalidateAllTokens();
        await user.save();
      }
      
      logger.info(`User ${userId} logged out from all devices`);
      
      res.status(200).json({
        success: true,
        message: 'از تمام دستگاه‌ها خارج شدید'
      });
      
    } catch (error) {
      logger.error('Error in logoutAll:', error);
      next(error);
    }
  }
  
  /**
   * درخواست فراموشی رمز عبور
   * @param {Object} req - درخواست Express
   * @param {Object} res - پاسخ Express
   * @param {Function} next - تابع بعدی
   */
  async forgotPassword(req, res, next) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          errors: errors.array()
        });
      }
      
      const { phone } = req.body;
      
      // بررسی rate limiting
      const canSend = await authService.checkRateLimit(phone, 'forgot_password');
      if (!canSend) {
        return res.status(429).json({
          success: false,
          message: 'تعداد درخواست‌های شما بیش از حد مجاز است. لطفا ۱۵ دقیقه دیگر تلاش کنید.'
        });
      }
      
      const user = await User.findOne({ phone });
      if (!user) {
        // برای امنیت، حتی اگر کاربر وجود نداشته باشد هم پیام یکسان می‌دهیم
        return res.status(200).json({
          success: true,
          message: 'اگر شماره موبایل در سیستم موجود باشد، کد بازیابی ارسال خواهد شد'
        });
      }
      
      // تولید OTP برای بازیابی رمز عبور
      const otpCode = user.generateOTP();
      await user.save();
      
      // ارسال OTP
      await authService.sendPasswordResetSMS(phone, otpCode);
      
      logger.info(`Password reset OTP sent to ${phone}`);
      
      res.status(200).json({
        success: true,
        message: 'کد بازیابی رمز عبور ارسال شد',
        data: {
          phone,
          expiresIn: 300,
          ...(process.env.NODE_ENV !== 'production' && { otpCode })
        }
      });
      
    } catch (error) {
      logger.error('Error in forgotPassword:', error);
      next(error);
    }
  }
  
  /**
   * بازیابی رمز عبور با OTP
   * @param {Object} req - درخواست Express
   * @param {Object} res - پاسخ Express
   * @param {Function} next - تابع بعدی
   */
  async resetPassword(req, res, next) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          errors: errors.array()
        });
      }
      
      const { phone, otpCode, newPassword } = req.body;
      
      const user = await User.findOne({ phone }).select('+password');
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'کاربری با این شماره موبایل یافت نشد'
        });
      }
      
      // اعتبارسنجی OTP
      const validationResult = user.validateOTP(otpCode);
      if (!validationResult.isValid) {
        return res.status(400).json({
          success: false,
          message: validationResult.reason
        });
      }
      
      // بررسی مشابهت رمز عبور جدید با قبلی
      if (await user.comparePassword(newPassword)) {
        return res.status(400).json({
          success: false,
          message: 'رمز عبور جدید باید با رمز عبور قبلی متفاوت باشد'
        });
      }
      
      // تغییر رمز عبور
      user.password = newPassword;
      user.invalidateAllTokens(); // باطل کردن تمام سشن‌ها
      await user.save();
      
      logger.info(`User ${user._id} reset password via OTP`);
      
      res.status(200).json({
        success: true,
        message: 'رمز عبور با موفقیت تغییر کرد. لطفا مجددا وارد شوید.'
      });
      
    } catch (error) {
      logger.error('Error in resetPassword:', error);
      next(error);
    }
  }
  
  /**
   * حذف حساب کاربری
   * @param {Object} req - درخواست Express
   * @param {Object} res - پاسخ Express
   * @param {Function} next - تابع بعدی
   */
  async deleteAccount(req, res, next) {
    try {
      const userId = req.user.userId;
      const { password } = req.body;
      
      // برای حذف حساب، نیاز به تأیید رمز عبور داریم
      const user = await User.findById(userId).select('+password');
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'کاربر یافت نشد'
        });
      }
      
      // بررسی رمز عبور
      if (!password || !(await user.comparePassword(password))) {
        return res.status(400).json({
          success: false,
          message: 'رمز عبور نادرست است'
        });
      }
      
      // به جای حذف فیزیکی، حساب را غیرفعال می‌کنیم
      user.isActive = false;
      user.invalidateAllTokens();
      await user.save();
      
      logger.info(`User ${userId} deactivated account`);
      
      res.status(200).json({
        success: true,
        message: 'حساب کاربری شما با موفقیت غیرفعال شد'
      });
      
    } catch (error) {
      logger.error('Error in deleteAccount:', error);
      next(error);
    }
  }
  
  /**
   * دریافت لیست سشن‌های فعال
   * @param {Object} req - درخواست Express
   * @param {Object} res - پاسخ Express
   * @param {Function} next - تابع بعدی
   */
  async getActiveSessions(req, res, next) {
    try {
      const userId = req.user.userId;
      const currentToken = req.headers.authorization?.replace('Bearer ', '');
      
      const user = await User.findById(userId).select('sessions');
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'کاربر یافت نشد'
        });
      }
      
      // فیلتر سشن‌های فعال
      const activeSessions = user.sessions
        .filter(session => session.isActive && session.expiresAt > new Date())
        .map(session => ({
          _id: session._id,
          deviceInfo: session.deviceInfo,
          ipAddress: session.ipAddress,
          createdAt: session.createdAt,
          expiresAt: session.expiresAt,
          isCurrent: session.token === currentToken
        }));
      
      res.status(200).json({
        success: true,
        data: { sessions: activeSessions }
      });
      
    } catch (error) {
      logger.error('Error in getActiveSessions:', error);
      next(error);
    }
  }
  
  /**
   * حذف سشن خاص
   * @param {Object} req - درخواست Express
   * @param {Object} res - پاسخ Express
   * @param {Function} next - تابع بعدی
   */
  async revokeSession(req, res, next) {
    try {
      const userId = req.user.userId;
      const { sessionId } = req.params;
      const currentToken = req.headers.authorization?.replace('Bearer ', '');
      
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'کاربر یافت نشد'
        });
      }
      
      // پیدا کردن سشن
      const sessionIndex = user.sessions.findIndex(s => s._id.toString() === sessionId);
      if (sessionIndex === -1) {
        return res.status(404).json({
          success: false,
          message: 'سشن یافت نشد'
        });
      }
      
      // بررسی اینکه سشن جاری را نمی‌توان حذف کرد
      if (user.sessions[sessionIndex].token === currentToken) {
        return res.status(400).json({
          success: false,
          message: 'نمی‌توان سشن جاری را حذف کرد'
        });
      }
      
      // حذف سشن
      user.sessions.splice(sessionIndex, 1);
      await user.save();
      
      logger.info(`User ${userId} revoked session ${sessionId}`);
      
      res.status(200).json({
        success: true,
        message: 'سشن با موفقیت حذف شد'
      });
      
    } catch (error) {
      logger.error('Error in revokeSession:', error);
      next(error);
    }
  }
}

module.exports = new AuthController();