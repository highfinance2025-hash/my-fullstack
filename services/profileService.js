/**
 * @file سرویس مدیریت پروفایل کاربران HTLand
 * @description منطق کسب‌وکار و عملیات‌های مربوط به پروفایل کاربران
 * @since 1403/10/01
 */

const User = require('../models/User.model');
const Order = require('../models/Order.model');
const Review = require('../models/Review.model');
const cloudinary = require('../config/cloudinary');
const logger = require('../utils/logger');
const bcrypt = require('bcryptjs');

/**
 * دریافت اطلاعات پروفایل کاربر
 * @param {string} userId - شناسه کاربر
 * @returns {Promise<Object>} اطلاعات پروفایل
 */
const getUserProfile = async (userId) => {
  try {
    const user = await User.findById(userId)
      .select('-password -verificationCode -verificationCodeExpires -__v')
      .lean();
    
    if (!user) {
      throw new Error('کاربر پیدا نشد');
    }
    
    // افزودن اطلاعات آماری
    const stats = await getUserStatistics(userId);
    
    return {
      ...user,
      stats,
      safeInfo: {
        phone: maskPhoneNumber(user.phone),
        email: user.email ? maskEmail(user.email) : null,
        nationalCode: user.nationalCode ? maskNationalCode(user.nationalCode) : null
      }
    };
  } catch (error) {
    logger.error(`خطا در دریافت پروفایل کاربر ${userId}:`, error);
    throw new Error('خطا در دریافت اطلاعات پروفایل');
  }
};

/**
 * ویرایش اطلاعات پروفایل کاربر
 * @param {string} userId - شناسه کاربر
 * @param {Object} updateData - اطلاعات جدید
 * @returns {Promise<Object>} کاربر ویرایش شده
 */
const updateUserProfile = async (userId, updateData) => {
  try {
    // فیلدهای غیرقابل ویرایش
    const immutableFields = ['phone', 'role', 'walletBalance', 'referralCode'];
    immutableFields.forEach(field => {
      if (updateData[field] !== undefined) {
        delete updateData[field];
      }
    });
    
    // اعتبارسنجی ایمیل اگر وجود دارد
    if (updateData.email) {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(updateData.email)) {
        throw new Error('ایمیل معتبر نیست');
      }
      
      // بررسی تکراری نبودن ایمیل
      const existingUser = await User.findOne({
        email: updateData.email,
        _id: { $ne: userId }
      });
      
      if (existingUser) {
        throw new Error('این ایمیل قبلاً ثبت شده است');
      }
    }
    
    // اعتبارسنجی کد ملی اگر وجود دارد
    if (updateData.nationalCode) {
      if (!/^\d{10}$/.test(updateData.nationalCode)) {
        throw new Error('کد ملی باید ۱۰ رقم باشد');
      }
      
      // الگوریتم کنترل کد ملی (اختیاری)
      if (!validateNationalCode(updateData.nationalCode)) {
        throw new Error('کد ملی معتبر نیست');
      }
    }
    
    const user = await User.findByIdAndUpdate(
      userId,
      { $set: updateData },
      { new: true, runValidators: true }
    ).select('-password -verificationCode -verificationCodeExpires -__v');
    
    if (!user) {
      throw new Error('کاربر پیدا نشد');
    }
    
    logger.info(`پروفایل کاربر ${userId} ویرایش شد`);
    
    return user;
  } catch (error) {
    logger.error(`خطا در ویرایش پروفایل کاربر ${userId}:`, error);
    throw error;
  }
};

/**
 * آپدیت تصویر پروفایل
 * @param {string} userId - شناسه کاربر
 * @param {string} imageUrl - آدرس تصویر جدید
 * @param {string} publicId - شناسه عمومی در Cloudinary
 * @returns {Promise<Object>} کاربر با تصویر جدید
 */
const updateProfileImage = async (userId, imageUrl, publicId) => {
  try {
    // پیدا کردن کاربر فعلی برای حذف تصویر قبلی
    const currentUser = await User.findById(userId)
      .select('profileImagePublicId');
    
    // اگر تصویر قبلی وجود دارد، از Cloudinary حذف کن
    if (currentUser && currentUser.profileImagePublicId) {
      try {
        await cloudinary.uploader.destroy(currentUser.profileImagePublicId);
        logger.info(`تصویر قبلی از Cloudinary حذف شد: ${currentUser.profileImagePublicId}`);
      } catch (cloudinaryError) {
        logger.warn('خطا در حذف تصویر قبلی از Cloudinary:', cloudinaryError);
      }
    }
    
    // آپدیت کاربر با تصویر جدید
    const user = await User.findByIdAndUpdate(
      userId,
      {
        $set: {
          profileImage: imageUrl,
          profileImagePublicId: publicId
        }
      },
      { new: true }
    ).select('-password -verificationCode -verificationCodeExpires -__v');
    
    if (!user) {
      throw new Error('کاربر پیدا نشد');
    }
    
    logger.info(`تصویر پروفایل کاربر ${userId} آپدیت شد`);
    
    return user;
  } catch (error) {
    logger.error(`خطا در آپدیت تصویر پروفایل کاربر ${userId}:`, error);
    throw new Error('خطا در آپدیت تصویر پروفایل');
  }
};

/**
 * حذف تصویر پروفایل
 * @param {string} userId - شناسه کاربر
 * @returns {Promise<Object>} کاربر بدون تصویر پروفایل
 */
const removeProfileImage = async (userId) => {
  try {
    const user = await User.findById(userId)
      .select('profileImagePublicId');
    
    if (!user) {
      throw new Error('کاربر پیدا نشد');
    }
    
    // اگر تصویری در Cloudinary وجود دارد، حذف کن
    if (user.profileImagePublicId) {
      try {
        await cloudinary.uploader.destroy(user.profileImagePublicId);
        logger.info(`تصویر پروفایل از Cloudinary حذف شد: ${user.profileImagePublicId}`);
      } catch (cloudinaryError) {
        logger.warn('خطا در حذف تصویر از Cloudinary:', cloudinaryError);
      }
    }
    
    // آپدیت کاربر با تصویر پیش‌فرض
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      {
        $set: {
          profileImage: 'https://res.cloudinary.com/htland/image/upload/v1/default-avatar.png',
          profileImagePublicId: null
        }
      },
      { new: true }
    ).select('-password -verificationCode -verificationCodeExpires -__v');
    
    logger.info(`تصویر پروفایل کاربر ${userId} حذف شد`);
    
    return updatedUser;
  } catch (error) {
    logger.error(`خطا در حذف تصویر پروفایل کاربر ${userId}:`, error);
    throw new Error('خطا در حذف تصویر پروفایل');
  }
};

/**
 * تغییر رمز عبور
 * @param {string} userId - شناسه کاربر
 * @param {string} currentPassword - رمز عبور فعلی
 * @param {string} newPassword - رمز عبور جدید
 * @returns {Promise<boolean>} موفقیت عملیات
 */
const changePassword = async (userId, currentPassword, newPassword) => {
  try {
    const user = await User.findById(userId).select('+password');
    
    if (!user) {
      throw new Error('کاربر پیدا نشد');
    }
    
    // بررسی رمز عبور فعلی
    const isMatch = await user.comparePassword(currentPassword);
    if (!isMatch) {
      return false;
    }
    
    // بررسی عدم تشابه رمز عبور جدید با قبلی
    const isSame = await user.comparePassword(newPassword);
    if (isSame) {
      throw new Error('رمز عبور جدید نباید با رمز عبور فعلی یکسان باشد');
    }
    
    // تغییر رمز عبور
    user.password = newPassword;
    await user.save();
    
    logger.info(`رمز عبور کاربر ${userId} تغییر کرد`);
    
    return true;
  } catch (error) {
    logger.error(`خطا در تغییر رمز عبور کاربر ${userId}:`, error);
    throw error;
  }
};

/**
 * تغییر تنظیمات اعلان‌ها
 * @param {string} userId - شناسه کاربر
 * @param {Object} settings - تنظیمات جدید
 * @returns {Promise<Object>} کاربر با تنظیمات جدید
 */
const updateNotificationSettings = async (userId, settings) => {
  try {
    const user = await User.findByIdAndUpdate(
      userId,
      {
        $set: {
          'notifications.sms': settings.sms !== undefined ? settings.sms : true,
          'notifications.email': settings.email !== undefined ? settings.email : true,
          'notifications.push': settings.push !== undefined ? settings.push : true
        }
      },
      { new: true }
    ).select('-password -verificationCode -verificationCodeExpires -__v');
    
    if (!user) {
      throw new Error('کاربر پیدا نشد');
    }
    
    logger.info(`تنظیمات اعلان‌های کاربر ${userId} آپدیت شد`);
    
    return user;
  } catch (error) {
    logger.error(`خطا در آپدیت تنظیمات اعلان‌های کاربر ${userId}:`, error);
    throw new Error('خطا در آپدیت تنظیمات اعلان‌ها');
  }
};

/**
 * دریافت آمار کاربر
 * @param {string} userId - شناسه کاربر
 * @returns {Promise<Object>} آمار کاربر
 */
const getUserStats = async (userId) => {
  try {
    const [
      totalOrders,
      completedOrders,
      totalSpent,
      totalReviews,
      averageRating,
      walletBalance,
      wishlistCount,
      addressesCount
    ] = await Promise.all([
      // تعداد کل سفارش‌ها
      Order.countDocuments({ user: userId }),
      
      // تعداد سفارش‌های تکمیل شده
      Order.countDocuments({ user: userId, status: 'delivered' }),
      
      // مجموع مبلغ خریدها
      Order.aggregate([
        { $match: { user: mongoose.Types.ObjectId(userId), status: 'delivered' } },
        { $group: { _id: null, total: { $sum: '$totalAmount' } } }
      ]),
      
      // تعداد نقد و بررسی‌ها
      Review.countDocuments({ user: userId }),
      
      // میانگین امتیاز نقد و بررسی‌ها
      Review.aggregate([
        { $match: { user: mongoose.Types.ObjectId(userId) } },
        { $group: { _id: null, average: { $avg: '$rating' } } }
      ]),
      
      // موجودی کیف پول
      User.findById(userId).select('walletBalance'),
      
      // تعداد محصولات در لیست علاقه‌مندی‌ها
      User.findById(userId).select('wishlist'),
      
      // تعداد آدرس‌ها
      require('../models/Address.model').countDocuments({ user: userId, isActive: true })
    ]);
    
    return {
      orders: {
        total: totalOrders || 0,
        completed: completedOrders || 0,
        pending: totalOrders - completedOrders
      },
      spending: {
        total: totalSpent[0]?.total || 0,
        averagePerOrder: completedOrders > 0 ? (totalSpent[0]?.total || 0) / completedOrders : 0
      },
      reviews: {
        total: totalReviews || 0,
        averageRating: averageRating[0]?.average ? averageRating[0].average.toFixed(1) : 0
      },
      wallet: {
        balance: walletBalance?.walletBalance || 0,
        formattedBalance: new Intl.NumberFormat('fa-IR').format(walletBalance?.walletBalance || 0) + ' تومان'
      },
      wishlist: {
        count: wishlistCount?.wishlist?.length || 0
      },
      addresses: {
        count: addressesCount || 0
      },
      membership: {
        duration: calculateMembershipDuration(userId),
        level: calculateUserLevel(completedOrders, totalSpent[0]?.total || 0)
      }
    };
  } catch (error) {
    logger.error(`خطا در دریافت آمار کاربر ${userId}:`, error);
    throw new Error('خطا در دریافت آمار');
  }
};

/**
 * فعال/غیرفعال کردن حساب کاربری
 * @param {string} userId - شناسه کاربر
 * @returns {Promise<Object>} کاربر با وضعیت جدید
 */
const toggleAccountActive = async (userId) => {
  try {
    const user = await User.findById(userId);
    
    if (!user) {
      throw new Error('کاربر پیدا نشد');
    }
    
    user.isActive = !user.isActive;
    await user.save();
    
    logger.info(`حساب کاربری ${userId} ${user.isActive ? 'فعال' : 'غیرفعال'} شد`);
    
    return user;
  } catch (error) {
    logger.error(`خطا در تغییر وضعیت حساب کاربری ${userId}:`, error);
    throw new Error('خطا در تغییر وضعیت حساب کاربری');
  }
};

/**
 * اعتبارسنجی کد ملی
 * @param {string} nationalCode - کد ملی
 * @returns {boolean} معتبر بودن
 */
const validateNationalCode = (nationalCode) => {
  if (!/^\d{10}$/.test(nationalCode)) return false;
  
  const check = parseInt(nationalCode[9]);
  let sum = 0;
  
  for (let i = 0; i < 9; i++) {
    sum += parseInt(nationalCode[i]) * (10 - i);
  }
  
  const remainder = sum % 11;
  const isValid = (remainder < 2 && check === remainder) || (remainder >= 2 && check === 11 - remainder);
  
  return isValid;
};

/**
 * محاسبه مدت عضویت
 * @param {string} userId - شناسه کاربر
 * @returns {Promise<string>} مدت عضویت
 */
const calculateMembershipDuration = async (userId) => {
  try {
    const user = await User.findById(userId).select('createdAt');
    
    if (!user) return 'نامشخص';
    
    const now = new Date();
    const createdAt = new Date(user.createdAt);
    const diffTime = Math.abs(now - createdAt);
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    
    if (diffDays < 30) {
      return `${diffDays} روز`;
    } else if (diffDays < 365) {
      const months = Math.floor(diffDays / 30);
      return `${months} ماه`;
    } else {
      const years = Math.floor(diffDays / 365);
      const remainingMonths = Math.floor((diffDays % 365) / 30);
      return `${years} سال و ${remainingMonths} ماه`;
    }
  } catch (error) {
    return 'نامشخص';
  }
};

/**
 * محاسبه سطح کاربر
 * @param {number} completedOrders - تعداد سفارش‌های تکمیل شده
 * @param {number} totalSpent - مجموع مبلغ خریدها
 * @returns {string} سطح کاربر
 */
const calculateUserLevel = (completedOrders, totalSpent) => {
  if (totalSpent > 5000000 || completedOrders > 20) {
    return 'الماسی';
  } else if (totalSpent > 2000000 || completedOrders > 10) {
    return 'طلایی';
  } else if (totalSpent > 500000 || completedOrders > 5) {
    return 'نقره‌ای';
  } else if (completedOrders > 0) {
    return 'برنزی';
  } else {
    return 'جدید';
  }
};

/**
 * مخفی کردن شماره تلفن
 * @param {string} phone - شماره تلفن
 * @returns {string} شماره تلفن مخفی شده
 */
const maskPhoneNumber = (phone) => {
  if (!phone || phone.length !== 11) return phone;
  return `${phone.substring(0, 4)}***${phone.substring(7)}`;
};

/**
 * مخفی کردن ایمیل
 * @param {string} email - آدرس ایمیل
 * @returns {string} ایمیل مخفی شده
 */
const maskEmail = (email) => {
  if (!email) return email;
  const [localPart, domain] = email.split('@');
  if (localPart.length <= 2) return email;
  
  const maskedLocal = localPart.substring(0, 2) + '*'.repeat(localPart.length - 2);
  return `${maskedLocal}@${domain}`;
};

/**
 * مخفی کردن کد ملی
 * @param {string} nationalCode - کد ملی
 * @returns {string} کد ملی مخفی شده
 */
const maskNationalCode = (nationalCode) => {
  if (!nationalCode || nationalCode.length !== 10) return nationalCode;
  return `${nationalCode.substring(0, 3)}***${nationalCode.substring(6)}`;
};

module.exports = {
  getUserProfile,
  updateUserProfile,
  updateProfileImage,
  removeProfileImage,
  changePassword,
  updateNotificationSettings,
  getUserStats,
  toggleAccountActive,
  validateNationalCode,
  calculateMembershipDuration,
  calculateUserLevel,
  maskPhoneNumber,
  maskEmail,
  maskNationalCode
};