/**
 * @file میدلورهای مدیریت آدرس‌های کاربران HTLand
 * @description میدلورهای اعتبارسنجی و کنترل دسترسی برای آدرس‌ها
 * @since 1403/10/01
 */

const Address = require('../models/Address.model');
const { validationResult } = require('express-validator');

/**
 * اعتبارسنجی داده‌های ورودی آدرس
 * @middleware
 */
const validateAddressInput = (req, res, next) => {
  const errors = validationResult(req);
  
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      errors: errors.array().map(err => ({
        field: err.param,
        message: err.msg
      }))
    });
  }
  
  // اعتبارسنجی سفارشی اضافی
  const customErrors = [];
  
  // اعتبارسنجی استان و شهر
  if (req.body.province && req.body.city) {
    const validProvinces = [
      'مازندران', 'گیلان', 'گلستان', 'آذربایجان شرقی', 'آذربایجان غربی',
      'تهران', 'البرز', 'قم', 'مرکزی', 'همدان', 'زنجان', 'اردبیل',
      'قزوین', 'کردستان', 'کرمانشاه', 'لرستان', 'ایلام', 'خوزستان',
      'فارس', 'بوشهر', 'هرمزگان', 'کرمان', 'سیستان و بلوچستان',
      'خراسان رضوی', 'خراسان شمالی', 'خراسان جنوبی', 'یزد', 'اصفهان',
      'سمنان', 'چهارمحال و بختیاری', 'کهگیلویه و بویراحمد'
    ];
    
    if (!validProvinces.includes(req.body.province)) {
      customErrors.push({
        field: 'province',
        message: 'استان معتبر نیست'
      });
    }
    
    // اعتبارسنجی طول شهر
    if (req.body.city.length < 2 || req.body.city.length > 50) {
      customErrors.push({
        field: 'city',
        message: 'نام شهر باید بین ۲ تا ۵۰ کاراکتر باشد'
      });
    }
  }
  
  // اعتبارسنجی کد پستی
  if (req.body.postalCode) {
    const postalCodeRegex = /^\d{10}$/;
    if (!postalCodeRegex.test(req.body.postalCode)) {
      customErrors.push({
        field: 'postalCode',
        message: 'کد پستی باید ۱۰ رقم باشد'
      });
    }
  }
  
  // اعتبارسنجی شماره تلفن
  if (req.body.phone) {
    const phoneRegex = /^09[0-9]{9}$/;
    if (!phoneRegex.test(req.body.phone)) {
      customErrors.push({
        field: 'phone',
        message: 'شماره تلفن معتبر نیست (فرمت: 09123456789)'
      });
    }
  }
  
  // اعتبارسنجی نام کامل
  if (req.body.fullName) {
    const persianRegex = /^[\u0600-\u06FF\s]+$/;
    if (!persianRegex.test(req.body.fullName)) {
      customErrors.push({
        field: 'fullName',
        message: 'نام کامل باید فارسی باشد'
      });
    }
    
    if (req.body.fullName.length < 3 || req.body.fullName.length > 100) {
      customErrors.push({
        field: 'fullName',
        message: 'نام کامل باید بین ۳ تا ۱۰۰ کاراکتر باشد'
      });
    }
  }
  
  // اعتبارسنجی برچسب آدرس
  if (req.body.label && !['خانه', 'کار', 'فامیل', 'دیگر'].includes(req.body.label)) {
    customErrors.push({
      field: 'label',
      message: 'برچسب آدرس معتبر نیست'
    });
  }
  
  if (customErrors.length > 0) {
    return res.status(400).json({
      success: false,
      errors: customErrors
    });
  }
  
  next();
};

/**
 * بررسی مالکیت آدرس (آیا آدرس متعلق به کاربر است؟)
 * @middleware
 */
const checkAddressOwnership = async (req, res, next) => {
  try {
    const addressId = req.params.id;
    const userId = req.user._id;
    
    if (!addressId) {
      return res.status(400).json({
        success: false,
        error: 'شناسه آدرس الزامی است'
      });
    }
    
    const address = await Address.findOne({
      _id: addressId,
      user: userId,
      isActive: true
    });
    
    if (!address) {
      return res.status(404).json({
        success: false,
        error: 'آدرس پیدا نشد یا دسترسی غیرمجاز است'
      });
    }
    
    // ذخیره آدرس در request برای استفاده در کنترلر
    req.address = address;
    next();
  } catch (error) {
    console.error('خطا در بررسی مالکیت آدرس:', error);
    res.status(500).json({
      success: false,
      error: 'خطای سرور در بررسی مالکیت'
    });
  }
};

/**
 * بررسی تعداد آدرس‌های کاربر (حداکثر ۳ آدرس)
 * @middleware
 */
const checkAddressLimit = async (req, res, next) => {
  try {
    const userId = req.user._id;
    
    const addressCount = await Address.countDocuments({
      user: userId,
      isActive: true
    });
    
    if (addressCount >= 3) {
      return res.status(409).json({
        success: false,
        error: 'هر کاربر می‌تواند حداکثر ۳ آدرس فعال داشته باشد'
      });
    }
    
    next();
  } catch (error) {
    console.error('خطا در بررسی تعداد آدرس‌ها:', error);
    res.status(500).json({
      success: false,
      error: 'خطای سرور در بررسی محدودیت آدرس'
    });
  }
};

/**
 * بررسی وجود آدرس پیش‌فرض برای حذف
 * @middleware
 */
const checkDefaultAddressForDeletion = async (req, res, next) => {
  try {
    const addressId = req.params.id;
    
    const address = await Address.findById(addressId);
    
    if (!address) {
      return res.status(404).json({
        success: false,
        error: 'آدرس پیدا نشد'
      });
    }
    
    if (address.isDefault) {
      return res.status(400).json({
        success: false,
        error: 'نمی‌توان آدرس پیش‌فرض را حذف کرد. ابتدا آدرس دیگری را پیش‌فرض کنید'
      });
    }
    
    next();
  } catch (error) {
    console.error('خطا در بررسی آدرس پیش‌فرض:', error);
    res.status(500).json({
      success: false,
      error: 'خطای سرور در بررسی آدرس پیش‌فرض'
    });
  }
};

/**
 * اعتبارسنجی آدرس برای سفارش
 * @middleware
 */
const validateAddressForOrder = async (req, res, next) => {
  try {
    const addressId = req.params.id || req.body.addressId;
    const userId = req.user._id;
    
    if (!addressId) {
      return res.status(400).json({
        success: false,
        error: 'شناسه آدرس الزامی است'
      });
    }
    
    const address = await Address.findOne({
      _id: addressId,
      user: userId,
      isActive: true
    });
    
    if (!address) {
      return res.status(404).json({
        success: false,
        error: 'آدرس معتبر پیدا نشد'
      });
    }
    
    // بررسی کامل بودن اطلاعات آدرس
    const requiredFields = ['fullName', 'phone', 'province', 'city', 'address', 'postalCode'];
    const isComplete = requiredFields.every(field => 
      address[field] && address[field].toString().trim().length > 0
    );
    
    if (!isComplete) {
      return res.status(400).json({
        success: false,
        error: 'آدرس انتخاب شده کامل نیست. لطفاً اطلاعات آدرس را تکمیل کنید'
      });
    }
    
    // ذخیره آدرس در request
    req.address = address;
    next();
  } catch (error) {
    console.error('خطا در اعتبارسنجی آدرس برای سفارش:', error);
    res.status(500).json({
      success: false,
      error: 'خطای سرور در اعتبارسنجی آدرس'
    });
  }
};

/**
 * میدلور برای بررسی تکراری نبودن آدرس
 * @middleware
 */
const checkDuplicateAddress = async (req, res, next) => {
  try {
    const userId = req.user._id;
    const { province, city, address, postalCode } = req.body;
    
    if (!province || !city || !address || !postalCode) {
      return next(); // اگر اطلاعات کامل نیست، بررسی نکن
    }
    
    const existingAddress = await Address.findOne({
      user: userId,
      province,
      city,
      address,
      postalCode,
      isActive: true
    });
    
    if (existingAddress) {
      return res.status(409).json({
        success: false,
        error: 'این آدرس قبلاً ثبت شده است'
      });
    }
    
    next();
  } catch (error) {
    console.error('خطا در بررسی تکراری بودن آدرس:', error);
    res.status(500).json({
      success: false,
      error: 'خطای سرور در بررسی آدرس تکراری'
    });
  }
};

/**
 * میدلور برای تنظیم خودکار استان‌های شمالی
 * @middleware
 */
const setNorthernProvincePriority = (req, res, next) => {
  if (req.body.province) {
    const northernProvinces = ['مازندران', 'گیلان', 'گلستان'];
    
    if (northernProvinces.includes(req.body.province)) {
      // اگر آدرس در شمال ایران است، می‌توان اطلاعات اضافی اضافه کرد
      req.body.isNorthern = true;
      
      // برای استان‌های شمالی، ارسال سریع‌تر ممکن است
      if (!req.body.shippingNotes) {
        req.body.shippingNotes = 'ارسال سریع (۱-۲ روز کاری) به دلیل موقعیت جغرافیایی';
      }
    }
  }
  
  next();
};

module.exports = {
  validateAddressInput,
  checkAddressOwnership,
  checkAddressLimit,
  checkDefaultAddressForDeletion,
  validateAddressForOrder,
  checkDuplicateAddress,
  setNorthernProvincePriority
};