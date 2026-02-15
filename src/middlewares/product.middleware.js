/**
 * @file میدلورهای محصولات HTLand
 * @description اعتبارسنجی، آپلود تصویر و کنترل دسترسی
 */

const multer = require('multer');
const { body, validationResult } = require('express-validator');
const AppError = require('../utils/AppError');
const logger = require('../utils/logger');

/**
 * پیکربندی Multer برای آپلود موقت فایل‌ها
 */
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/temp/');
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, `${file.fieldname}-${uniqueSuffix}-${file.originalname}`);
  }
});

/**
 * فیلتر فایل‌ها: فقط تصاویر مجاز
 */
const fileFilter = (req, file, cb) => {
  const allowedMimeTypes = [
    'image/jpeg',
    'image/jpg',
    'image/png',
    'image/webp',
    'image/gif'
  ];
  
  if (allowedMimeTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new AppError('فقط فایل‌های تصویری (JPEG, PNG, WebP, GIF) مجاز هستند', 400), false);
  }
};

/**
 * ایجاد نمونه Multer
 */
const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB
    files: 11 // 1 تصویر اصلی + 10 تصویر گالری
  }
});

/**
 * میدلور آپلود تصاویر محصول
 */
exports.uploadProductImages = upload.fields([
  { name: 'image', maxCount: 1 },
  { name: 'gallery', maxCount: 10 }
]);

/**
 * اعتبارسنجی داده‌های محصول
 */
exports.validateProduct = [
  // اعتبارسنجی نام
  body('name')
    .trim()
    .notEmpty()
    .withMessage('نام محصول الزامی است')
    .isLength({ min: 3, max: 200 })
    .withMessage('نام محصول باید بین ۳ تا ۲۰۰ کاراکتر باشد'),
  
  // اعتبارسنجی توضیحات
  body('description')
    .trim()
    .notEmpty()
    .withMessage('توضیحات محصول الزامی است')
    .isLength({ min: 10, max: 2000 })
    .withMessage('توضیحات محصول باید بین ۱۰ تا ۲۰۰۰ کاراکتر باشد'),
  
  // اعتبارسنجی توضیح کوتاه
  body('shortDescription')
    .optional()
    .trim()
    .isLength({ max: 200 })
    .withMessage('توضیح کوتاه نمی‌تواند بیشتر از ۲۰۰ کاراکتر باشد'),
  
  // اعتبارسنجی قیمت
  body('price')
    .notEmpty()
    .withMessage('قیمت محصول الزامی است')
    .isFloat({ min: 0 })
    .withMessage('قیمت باید عدد مثبت باشد')
    .custom(value => {
      if (value < 1000) {
        throw new Error('قیمت نمی‌تواند کمتر از ۱۰۰۰ تومان باشد');
      }
      return true;
    }),
  
  // اعتبارسنجی قیمت تخفیف
  body('discountPrice')
    .optional()
    .isFloat({ min: 0 })
    .withMessage('قیمت تخفیف باید عدد مثبت باشد')
    .custom((value, { req }) => {
      if (value && parseFloat(value) >= parseFloat(req.body.price)) {
        throw new Error('قیمت تخفیف باید کمتر از قیمت اصلی باشد');
      }
      return true;
    }),
  
  // اعتبارسنجی دسته‌بندی انگلیسی
  body('category')
    .notEmpty()
    .withMessage('دسته‌بندی انگلیسی الزامی است')
    .isIn(['rice', 'caviar', 'fish', 'honey', 'chicken', 'souvenir'])
    .withMessage('دسته‌بندی انگلیسی معتبر نیست'),
  
  // اعتبارسنجی دسته‌بندی فارسی
  body('categoryFa')
    .notEmpty()
    .withMessage('دسته‌بندی فارسی الزامی است')
    .isIn(['برنج شمال', 'خاویار ایرانی', 'ماهی تازه', 'عسل طبیعی', 'مرغ محلی', 'سوغات شمال'])
    .withMessage('دسته‌بندی فارسی معتبر نیست'),
  
  // اعتبارسنجی موجودی
  body('stock')
    .optional()
    .isInt({ min: 0 })
    .withMessage('موجودی باید عدد صحیح و غیرمنفی باشد'),
  
  // اعتبارسنجی ویژه بودن
  body('featured')
    .optional()
    .isBoolean()
    .withMessage('مقدار featured باید true یا false باشد'),
  
  // اعتبارسنجی تگ‌ها
  body('tags')
    .optional()
    .custom(value => {
      if (typeof value === 'string') {
        try {
          const tags = JSON.parse(value);
          return Array.isArray(tags) && tags.every(tag => typeof tag === 'string');
        } catch {
          return false;
        }
      }
      return Array.isArray(value) && value.every(tag => typeof tag === 'string');
    })
    .withMessage('تگ‌ها باید آرایه‌ای از رشته‌ها باشند'),
  
  // اعتبارسنجی وزن
  body('specifications.weight.value')
    .optional()
    .isFloat({ min: 0 })
    .withMessage('وزن باید عدد مثبت باشد'),
  
  body('specifications.weight.unit')
    .optional()
    .isIn(['گرم', 'کیلوگرم', 'لیتر', 'عدد', 'بسته'])
    .withMessage('واحد وزن معتبر نیست'),
  
  // اعتبارسنجی تاریخ‌ها
  body('productionDate')
    .optional()
    .isISO8601()
    .withMessage('تاریخ تولید معتبر نیست'),
  
  body('expiryDate')
    .optional()
    .isISO8601()
    .withMessage('تاریخ انقضا معتبر نیست')
    .custom((value, { req }) => {
      if (req.body.productionDate && new Date(value) <= new Date(req.body.productionDate)) {
        throw new Error('تاریخ انقضا باید بعد از تاریخ تولید باشد');
      }
      return true;
    }),
  
  // بررسی خطاهای اعتبارسنجی
  (req, res, next) => {
    const errors = validationResult(req);
    
    if (!errors.isEmpty()) {
      const errorMessages = errors.array().map(err => err.msg);
      logger.warn('خطای اعتبارسنجی محصول', {
        errors: errorMessages,
        user: req.user?._id
      });
      return next(new AppError(errorMessages.join(' | '), 400));
    }
    
    // تبدیل تگ‌ها از JSON string به آرایه
    if (req.body.tags && typeof req.body.tags === 'string') {
      try {
        req.body.tags = JSON.parse(req.body.tags);
      } catch {
        req.body.tags = req.body.tags.split(',').map(tag => tag.trim());
      }
    }
    
    next();
  }
];

/**
 * میدلور بررسی وجود محصول
 */
exports.checkProductExists = async (req, res, next) => {
  try {
    const Product = require('../models/Product.model');
    const product = await Product.findOne({
      $or: [
        { _id: req.params.id },
        { slug: req.params.id }
      ]
    });
    
    if (!product) {
      return next(new AppError('محصول یافت نشد', 404));
    }
    
    req.product = product;
    next();
  } catch (error) {
    next(error);
  }
};

/**
 * میدلور بررسی دسترسی ادمین
 */
exports.isAdmin = (req, res, next) => {
  if (!req.user || !req.user.isAdmin) {
    logger.warn('تلاش برای دسترسی غیرمجاز به محصولات', {
      userId: req.user?._id,
      route: req.originalUrl
    });
    return next(new AppError('شما دسترسی به این عملیات را ندارید', 403));
  }
  next();
};

/**
 * میدلور بررسی موجودی محصول
 */
exports.checkStock = async (req, res, next) => {
  try {
    const { productId, quantity = 1 } = req.body;
    
    if (!productId) {
      return next(new AppError('شناسه محصول الزامی است', 400));
    }
    
    if (!quantity || quantity <= 0) {
      return next(new AppError('تعداد معتبر نیست', 400));
    }
    
    const Product = require('../models/Product.model');
    const product = await Product.findOne({
      _id: productId,
      active: true
    });
    
    if (!product) {
      return next(new AppError('محصول یافت نشد', 404));
    }
    
    if (!product.inStock || product.stock < quantity) {
      return next(new AppError(
        `موجودی محصول "${product.name}" کافی نیست. موجودی: ${product.stock}`,
        400
      ));
    }
    
    req.product = product;
    next();
  } catch (error) {
    next(error);
  }
};

/**
 * میدلور بررسی دسته‌بندی معتبر
 */
exports.validateCategory = (req, res, next) => {
  const validCategories = {
    rice: 'برنج شمال',
    caviar: 'خاویار ایرانی',
    fish: 'ماهی تازه',
    honey: 'عسل طبیعی',
    chicken: 'مرغ محلی',
    souvenir: 'سوغات شمال'
  };
  
  if (req.body.category && !validCategories[req.body.category]) {
    return next(new AppError('دسته‌بندی معتبر نیست', 400));
  }
  
  if (req.body.categoryFa && !Object.values(validCategories).includes(req.body.categoryFa)) {
    return next(new AppError('دسته‌بندی فارسی معتبر نیست', 400));
  }
  
  // تطبیق دسته‌بندی انگلیسی و فارسی
  if (req.body.category && req.body.categoryFa) {
    if (validCategories[req.body.category] !== req.body.categoryFa) {
      return next(new AppError('دسته‌بندی انگلیسی و فارسی مطابقت ندارند', 400));
    }
  }
  
  next();
};

/**
 * میدلور پاکسازی فایل‌های موقت در صورت خطا
 */
exports.cleanupTempFiles = (req, res, next) => {
  // در صورت خطا، فایل‌های آپلود شده موقت را پاک می‌کند
  res.on('finish', () => {
    if (req.files) {
      const fs = require('fs');
      const path = require('path');
      
      Object.values(req.files).forEach(files => {
        files.forEach(file => {
          fs.unlink(file.path, err => {
            if (err) {
              logger.error(`خطا در حذف فایل موقت: ${file.path}`, { error: err.message });
            }
          });
        });
      });
    }
  });
  
  next();
};