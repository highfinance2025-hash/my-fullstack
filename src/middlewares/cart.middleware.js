/**
 * @file میدلورهای سبد خرید HTLand
 * @description اعتبارسنجی و بررسی‌های سبد خرید
 */

const { body, param, validationResult } = require('express-validator');
const Product = require('../models/Product.model');
const Cart = require('../models/Cart.model');
const AppError = require('../utils/AppError');
const logger = require('../utils/logger');

/**
 * اعتبارسنجی آیتم سبد خرید
 */
exports.validateCartItem = [
  // اعتبارسنجی productId در body (برای POST)
  body('productId')
    .optional()
    .isMongoId()
    .withMessage('شناسه محصول معتبر نیست')
    .custom(async (value, { req }) => {
      if (value) {
        const product = await Product.findById(value);
        if (!product) {
          throw new Error('محصول یافت نشد');
        }
        if (!product.active) {
          throw new Error('محصول غیرفعال است');
        }
      }
      return true;
    }),
  
  // اعتبارسنجی productId در params (برای PUT/DELETE)
  param('productId')
    .optional()
    .isMongoId()
    .withMessage('شناسه محصول معتبر نیست'),
  
  // اعتبارسنجی quantity
  body('quantity')
    .optional()
    .isInt({ min: 0, max: 99 })
    .withMessage('تعداد باید بین ۰ تا ۹۹ باشد')
    .toInt(),
  
  // اعتبارسنجی couponCode
  body('couponCode')
    .optional()
    .trim()
    .isLength({ min: 3, max: 20 })
    .withMessage('کد کوپن باید بین ۳ تا ۲۰ کاراکتر باشد')
    .matches(/^[A-Z0-9_-]+$/i)
    .withMessage('کد کوپن فقط می‌تواند شامل حروف انگلیسی، اعداد، خط فاصله و زیرخط باشد'),
  
  // اعتبارسنجی shippingFee
  body('shippingFee')
    .optional()
    .isFloat({ min: 0 })
    .withMessage('هزینه ارسال نمی‌تواند منفی باشد')
    .toFloat(),
  
  // بررسی خطاهای اعتبارسنجی
  (req, res, next) => {
    const errors = validationResult(req);
    
    if (!errors.isEmpty()) {
      const errorMessages = errors.array().map(err => `${err.param}: ${err.msg}`);
      logger.warn('خطای اعتبارسنجی سبد خرید', {
        errors: errorMessages,
        userId: req.user?._id,
        path: req.path
      });
      return next(new AppError(errorMessages.join(' | '), 400));
    }
    
    next();
  }
];

/**
 * بررسی موجودی محصول
 */
exports.checkProductStock = async (req, res, next) => {
  try {
    const productId = req.body.productId || req.params.productId;
    const quantity = req.body.quantity || 1;
    
    if (!productId) {
      return next();
    }
    
    // یافتن محصول
    const product = await Product.findById(productId);
    
    if (!product) {
      return next(new AppError('محصول یافت نشد', 404));
    }
    
    // بررسی موجودی
    if (!product.inStock) {
      return next(new AppError('محصول موجود نیست', 400));
    }
    
    if (product.stock < quantity) {
      return next(new AppError(
        `موجودی محصول "${product.name}" کافی نیست. موجودی: ${product.stock}`,
        400
      ));
    }
    
    // ذخیره محصول در request برای استفاده در کنترلر
    req.product = product;
    next();
    
  } catch (error) {
    next(error);
  }
};

/**
 * بررسی مالکیت سبد خرید
 */
exports.checkCartOwnership = async (req, res, next) => {
  try {
    const userId = req.user._id;
    const { productId } = req.params;
    
    // یافتن سبد خرید کاربر
    const cart = await Cart.findOne({ user: userId, status: 'active' });
    
    if (!cart) {
      return next(new AppError('سبد خرید یافت نشد', 404));
    }
    
    // اگر productId مشخص شده، بررسی وجود آن در سبد
    if (productId) {
      const itemExists = cart.items.some(
        item => item.productId.toString() === productId
      );
      
      if (!itemExists) {
        return next(new AppError('محصول در سبد خرید شما یافت نشد', 404));
      }
    }
    
    // ذخیره سبد خرید در request
    req.cart = cart;
    next();
    
  } catch (error) {
    next(error);
  }
};

/**
 * بررسی عدم خالی بودن سبد خرید
 */
exports.checkCartNotEmpty = async (req, res, next) => {
  try {
    const userId = req.user._id;
    
    const cart = await Cart.findOne({ user: userId, status: 'active' });
    
    if (!cart || cart.items.length === 0) {
      return next(new AppError('سبد خرید شما خالی است', 400));
    }
    
    req.cart = cart;
    next();
    
  } catch (error) {
    next(error);
  }
};

/**
 * بررسی محدودیت تعداد آیتم‌ها در سبد
 */
exports.checkCartItemLimit = async (req, res, next) => {
  try {
    const userId = req.user._id;
    
    const cart = await Cart.findOne({ user: userId, status: 'active' });
    
    if (cart && cart.items.length >= 20) {
      return next(new AppError(
        'حداکثر ۲۰ محصول می‌توانید به سبد خرید اضافه کنید. لطفاً برخی محصولات را حذف کنید.',
        400
      ));
    }
    
    next();
    
  } catch (error) {
    next(error);
  }
};

/**
 * میدلور بررسی تغییرات قیمت محصولات در سبد
 */
exports.checkPriceChanges = async (req, res, next) => {
  try {
    const userId = req.user._id;
    
    const cart = await Cart.findOne({ user: userId, status: 'active' })
      .populate('items.productId', 'price discountPrice');
    
    if (!cart || cart.items.length === 0) {
      return next();
    }
    
    const priceChanges = [];
    
    for (const item of cart.items) {
      if (item.productId) {
        const currentFinalPrice = item.productId.discountPrice || item.productId.price;
        
        if (currentFinalPrice !== item.finalPriceAtTime) {
          priceChanges.push({
            productId: item.productId._id,
            productName: item.productName,
            oldPrice: item.finalPriceAtTime,
            newPrice: currentFinalPrice,
            difference: currentFinalPrice - item.finalPriceAtTime
          });
        }
      }
    }
    
    if (priceChanges.length > 0) {
      // ذخیره تغییرات قیمت در request
      req.priceChanges = priceChanges;
      
      logger.info('تغییرات قیمت در سبد خرید شناسایی شد', {
        userId,
        cartId: cart._id,
        priceChanges: priceChanges.length
      });
    }
    
    next();
    
  } catch (error) {
    next(error);
  }
};

/**
 * میدلور لاگینگ درخواست‌های سبد خرید
 */
exports.cartRequestLogger = (req, res, next) => {
  const startTime = Date.now();
  
  // لاگ درخواست ورودی
  logger.info('درخواست سبد خرید', {
    method: req.method,
    path: req.path,
    userId: req.user?._id,
    userIp: req.ip,
    userAgent: req.get('User-Agent')?.substr(0, 100)
  });
  
  // ذخیره تابع اصلی response.send
  const originalSend = res.send;
  
  // بازنویسی تابع send برای لاگ پاسخ
  res.send = function(data) {
    const duration = Date.now() - startTime;
    
    logger.info('پاسخ سبد خرید', {
      method: req.method,
      path: req.path,
      userId: req.user?._id,
      statusCode: res.statusCode,
      duration: `${duration}ms`,
      responseSize: data?.length || 0
    });
    
    // فراخوانی تابع اصلی
    return originalSend.call(this, data);
  };
  
  next();
};

/**
 * میدلور بررسی دسترسی به سبد خرید بر اساس دستگاه
 */
exports.checkDeviceAccess = async (req, res, next) => {
  try {
    const userId = req.user._id;
    const userIp = req.ip;
    const userAgent = req.get('User-Agent');
    
    // یافتن سبد خرید
    const cart = await Cart.findOne({ user: userId, status: 'active' });
    
    if (!cart) {
      return next();
    }
    
    // اگر دستگاه تغییر کرده باشد، لاگ کنیم
    if (cart.userIp !== userIp || cart.userAgent !== userAgent) {
      logger.info('دستگاه کاربر برای دسترسی به سبد خرید تغییر کرده', {
        userId,
        cartId: cart._id,
        oldIp: cart.userIp,
        newIp: userIp,
        oldAgent: cart.userAgent?.substr(0, 50),
        newAgent: userAgent?.substr(0, 50)
      });
      
      // به‌روزرسانی اطلاعات دستگاه
      cart.userIp = userIp;
      cart.userAgent = userAgent;
      await cart.save();
    }
    
    next();
    
  } catch (error) {
    next(error);
  }
};