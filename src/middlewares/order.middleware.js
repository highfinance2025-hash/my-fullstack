/**
 * @file میدلورهای سفارشات HTLand
 * @description اعتبارسنجی و بررسی‌های سفارشات
 */

const { body, param, validationResult } = require('express-validator');
const Cart = require('../models/Cart.model');
const Product = require('../models/Product.model');
const Order = require('../models/Order.model');
const AppError = require('../utils/AppError');
const logger = require('../utils/logger');

/**
 * اعتبارسنجی ورودی سفارش
 */
exports.validateOrderInput = [
  // اعتبارسنجی shippingAddressId
  body('shippingAddressId')
    .optional()
    .isMongoId()
    .withMessage('شناسه آدرس معتبر نیست'),
  
  // اعتبارسنجی paymentMethod
  body('paymentMethod')
    .notEmpty()
    .withMessage('روش پرداخت الزامی است')
    .isIn(['wallet', 'zarinpal', 'bank_transfer', 'cash_on_delivery'])
    .withMessage('روش پرداخت معتبر نیست'),
  
  // اعتبارسنجی useWalletBalance
  body('useWalletBalance')
    .optional()
    .isBoolean()
    .withMessage('مقدار useWalletBalance باید true یا false باشد')
    .toBoolean(),
  
  // اعتبارسنجی notes
  body('notes')
    .optional()
    .isLength({ max: 500 })
    .withMessage('یادداشت نمی‌تواند بیشتر از ۵۰۰ کاراکتر باشد')
    .trim(),
  
  // اعتبارسنجی orderId برای لغو
  param('id')
    .optional()
    .isMongoId()
    .withMessage('شناسه سفارش معتبر نیست'),
  
  // اعتبارسنجی reason برای لغو
  body('reason')
    .optional()
    .isLength({ max: 200 })
    .withMessage('دلیل لغو نمی‌تواند بیشتر از ۲۰۰ کاراکتر باشد')
    .trim(),
  
  // اعتبارسنجی status برای به‌روزرسانی
  body('status')
    .optional()
    .isIn(['paid', 'processing', 'shipped', 'delivered', 'cancelled', 'refunded'])
    .withMessage('وضعیت سفارش معتبر نیست'),
  
  // اعتبارسنجی trackingCode
  body('trackingCode')
    .optional()
    .isLength({ min: 5, max: 50 })
    .withMessage('کد رهگیری باید بین ۵ تا ۵۰ کاراکتر باشد')
    .matches(/^[A-Z0-9]+$/)
    .withMessage('کد رهگیری فقط می‌تواند شامل حروف بزرگ انگلیسی و اعداد باشد'),
  
  // اعتبارسنجی shippingProvider
  body('shippingProvider')
    .optional()
    .isIn(['post', 'tipax', 'snap', 'custom', 'pickup'])
    .withMessage('شرکت ارسال‌کننده معتبر نیست'),
  
  // اعتبارسنجی trackingUrl
  body('trackingUrl')
    .optional()
    .isURL()
    .withMessage('لینک رهگیری معتبر نیست'),
  
  // بررسی خطاهای اعتبارسنجی
  (req, res, next) => {
    const errors = validationResult(req);
    
    if (!errors.isEmpty()) {
      const errorMessages = errors.array().map(err => `${err.param}: ${err.msg}`);
      logger.warn('خطای اعتبارسنجی سفارش', {
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
 * بررسی موجودی محصولات قبل از سفارش
 */
exports.checkStockAvailability = async (req, res, next) => {
  try {
    const userId = req.user._id;
    
    // یافتن سبد خرید کاربر
    const cart = await Cart.findOne({ user: userId, status: 'active' })
      .populate('items.productId', 'stock inStock active');
    
    if (!cart || cart.items.length === 0) {
      return next(new AppError('سبد خرید شما خالی است', 400));
    }
    
    // بررسی موجودی هر محصول
    const unavailableItems = [];
    
    for (const item of cart.items) {
      const product = item.productId;
      
      if (!product) {
        unavailableItems.push({
          productId: item.productId?._id || item.productId,
          reason: 'محصول حذف شده است',
          itemName: item.productName
        });
        continue;
      }
      
      if (!product.active) {
        unavailableItems.push({
          productId: product._id,
          reason: 'محصول غیرفعال شده است',
          itemName: product.name
        });
        continue;
      }
      
      if (!product.inStock) {
        unavailableItems.push({
          productId: product._id,
          reason: 'محصول موجود نیست',
          itemName: product.name
        });
        continue;
      }
      
      if (product.stock < item.quantity) {
        unavailableItems.push({
          productId: product._id,
          reason: `موجودی کافی نیست (موجودی: ${product.stock}, درخواست: ${item.quantity})`,
          itemName: product.name,
          requested: item.quantity,
          available: product.stock
        });
      }
    }
    
    if (unavailableItems.length > 0) {
      logger.warn('موجودی برخی محصولات کافی نیست', {
        userId,
        unavailableItems
      });
      
      return next(new AppError(
        'موجودی برخی محصولات کافی نیست. لطفاً سبد خرید را بررسی کنید.',
        400,
        { unavailableItems }
      ));
    }
    
    // ذخیره سبد خرید در request برای استفاده در کنترلر
    req.cart = cart;
    next();
    
  } catch (error) {
    next(error);
  }
};

/**
 * بررسی مالکیت سفارش
 */
exports.checkOrderOwnership = async (req, res, next) => {
  try {
    const userId = req.user._id;
    const { id } = req.params;
    const isAdmin = req.user.isAdmin;
    
    // یافتن سفارش
    const order = await Order.findOne({ _id: id, isDeleted: false });
    
    if (!order) {
      return next(new AppError('سفارش یافت نشد', 404));
    }
    
    // بررسی دسترسی
    if (!isAdmin && !order.user.equals(userId)) {
      logger.warn('تلاش برای دسترسی غیرمجاز به سفارش', {
        userId,
        orderId: id,
        orderOwner: order.user.toString()
      });
      return next(new AppError('شما دسترسی به این سفارش را ندارید', 403));
    }
    
    // ذخیره سفارش در request
    req.order = order;
    next();
    
  } catch (error) {
    next(error);
  }
};

/**
 * بررسی امکان لغو سفارش
 */
exports.checkCancellationAvailability = async (req, res, next) => {
  try {
    const order = req.order;
    
    if (!order) {
      return next(new AppError('سفارش یافت نشد', 404));
    }
    
    // بررسی وضعیت سفارش
    if (order.status === 'delivered') {
      return next(new AppError('سفارش تحویل داده شده قابل لغو نیست', 400));
    }
    
    if (order.status === 'cancelled') {
      return next(new AppError('سفارش قبلاً لغو شده است', 400));
    }
    
    // بررسی زمان (حداکثر ۱ ساعت پس از سفارش برای لغو آنلاین)
    if (order.status === 'pending' || order.status === 'paid') {
      const orderTime = new Date(order.timeline.orderedAt);
      const now = new Date();
      const hoursDiff = (now - orderTime) / (1000 * 60 * 60);
      
      if (hoursDiff > 1 && !req.user.isAdmin) {
        return next(new AppError(
          'زمان لغو آنلاین سپری شده است. لطفاً با پشتیبانی تماس بگیرید.',
          400
        ));
      }
    }
    
    next();
    
  } catch (error) {
    next(error);
  }
};

/**
 * بررسی امکان به‌روزرسانی وضعیت
 */
exports.checkStatusUpdatePermission = async (req, res, next) => {
  try {
    if (!req.user.isAdmin) {
      return next(new AppError('فقط ادمین می‌تواند وضعیت سفارش را تغییر دهد', 403));
    }
    
    const order = req.order;
    const { status } = req.body;
    
    if (!order) {
      return next(new AppError('سفارش یافت نشد', 404));
    }
    
    // بررسی انتقال وضعیت مجاز
    const validTransitions = {
      'pending': ['paid', 'cancelled'],
      'paid': ['processing', 'cancelled', 'refunded'],
      'processing': ['shipped', 'cancelled'],
      'shipped': ['delivered', 'cancelled'],
      'delivered': [],
      'cancelled': [],
      'refunded': []
    };
    
    if (!validTransitions[order.status]?.includes(status)) {
      return next(new AppError(
        `تغییر وضعیت از ${order.statusFa} به ${status} مجاز نیست`,
        400
      ));
    }
    
    next();
    
  } catch (error) {
    next(error);
  }
};

/**
 * بررسی پرداخت موفق سفارش
 */
exports.checkPaymentStatus = async (req, res, next) => {
  try {
    const order = req.order;
    
    if (!order) {
      return next(new AppError('سفارش یافت نشد', 404));
    }
    
    // برای برخی عملیات، نیاز به پرداخت موفق است
    const allowedStatuses = ['paid', 'processing', 'shipped', 'delivered'];
    
    if (!allowedStatuses.includes(order.status)) {
      return next(new AppError(
        'این عملیات فقط برای سفارشات پرداخت شده مجاز است',
        400
      ));
    }
    
    next();
    
  } catch (error) {
    next(error);
  }
};

/**
 * میدلور لاگینگ درخواست‌های سفارش
 */
exports.orderRequestLogger = (req, res, next) => {
  const startTime = Date.now();
  
  // لاگ درخواست ورودی
  logger.info('درخواست سفارش', {
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
    
    logger.info('پاسخ سفارش', {
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
 * میدلور اعتبارسنجی آدرس ارسال
 */
exports.validateShippingAddress = async (req, res, next) => {
  try {
    const { shippingAddressId } = req.body;
    
    if (!shippingAddressId) {
      return next(new AppError('آدرس ارسال الزامی است', 400));
    }
    
    // در اینجا باید آدرس از سرویس آدرس‌ها دریافت شود
    // برای نمونه، یک آدرس فرضی
    const address = {
      _id: shippingAddressId,
      recipientName: req.user.name,
      recipientPhone: req.user.phone || '09123456789',
      province: 'مازندران',
      city: 'ساری',
      address: 'بلوار طالقانی، برج پاسارگاد',
      postalCode: '4816612345'
    };
    
    if (!address) {
      return next(new AppError('آدرس ارسال یافت نشد', 404));
    }
    
    // ذخیره آدرس در request
    req.shippingAddress = address;
    next();
    
  } catch (error) {
    next(error);
  }
};

/**
 * میدلور بررسی محدودیت سفارش
 */
exports.checkOrderLimits = async (req, res, next) => {
  try {
    const userId = req.user._id;
    
    // بررسی تعداد سفارشات در حال پردازش
    const processingOrders = await Order.countDocuments({
      user: userId,
      status: { $in: ['pending', 'paid', 'processing'] },
      isDeleted: false
    });
    
    // حداکثر ۵ سفارش همزمان
    if (processingOrders >= 5) {
      return next(new AppError(
        'شما نمی‌توانید بیش از ۵ سفارش همزمان داشته باشید. لطفاً سفارشات قبلی را تکمیل کنید.',
        400
      ));
    }
    
    next();
    
  } catch (error) {
    next(error);
  }
};