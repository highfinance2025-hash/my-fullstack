/**
 * @file کنترلر سبد خرید HTLand
 * @description مدیریت کامل عملیات سبد خرید کاربران
 */

const Cart = require('../models/Cart.model');
const Product = require('../models/Product.model');
const cartService = require('../services/cartService');
const asyncHandler = require('../utils/asyncHandler');
const AppError = require('../utils/AppError');
const logger = require('../utils/logger');

/**
 * کنترلر سبد خرید
 */
const cartController = {
  
  /**
   * دریافت سبد خرید کاربر
   * @route GET /api/v1/cart
   * @access خصوصی (کاربر لاگین‌شده)
   */
  getCart: asyncHandler(async (req, res, next) => {
    const userId = req.user._id;
    
    // دریافت سبد خرید
    let cart = await Cart.findOne({ user: userId, status: 'active' })
      .populate({
        path: 'items.productId',
        select: 'name price discountPrice image category categoryFa inStock active stock',
        match: { active: true }
      });
    
    // اگر سبد خرید وجود نداشت، ایجاد شود
    if (!cart) {
      cart = await Cart.create({ user: userId });
    }
    
    // فیلتر کردن محصولات غیرفعال
    const validItems = cart.items.filter(item => 
      item.productId && item.productId.active
    );
    
    // اگر محصولات غیرفعال وجود داشت، سبد را به‌روزرسانی کن
    if (validItems.length !== cart.items.length) {
      cart.items = validItems;
      await cart.save();
    }
    
    // دریافت خلاصه سبد خرید
    const cartSummary = cart.getSummary();
    
    logger.info(`سبد خرید کاربر ${userId} دریافت شد`, {
      userId,
      itemsCount: cartSummary.totalItems,
      totalAmount: cartSummary.totalAmount
    });
    
    res.status(200).json({
      success: true,
      message: 'سبد خرید با موفقیت دریافت شد',
      data: {
        ...cartSummary,
        cartId: cart._id,
        updatedAt: cart.updatedAt
      }
    });
  }),
  
  /**
   * افزودن محصول به سبد خرید
   * @route POST /api/v1/cart/items
   * @access خصوصی (کاربر لاگین‌شده)
   */
  addItem: asyncHandler(async (req, res, next) => {
    const userId = req.user._id;
    const { productId, quantity = 1 } = req.body;
    
    // اعتبارسنجی ورودی
    if (!productId) {
      return next(new AppError('شناسه محصول الزامی است', 400));
    }
    
    if (quantity < 1 || quantity > 99) {
      return next(new AppError('تعداد باید بین ۱ تا ۹۹ باشد', 400));
    }
    
    // بررسی وجود محصول
    const product = await Product.findOne({
      _id: productId,
      active: true
    });
    
    if (!product) {
      return next(new AppError('محصول یافت نشد', 404));
    }
    
    // بررسی موجودی
    if (!product.inStock || product.stock < quantity) {
      return next(new AppError('موجودی محصول کافی نیست', 400));
    }
    
    // یافتن یا ایجاد سبد خرید
    let cart = await Cart.findOne({ user: userId, status: 'active' });
    
    if (!cart) {
      cart = await Cart.create({ 
        user: userId,
        userIp: req.ip,
        userAgent: req.get('User-Agent')
      });
    }
    
    // افزودن محصول به سبد
    await cart.addItem(product, quantity);
    
    // دریافت خلاصه به‌روزرسانی شده
    const updatedCart = await Cart.findById(cart._id)
      .populate('items.productId', 'name price discountPrice image category');
    
    const cartSummary = updatedCart.getSummary();
    
    logger.info(`محصول به سبد خرید اضافه شد`, {
      userId,
      productId,
      productName: product.name,
      quantity,
      cartId: cart._id
    });
    
    res.status(200).json({
      success: true,
      message: 'محصول با موفقیت به سبد خرید اضافه شد',
      data: {
        cartId: cart._id,
        addedProduct: {
          productId: product._id,
          name: product.name,
          quantity,
          price: product.discountPrice || product.price,
          total: (product.discountPrice || product.price) * quantity
        },
        cartSummary: cartSummary
      }
    });
  }),
  
  /**
   * به‌روزرسانی تعداد محصول در سبد خرید
   * @route PUT /api/v1/cart/items/{productId}
   * @access خصوصی (کاربر لاگین‌شده)
   */
  updateItemQuantity: asyncHandler(async (req, res, next) => {
    const userId = req.user._id;
    const { productId } = req.params;
    const { quantity } = req.body;
    
    // اعتبارسنجی ورودی
    if (!quantity || quantity < 0 || quantity > 99) {
      return next(new AppError('تعداد باید بین ۰ تا ۹۹ باشد', 400));
    }
    
    // یافتن سبد خرید
    const cart = await Cart.findOne({ user: userId, status: 'active' });
    
    if (!cart) {
      return next(new AppError('سبد خرید یافت نشد', 404));
    }
    
    // بررسی وجود محصول در سبد
    const cartItem = cart.items.find(
      item => item.productId.toString() === productId
    );
    
    if (!cartItem) {
      return next(new AppError('محصول در سبد خرید یافت نشد', 404));
    }
    
    // اگر تعداد صفر باشد، محصول حذف شود
    if (quantity === 0) {
      await cart.removeItem(productId);
      
      logger.info(`محصول از سبد خرید حذف شد (تعداد صفر)`, {
        userId,
        productId,
        cartId: cart._id
      });
      
      return res.status(200).json({
        success: true,
        message: 'محصول از سبد خرید حذف شد',
        data: {
          removed: true,
          cartSummary: cart.getSummary()
        }
      });
    }
    
    // بررسی موجودی محصول
    const product = await Product.findById(productId);
    
    if (!product) {
      return next(new AppError('محصول یافت نشد', 404));
    }
    
    if (!product.inStock || product.stock < quantity) {
      return next(new AppError('موجودی محصول کافی نیست', 400));
    }
    
    // به‌روزرسانی تعداد
    await cart.updateItemQuantity(productId, quantity);
    
    const updatedCart = await Cart.findById(cart._id)
      .populate('items.productId', 'name price discountPrice image');
    
    logger.info(`تعداد محصول در سبد خرید به‌روزرسانی شد`, {
      userId,
      productId,
      oldQuantity: cartItem.quantity,
      newQuantity: quantity,
      cartId: cart._id
    });
    
    res.status(200).json({
      success: true,
      message: 'تعداد محصول با موفقیت به‌روزرسانی شد',
      data: {
        updated: true,
        productId,
        newQuantity: quantity,
        cartSummary: updatedCart.getSummary()
      }
    });
  }),
  
  /**
   * حذف محصول از سبد خرید
   * @route DELETE /api/v1/cart/items/{productId}
   * @access خصوصی (کاربر لاگین‌شده)
   */
  removeItem: asyncHandler(async (req, res, next) => {
    const userId = req.user._id;
    const { productId } = req.params;
    
    // یافتن سبد خرید
    const cart = await Cart.findOne({ user: userId, status: 'active' });
    
    if (!cart) {
      return next(new AppError('سبد خرید یافت نشد', 404));
    }
    
    // بررسی وجود محصول در سبد
    const cartItem = cart.items.find(
      item => item.productId.toString() === productId
    );
    
    if (!cartItem) {
      return next(new AppError('محصول در سبد خرید یافت نشد', 404));
    }
    
    // حذف محصول
    await cart.removeItem(productId);
    
    logger.info(`محصول از سبد خرید حذف شد`, {
      userId,
      productId,
      productName: cartItem.productName,
      cartId: cart._id
    });
    
    res.status(200).json({
      success: true,
      message: 'محصول با موفقیت از سبد خرید حذف شد',
      data: {
        removed: true,
        removedProductId: productId,
        cartSummary: cart.getSummary()
      }
    });
  }),
  
  /**
   * خالی کردن سبد خرید
   * @route DELETE /api/v1/cart
   * @access خصوصی (کاربر لاگین‌شده)
   */
  clearCart: asyncHandler(async (req, res, next) => {
    const userId = req.user._id;
    
    // یافتن سبد خرید
    const cart = await Cart.findOne({ user: userId, status: 'active' });
    
    if (!cart) {
      return next(new AppError('سبد خرید یافت نشد', 404));
    }
    
    // ذخیره اطلاعات برای لاگ
    const itemsCount = cart.items.length;
    
    // خالی کردن سبد
    await cart.clearCart();
    
    logger.info(`سبد خرید خالی شد`, {
      userId,
      cartId: cart._id,
      removedItems: itemsCount
    });
    
    res.status(200).json({
      success: true,
      message: 'سبد خرید با موفقیت خالی شد',
      data: {
        cleared: true,
        cartId: cart._id,
        removedItemsCount: itemsCount
      }
    });
  }),
  
  /**
   * اعمال کوپن تخفیف
   * @route POST /api/v1/cart/coupon
   * @access خصوصی (کاربر لاگین‌شده)
   */
  applyCoupon: asyncHandler(async (req, res, next) => {
    const userId = req.user._id;
    const { couponCode } = req.body;
    
    if (!couponCode) {
      return next(new AppError('کد کوپن الزامی است', 400));
    }
    
    // یافتن سبد خرید
    const cart = await Cart.findOne({ user: userId, status: 'active' });
    
    if (!cart) {
      return next(new AppError('سبد خرید یافت نشد', 404));
    }
    
    if (cart.items.length === 0) {
      return next(new AppError('سبد خرید خالی است', 400));
    }
    
    // در اینجا باید کوپن از دیتابیس بررسی شود
    // برای نمونه، یک کوپن تستی
    const validCoupons = {
      'HTLAND10': 10,
      'HTLAND20': 20,
      'SAVE50': 50
    };
    
    const discountPercentage = validCoupons[couponCode.toUpperCase()];
    
    if (!discountPercentage) {
      return next(new AppError('کد کوپن نامعتبر است', 400));
    }
    
    // اعمال تخفیف
    cart.couponCode = couponCode.toUpperCase();
    cart.couponDiscount = discountPercentage;
    
    await cart.save();
    
    const updatedCart = await Cart.findById(cart._id);
    
    logger.info(`کوپن تخفیف اعمال شد`, {
      userId,
      cartId: cart._id,
      couponCode,
      discountPercentage
    });
    
    res.status(200).json({
      success: true,
      message: `کوپن تخفیف ${discountPercentage}% اعمال شد`,
      data: {
        couponApplied: true,
        couponCode: cart.couponCode,
        discountPercentage: cart.couponDiscount,
        discountAmount: (cart.totalAmount * cart.couponDiscount) / 100,
        cartSummary: updatedCart.getSummary()
      }
    });
  }),
  
  /**
   * حذف کوپن تخفیف
   * @route DELETE /api/v1/cart/coupon
   * @access خصوصی (کاربر لاگین‌شده)
   */
  removeCoupon: asyncHandler(async (req, res, next) => {
    const userId = req.user._id;
    
    // یافتن سبد خرید
    const cart = await Cart.findOne({ user: userId, status: 'active' });
    
    if (!cart) {
      return next(new AppError('سبد خرید یافت نشد', 404));
    }
    
    if (!cart.couponCode) {
      return next(new AppError('کوپنی برای حذف وجود ندارد', 400));
    }
    
    const removedCoupon = cart.couponCode;
    
    // حذف کوپن
    cart.couponCode = undefined;
    cart.couponDiscount = 0;
    
    await cart.save();
    
    logger.info(`کوپن تخفیف حذف شد`, {
      userId,
      cartId: cart._id,
      removedCoupon
    });
    
    res.status(200).json({
      success: true,
      message: 'کوپن تخفیف با موفقیت حذف شد',
      data: {
        couponRemoved: true,
        removedCoupon,
        cartSummary: cart.getSummary()
      }
    });
  }),
  
  /**
   * به‌روزرسانی هزینه ارسال
   * @route PUT /api/v1/cart/shipping
   * @access خصوصی (کاربر لاگین‌شده)
   */
  updateShipping: asyncHandler(async (req, res, next) => {
    const userId = req.user._id;
    const { shippingFee = 0 } = req.body;
    
    if (shippingFee < 0) {
      return next(new AppError('هزینه ارسال نمی‌تواند منفی باشد', 400));
    }
    
    // یافتن سبد خرید
    const cart = await Cart.findOne({ user: userId, status: 'active' });
    
    if (!cart) {
      return next(new AppError('سبد خرید یافت نشد', 404));
    }
    
    // به‌روزرسانی هزینه ارسال
    cart.shippingFee = shippingFee;
    
    await cart.save();
    
    logger.info(`هزینه ارسال به‌روزرسانی شد`, {
      userId,
      cartId: cart._id,
      shippingFee
    });
    
    res.status(200).json({
      success: true,
      message: 'هزینه ارسال با موفقیت به‌روزرسانی شد',
      data: {
        shippingUpdated: true,
        newShippingFee: cart.shippingFee,
        cartSummary: cart.getSummary()
      }
    });
  }),
  
  /**
   * تایید نهایی سبد خرید (قبل از پرداخت)
   * @route POST /api/v1/cart/checkout/prepare
   * @access خصوصی (کاربر لاگین‌شده)
   */
  prepareCheckout: asyncHandler(async (req, res, next) => {
    const userId = req.user._id;
    
    // یافتن سبد خرید
    const cart = await Cart.findOne({ user: userId, status: 'active' })
      .populate('items.productId', 'name price discountPrice image stock inStock active');
    
    if (!cart) {
      return next(new AppError('سبد خرید یافت نشد', 404));
    }
    
    if (cart.items.length === 0) {
      return next(new AppError('سبد خرید خالی است', 400));
    }
    
    // بررسی موجودی و وضعیت تمام محصولات
    const validationResults = await cartService.validateCartItems(cart);
    
    if (!validationResults.valid) {
      return next(new AppError(
        'برخی محصولات در سبد خرید موجود نیستند',
        400,
        { invalidItems: validationResults.invalidItems }
      ));
    }
    
    // محاسبه جمع‌های نهایی
    const cartSummary = cart.getSummary();
    
    // ایجاد شناسه یکتا برای پرداخت
    const checkoutId = `chk_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    logger.info(`پرداخت آماده شد`, {
      userId,
      cartId: cart._id,
      checkoutId,
      finalAmount: cartSummary.finalAmount,
      itemsCount: cartSummary.totalItems
    });
    
    res.status(200).json({
      success: true,
      message: 'سبد خرید برای پرداخت آماده است',
      data: {
        checkoutId,
        cartSummary,
        walletRequired: cartSummary.finalAmount,
        canCheckout: true,
        timestamp: new Date().toISOString(),
        expiresIn: 1800 // 30 دقیقه اعتبار
      }
    });
  }),
  
  /**
   * همگام‌سازی سبد خرید با اطلاعات به‌روز محصولات
   * @route POST /api/v1/cart/sync
   * @access خصوصی (کاربر لاگین‌شده)
   */
  syncCart: asyncHandler(async (req, res, next) => {
    const userId = req.user._id;
    
    // یافتن سبد خرید
    const cart = await Cart.findOne({ user: userId, status: 'active' });
    
    if (!cart) {
      return next(new AppError('سبد خرید یافت نشد', 404));
    }
    
    // همگام‌سازی با اطلاعات به‌روز محصولات
    const syncResult = await cartService.syncCartWithProducts(cart);
    
    logger.info(`سبد خرید همگام‌سازی شد`, {
      userId,
      cartId: cart._id,
      updatedItems: syncResult.updatedItems,
      removedItems: syncResult.removedItems
    });
    
    res.status(200).json({
      success: true,
      message: 'سبد خرید با موفقیت همگام‌سازی شد',
      data: {
        synced: true,
        ...syncResult,
        cartSummary: cart.getSummary()
      }
    });
  })
};

module.exports = cartController;