/**
 * @file کنترلر سفارشات HTLand
 * @description مدیریت کامل عملیات سفارشات کاربران
 */

const Order = require('../models/Order.model');
const Cart = require('../models/Cart.model');
const Product = require('../models/Product.model');
const orderService = require('../services/orderService');
const asyncHandler = require('../utils/asyncHandler');
const AppError = require('../utils/AppError');
const logger = require('../utils/logger');

/**
 * کنترلر سفارشات
 */
const orderController = {
  
  /**
   * ایجاد سفارش جدید از سبد خرید
   * @route POST /api/v1/orders
   * @access خصوصی (کاربر لاگین‌شده)
   */
  createOrder: asyncHandler(async (req, res, next) => {
    const userId = req.user._id;
    const { 
      shippingAddressId, 
      paymentMethod, 
      notes,
      useWalletBalance = true
    } = req.body;
    
    // اعتبارسنجی ورودی
    if (!shippingAddressId) {
      return next(new AppError('آدرس ارسال الزامی است', 400));
    }
    
    if (!paymentMethod) {
      return next(new AppError('روش پرداخت الزامی است', 400));
    }
    
    if (!['wallet', 'zarinpal', 'bank_transfer', 'cash_on_delivery'].includes(paymentMethod)) {
      return next(new AppError('روش پرداخت معتبر نیست', 400));
    }
    
    // یافتن سبد خرید کاربر
    const cart = await Cart.findOne({ user: userId, status: 'active' })
      .populate('items.productId', 'name price discountPrice image category categoryFa stock inStock active weight');
    
    if (!cart || cart.items.length === 0) {
      return next(new AppError('سبد خرید شما خالی است', 400));
    }
    
    // اعتبارسنجی موجودی و وضعیت محصولات
    const validationResult = await orderService.validateCartItems(cart.items);
    
    if (!validationResult.valid) {
      return next(new AppError(
        'برخی محصولات در سبد خرید موجود نیستند',
        400,
        { invalidItems: validationResult.invalidItems }
      ));
    }
    
    // دریافت آدرس ارسال (در اینجا باید از سرویس آدرس‌ها استفاده شود)
    // برای نمونه، یک آدرس فرضی
    const shippingAddress = {
      recipientName: req.user.name,
      recipientPhone: req.user.phone || '09123456789',
      province: 'مازندران',
      city: 'ساری',
      address: 'بلوار طالقانی، برج پاسارگاد، طبقه ۴',
      postalCode: '4816612345',
      deliveryNotes: notes || ''
    };
    
    // محاسبه جمع‌های مالی
    const totals = orderService.calculateOrderTotals(cart.items, cart.shippingFee || 0);
    
    // ایجاد سفارش
    const orderData = {
      user: userId,
      items: cart.items.map(item => ({
        product: item.productId._id,
        productName: item.productId.name,
        productImage: item.productId.image,
        category: item.productId.category,
        categoryFa: item.productId.categoryFa,
        quantity: item.quantity,
        unitPrice: item.priceAtTime,
        finalUnitPrice: item.finalPriceAtTime,
        totalPrice: item.finalPriceAtTime * item.quantity,
        weight: item.productId.weight
      })),
      shippingAddress,
      payment: {
        method: paymentMethod,
        amount: totals.finalAmount,
        status: 'pending'
      },
      subtotal: totals.subtotal,
      discount: totals.totalDiscount + (cart.couponDiscount ? (totals.subtotal * cart.couponDiscount / 100) : 0),
      shippingCost: totals.shippingFee,
      totalAmount: totals.finalAmount,
      notes: {
        customer: notes || ''
      }
    };
    
    let order;
    
    // پرداخت با کیف پول
    if (paymentMethod === 'wallet' && useWalletBalance) {
      try {
        order = await orderService.createOrderWithWalletPayment(orderData, req.user);
        
        logger.info(`سفارش با پرداخت کیف پول ایجاد شد`, {
          userId,
          orderId: order._id,
          orderNumber: order.orderNumber,
          amount: order.totalAmount
        });
        
      } catch (error) {
        return next(new AppError(error.message, 400));
      }
    } 
    // پرداخت با زرین‌پال
    else if (paymentMethod === 'zarinpal') {
      order = await Order.create(orderData);
      
      // ایجاد درخواست پرداخت زرین‌پال
      const paymentRequest = await orderService.createZarinpalPayment(order);
      
      // ذخیره authority در سفارش
      order.payment.zarinpalAuthority = paymentRequest.authority;
      await order.save();
      
      logger.info(`درخواست پرداخت زرین‌پال ایجاد شد`, {
        userId,
        orderId: order._id,
        authority: paymentRequest.authority,
        amount: order.totalAmount
      });
      
      return res.status(200).json({
        success: true,
        message: 'درخواست پرداخت ایجاد شد',
        data: {
          orderId: order._id,
          orderNumber: order.orderNumber,
          paymentUrl: paymentRequest.paymentUrl,
          authority: paymentRequest.authority,
          amount: order.totalAmount,
          redirectToGateway: true
        }
      });
    }
    // سایر روش‌های پرداخت
    else {
      order = await Order.create(orderData);
      
      logger.info(`سفارش با روش پرداخت ${paymentMethod} ایجاد شد`, {
        userId,
        orderId: order._id,
        orderNumber: order.orderNumber,
        amount: order.totalAmount,
        paymentMethod
      });
    }
    
    // خالی کردن سبد خرید پس از ایجاد سفارش موفق
    if (order.status !== 'pending') {
      await cart.clearCart();
    }
    
    // ارسال نوتیفیکیشن
    await orderService.sendOrderNotification(order, 'created');
    
    res.status(201).json({
      success: true,
      message: 'سفارش با موفقیت ایجاد شد',
      data: {
        orderId: order._id,
        orderNumber: order.orderNumber,
        status: order.status,
        statusFa: order.statusFa,
        totalAmount: order.totalAmount,
        payment: {
          method: order.payment.method,
          status: order.payment.status,
          nextStep: order.payment.status === 'pending' ? 'پرداخت' : 'پیگیری سفارش'
        },
        items: order.items.map(item => ({
          productName: item.productName,
          quantity: item.quantity,
          price: item.finalUnitPrice,
          total: item.totalPrice
        }))
      }
    });
  }),
  
  /**
   * دریافت جزئیات یک سفارش
   * @route GET /api/v1/orders/{id}
   * @access خصوصی (کاربر لاگین‌شده)
   */
  getOrder: asyncHandler(async (req, res, next) => {
    const userId = req.user._id;
    const { id } = req.params;
    const isAdmin = req.user.isAdmin;
    
    // جستجوی سفارش
    let order;
    
    if (isAdmin) {
      // ادمین می‌تواند هر سفارشی را ببیند
      order = await Order.findById(id)
        .populate('user', 'name email phone')
        .populate('items.product', 'name image price discountPrice categoryFa');
    } else {
      // کاربر فقط سفارشات خود را می‌بیند
      order = await Order.findOne({ _id: id, user: userId, isDeleted: false })
        .populate('items.product', 'name image price discountPrice categoryFa');
    }
    
    if (!order) {
      return next(new AppError('سفارش یافت نشد', 404));
    }
    
    logger.info(`جزئیات سفارش مشاهده شد`, {
      userId,
      orderId: order._id,
      orderNumber: order.orderNumber,
      viewedByAdmin: isAdmin
    });
    
    res.status(200).json({
      success: true,
      message: 'جزئیات سفارش با موفقیت دریافت شد',
      data: {
        order: {
          ...order.toObject(),
          statusFa: order.statusFa,
          itemCount: order.itemCount,
          displayDate: order.displayDate,
          estimatedTimeRemaining: order.estimatedTimeRemaining,
          timeline: order.getTimeline(),
          summary: order.getOrderSummary()
        }
      }
    });
  }),
  
  /**
   * دریافت لیست سفارشات کاربر
   * @route GET /api/v1/orders
   * @access خصوصی (کاربر لاگین‌شده)
   */
  getUserOrders: asyncHandler(async (req, res, next) => {
    const userId = req.user._id;
    const isAdmin = req.user.isAdmin;
    const {
      page = 1,
      limit = 10,
      status,
      startDate,
      endDate,
      sort = '-createdAt'
    } = req.query;
    
    // ساخت فیلترها
    const filter = { isDeleted: false };
    
    if (!isAdmin) {
      filter.user = userId;
    }
    
    if (status) {
      filter.status = status;
    }
    
    // فیلتر تاریخ
    if (startDate || endDate) {
      filter.createdAt = {};
      if (startDate) filter.createdAt.$gte = new Date(startDate);
      if (endDate) filter.createdAt.$lte = new Date(endDate);
    }
    
    // گزینه‌های صفحه‌بندی
    const options = {
      page: parseInt(page),
      limit: parseInt(limit),
      sort,
      select: 'orderNumber status totalAmount createdAt timeline.orderedAt shippingAddress.city shippingAddress.province',
      populate: [
        { path: 'user', select: 'name', match: isAdmin ? {} : { _id: userId } },
        { path: 'items.product', select: 'name image', limit: 1 }
      ]
    };
    
    // اجرای کوئری با صفحه‌بندی
    const orders = await Order.paginate(filter, options);
    
    logger.info(`لیست سفارشات دریافت شد`, {
      userId,
      isAdmin,
      page,
      limit,
      filter,
      total: orders.totalDocs
    });
    
    // فرمت پاسخ
    const formattedOrders = orders.docs.map(order => ({
      id: order._id,
      orderNumber: order.orderNumber,
      status: order.status,
      statusFa: order.statusFa,
      totalAmount: order.totalAmount,
      itemCount: order.itemCount,
      orderedAt: order.timeline.orderedAt,
      displayDate: order.displayDate,
      shippingInfo: {
        city: order.shippingAddress.city,
        province: order.shippingAddress.province,
        recipientName: order.shippingAddress.recipientName
      },
      firstItem: order.items[0] ? {
        productName: order.items[0].productName,
        image: order.items[0].productImage,
        quantity: order.items[0].quantity
      } : null
    }));
    
    res.status(200).json({
      success: true,
      message: 'لیست سفارشات با موفقیت دریافت شد',
      data: formattedOrders,
      pagination: {
        total: orders.totalDocs,
        limit: orders.limit,
        page: orders.page,
        pages: orders.totalPages,
        hasNext: orders.hasNextPage,
        hasPrev: orders.hasPrevPage
      }
    });
  }),
  
  /**
   * لغو سفارش
   * @route POST /api/v1/orders/{id}/cancel
   * @access خصوصی (کاربر لاگین‌شده)
   */
  cancelOrder: asyncHandler(async (req, res, next) => {
    const userId = req.user._id;
    const { id } = req.params;
    const { reason } = req.body;
    const isAdmin = req.user.isAdmin;
    
    // یافتن سفارش
    const order = await Order.findOne({ 
      _id: id, 
      user: isAdmin ? { $exists: true } : userId,
      isDeleted: false 
    });
    
    if (!order) {
      return next(new AppError('سفارش یافت نشد', 404));
    }
    
    // بررسی امکان لغو
    if (order.status === 'delivered') {
      return next(new AppError('سفارش تحویل داده شده قابل لغو نیست', 400));
    }
    
    if (order.status === 'cancelled') {
      return next(new AppError('سفارش قبلاً لغو شده است', 400));
    }
    
    // لغو سفارش
    try {
      await order.cancel(reason || 'لغو توسط کاربر');
      
      // بازگشت موجودی محصولات (در صورت نیاز)
      if (order.status !== 'pending') {
        await orderService.restoreProductStock(order.items);
      }
      
      // بازگشت وجه (در صورت پرداخت شده)
      if (order.payment.status === 'completed') {
        await orderService.refundPayment(order);
      }
      
      logger.info(`سفارش لغو شد`, {
        userId,
        orderId: order._id,
        orderNumber: order.orderNumber,
        cancelledByAdmin: isAdmin,
        reason
      });
      
      // ارسال نوتیفیکیشن
      await orderService.sendOrderNotification(order, 'cancelled');
      
      res.status(200).json({
        success: true,
        message: 'سفارش با موفقیت لغو شد',
        data: {
          orderId: order._id,
          orderNumber: order.orderNumber,
          status: order.status,
          statusFa: order.statusFa,
          cancelledAt: order.timeline.cancelledAt,
          refundStatus: order.payment.status === 'refunded' ? 'در حال پرداخت' : 'نیاز ندارد'
        }
      });
      
    } catch (error) {
      return next(new AppError(error.message, 400));
    }
  }),
  
  /**
   * به‌روزرسانی وضعیت سفارش (فقط ادمین)
   * @route PUT /api/v1/orders/{id}/status
   * @access خصوصی (فقط ادمین)
   */
  updateOrderStatus: asyncHandler(async (req, res, next) => {
    if (!req.user.isAdmin) {
      return next(new AppError('شما مجوز به‌روزرسانی وضعیت سفارش را ندارید', 403));
    }
    
    const { id } = req.params;
    const { status, notes, trackingCode, shippingProvider, trackingUrl } = req.body;
    
    // اعتبارسنجی وضعیت
    const validStatuses = ['paid', 'processing', 'shipped', 'delivered', 'cancelled', 'refunded'];
    if (!validStatuses.includes(status)) {
      return next(new AppError('وضعیت سفارش معتبر نیست', 400));
    }
    
    // یافتن سفارش
    const order = await Order.findById(id);
    
    if (!order) {
      return next(new AppError('سفارش یافت نشد', 404));
    }
    
    if (order.isDeleted) {
      return next(new AppError('سفارش حذف شده است', 400));
    }
    
    // به‌روزرسانی وضعیت
    try {
      await order.updateStatus(status, notes);
      
      // افزودن کد رهگیری اگر ارائه شده
      if (trackingCode && (status === 'shipped' || status === 'delivered')) {
        await order.addTracking(trackingCode, shippingProvider, trackingUrl);
      }
      
      logger.info(`وضعیت سفارش به‌روزرسانی شد`, {
        adminId: req.user._id,
        orderId: order._id,
        orderNumber: order.orderNumber,
        oldStatus: order.status,
        newStatus: status
      });
      
      // ارسال نوتیفیکیشن
      await orderService.sendOrderNotification(order, 'status_updated');
      
      res.status(200).json({
        success: true,
        message: 'وضعیت سفارش با موفقیت به‌روزرسانی شد',
        data: {
          orderId: order._id,
          orderNumber: order.orderNumber,
          status: order.status,
          statusFa: order.statusFa,
          updatedAt: order.updatedAt,
          timeline: order.getTimeline()
        }
      });
      
    } catch (error) {
      return next(new AppError(error.message, 400));
    }
  }),
  
  /**
   * پیگیری سفارش با شماره سفارش
   * @route GET /api/v1/orders/track/{orderNumber}
   * @access عمومی
   */
  trackOrder: asyncHandler(async (req, res, next) => {
    const { orderNumber } = req.params;
    const { phone } = req.query; // برای تأیید مالکیت
    
    // یافتن سفارش
    const order = await Order.findOne({ orderNumber, isDeleted: false })
      .populate('user', 'name phone');
    
    if (!order) {
      return next(new AppError('سفارش یافت نشد', 404));
    }
    
    // تأیید مالکیت (اگر شماره تلفن ارائه شده)
    if (phone && order.user.phone !== phone) {
      return next(new AppError('شماره تلفن با سفارش مطابقت ندارد', 403));
    }
    
    logger.info(`سفارش پیگیری شد`, {
      orderId: order._id,
      orderNumber,
      trackedWithPhone: !!phone
    });
    
    // اطلاعات عمومی برای پیگیری
    const trackingInfo = {
      orderNumber: order.orderNumber,
      status: order.status,
      statusFa: order.statusFa,
      timeline: order.getTimeline(),
      shippingInfo: {
        recipientName: order.shippingAddress.recipientName,
        city: order.shippingAddress.city,
        province: order.shippingAddress.province,
        estimatedDelivery: order.estimatedDelivery
      },
      tracking: order.trackingCode ? {
        code: order.trackingCode,
        provider: order.shippingProvider,
        url: order.trackingUrl
      } : null,
      itemCount: order.itemCount,
      totalAmount: order.totalAmount
    };
    
    res.status(200).json({
      success: true,
      message: 'اطلاعات پیگیری سفارش دریافت شد',
      data: trackingInfo
    });
  }),
  
  /**
   * تایید پرداخت زرین‌پال
   * @route GET /api/v1/orders/payment/verify
   * @access عمومی
   */
  verifyPayment: asyncHandler(async (req, res, next) => {
    const { Authority, Status } = req.query;
    
    if (!Authority || !Status) {
      return next(new AppError('پارامترهای پرداخت ناقص است', 400));
    }
    
    if (Status !== 'OK') {
      return next(new AppError('پرداخت ناموفق بود', 400));
    }
    
    // یافتن سفارش با authority
    const order = await Order.findOne({ 
      'payment.zarinpalAuthority': Authority,
      'payment.status': 'pending'
    });
    
    if (!order) {
      return next(new AppError('سفارش یافت نشد یا قبلاً پرداخت شده', 404));
    }
    
    // تایید پرداخت با زرین‌پال
    try {
      const verification = await orderService.verifyZarinpalPayment(Authority, order.totalAmount);
      
      if (!verification.success) {
        throw new Error('تایید پرداخت ناموفق بود');
      }
      
      // به‌روزرسانی وضعیت پرداخت
      order.payment.status = 'completed';
      order.payment.transactionId = verification.refId;
      order.payment.paidAt = new Date();
      order.status = 'paid';
      
      await order.save();
      
      // کاهش موجودی محصولات
      await orderService.decreaseProductStock(order.items);
      
      logger.info(`پرداخت زرین‌پال تایید شد`, {
        orderId: order._id,
        orderNumber: order.orderNumber,
        authority: Authority,
        refId: verification.refId,
        amount: order.totalAmount
      });
      
      // ارسال نوتیفیکیشن
      await orderService.sendOrderNotification(order, 'payment_verified');
      
      // ریدایرکت به صفحه موفقیت
      res.redirect(`${process.env.FRONTEND_URL}/orders/${order._id}/success?refId=${verification.refId}`);
      
    } catch (error) {
      logger.error('خطا در تایید پرداخت زرین‌پال:', error);
      
      // ریدایرکت به صفحه خطا
      res.redirect(`${process.env.FRONTEND_URL}/orders/payment/failed?error=${encodeURIComponent(error.message)}`);
    }
  }),
  
  /**
   * دریافت آمار سفارشات کاربر
   * @route GET /api/v1/orders/stats
   * @access خصوصی (کاربر لاگین‌شده)
   */
  getOrderStats: asyncHandler(async (req, res, next) => {
    const userId = req.user._id;
    const isAdmin = req.user.isAdmin;
    
    const stats = await Order.getStatistics(isAdmin ? null : userId);
    
    // آمار بیشتر برای ادمین
    let additionalStats = {};
    if (isAdmin) {
      additionalStats = await orderService.getAdminStatistics();
    }
    
    res.status(200).json({
      success: true,
      message: 'آمار سفارشات دریافت شد',
      data: {
        ...stats,
        ...additionalStats,
        userType: isAdmin ? 'admin' : 'customer'
      }
    });
  }),
  
  /**
   * دریافت سفارشات اخیر (برای داشبورد)
   * @route GET /api/v1/orders/recent
   * @access خصوصی (کاربر لاگین‌شده)
   */
  getRecentOrders: asyncHandler(async (req, res, next) => {
    const userId = req.user._id;
    const isAdmin = req.user.isAdmin;
    const { limit = 5 } = req.query;
    
    let orders;
    
    if (isAdmin) {
      orders = await Order.findRecentOrders(parseInt(limit));
    } else {
      orders = await Order.findUserOrders(userId)
        .sort('-createdAt')
        .limit(parseInt(limit));
    }
    
    const formattedOrders = orders.map(order => ({
      id: order._id,
      orderNumber: order.orderNumber,
      status: order.status,
      statusFa: order.statusFa,
      totalAmount: order.totalAmount,
      orderedAt: order.timeline.orderedAt,
      itemCount: order.itemCount,
      shippingCity: order.shippingAddress.city
    }));
    
    res.status(200).json({
      success: true,
      message: 'سفارشات اخیر دریافت شد',
      data: formattedOrders
    });
  })
};

module.exports = orderController;