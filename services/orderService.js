/**
 * @file سرویس سفارشات HTLand
 * @description منطق کسب‌وکار و عملیات مربوط به سفارشات
 */

const Order = require('../models/Order.model');
const Cart = require('../models/Cart.model');
const Product = require('../models/Product.model');
const AppError = require('../utils/AppError');
const logger = require('../utils/logger');
const axios = require('axios');

/**
 * سرویس مدیریت سفارشات
 */
const orderService = {
  
  /**
   * اعتبارسنجی آیتم‌های سبد خرید برای سفارش
   * @param {Array} cartItems - آیتم‌های سبد خرید
   * @returns {Promise<Object>} - نتیجه اعتبارسنجی
   */
  validateCartItems: async (cartItems) => {
    const invalidItems = [];
    let allValid = true;
    
    for (const item of cartItems) {
      try {
        const product = await Product.findById(item.productId._id || item.productId);
        
        if (!product) {
          invalidItems.push({
            productId: item.productId,
            reason: 'محصول حذف شده است',
            itemName: item.productName
          });
          allValid = false;
          continue;
        }
        
        if (!product.active) {
          invalidItems.push({
            productId: product._id,
            reason: 'محصول غیرفعال شده است',
            itemName: product.name
          });
          allValid = false;
          continue;
        }
        
        if (!product.inStock) {
          invalidItems.push({
            productId: product._id,
            reason: 'محصول موجود نیست',
            itemName: product.name
          });
          allValid = false;
          continue;
        }
        
        if (product.stock < item.quantity) {
          invalidItems.push({
            productId: product._id,
            reason: `موجودی کافی نیست (موجودی: ${product.stock}, درخواست: ${item.quantity})`,
            itemName: product.name,
            requested: item.quantity,
            available: product.stock
          });
          allValid = false;
        }
        
      } catch (error) {
        logger.error(`خطا در بررسی محصول ${item.productId}:`, error);
        invalidItems.push({
          productId: item.productId,
          reason: 'خطای سرور در بررسی محصول',
          itemName: item.productName
        });
        allValid = false;
      }
    }
    
    return {
      valid: allValid,
      invalidItems,
      totalItems: cartItems.length,
      validItems: cartItems.length - invalidItems.length
    };
  },
  
  /**
   * محاسبه جمع‌های مالی سفارش
   * @param {Array} items - آیتم‌های سفارش
   * @param {number} shippingFee - هزینه ارسال
   * @returns {Object} - محاسبات مالی
   */
  calculateOrderTotals: (items, shippingFee = 0) => {
    let subtotal = 0;
    let totalDiscount = 0;
    let totalItems = 0;
    
    items.forEach(item => {
      const itemPrice = item.finalPriceAtTime || item.unitPrice;
      const itemTotal = itemPrice * item.quantity;
      
      subtotal += itemTotal;
      totalItems += item.quantity;
      
      // محاسبه تخفیف آیتم
      if (item.priceAtTime > itemPrice) {
        totalDiscount += (item.priceAtTime - itemPrice) * item.quantity;
      }
    });
    
    // محاسبه مالیات (در صورت نیاز)
    const taxRate = 0.09; // 9% مالیات بر ارزش افزوده
    const tax = subtotal * taxRate;
    
    const finalAmount = subtotal + shippingFee + tax;
    
    return {
      subtotal,
      totalDiscount,
      totalItems,
      shippingFee,
      tax,
      finalAmount,
      formatted: {
        subtotal: subtotal.toLocaleString('fa-IR'),
        discount: totalDiscount.toLocaleString('fa-IR'),
        shipping: shippingFee.toLocaleString('fa-IR'),
        tax: tax.toLocaleString('fa-IR'),
        final: finalAmount.toLocaleString('fa-IR')
      }
    };
  },
  
  /**
   * ایجاد سفارش با پرداخت کیف پول
   * @param {Object} orderData - داده‌های سفارش
   * @param {Object} user - کاربر
   * @returns {Promise<Object>} - سفارش ایجاد شده
   */
  createOrderWithWalletPayment: async (orderData, user) => {
    try {
      // بررسی موجودی کیف پول
      const walletCheck = await orderService.checkWalletBalance(user._id, orderData.totalAmount);
      
      if (!walletCheck.hasSufficientBalance) {
        throw new AppError(
          `موجودی کیف پول کافی نیست. موجودی: ${walletCheck.balance}, مورد نیاز: ${orderData.totalAmount}`,
          400
        );
      }
      
      // کسر از کیف پول
      const paymentResult = await orderService.deductFromWallet({
        userId: user._id,
        amount: orderData.totalAmount,
        description: `پرداخت سفارش ${orderData.orderNumber || 'جدید'}`,
        orderId: null // بعداً اضافه می‌شود
      });
      
      if (!paymentResult.success) {
        throw new AppError('پرداخت با کیف پول ناموفق بود', 400);
      }
      
      // ایجاد سفارش
      orderData.payment.status = 'completed';
      orderData.payment.transactionId = paymentResult.transactionId;
      orderData.payment.paidAt = new Date();
      orderData.status = 'paid';
      
      const order = await Order.create(orderData);
      
      // به‌روزرسانی transactionId با شناسه سفارش
      await orderService.updateWalletTransaction(order._id, paymentResult.transactionId);
      
      // کاهش موجودی محصولات
      await orderService.decreaseProductStock(order.items);
      
      logger.info(`سفارش با پرداخت کیف پول ایجاد شد`, {
        userId: user._id,
        orderId: order._id,
        transactionId: paymentResult.transactionId,
        amount: order.totalAmount
      });
      
      return order;
      
    } catch (error) {
      logger.error('خطا در ایجاد سفارش با کیف پول:', error);
      throw error;
    }
  },
  
  /**
   * بررسی موجودی کیف پول
   * @param {string} userId - شناسه کاربر
   * @param {number} requiredAmount - مبلغ مورد نیاز
   * @returns {Promise<Object>} - وضعیت موجودی
   */
  checkWalletBalance: async (userId, requiredAmount) => {
    try {
      // اینجا باید به سرویس کیف پول متصل شویم
      // برای نمونه:
      const walletServiceUrl = process.env.WALLET_SERVICE_URL || 'http://localhost:3001';
      
      // در محیط واقعی:
      // const response = await axios.get(`${walletServiceUrl}/api/v1/wallet/balance/${userId}`);
      // const walletData = response.data;
      
      // داده نمونه:
      const walletData = {
        success: true,
        data: {
          balance: 1000000,
          currency: 'تومان'
        }
      };
      
      return {
        hasSufficientBalance: walletData.data.balance >= requiredAmount,
        balance: walletData.data.balance,
        requiredAmount,
        deficit: walletData.data.balance >= requiredAmount ? 0 : requiredAmount - walletData.data.balance,
        currency: walletData.data.currency
      };
      
    } catch (error) {
      logger.error('خطا در بررسی موجودی کیف پول:', error);
      throw new AppError('خطا در ارتباط با سرویس کیف پول', 500);
    }
  },
  
  /**
   * کسر از کیف پول
   * @param {Object} paymentData - داده‌های پرداخت
   * @returns {Promise<Object>} - نتیجه پرداخت
   */
  deductFromWallet: async (paymentData) => {
    try {
      // اینجا باید به سرویس کیف پول متصل شویم
      const walletServiceUrl = process.env.WALLET_SERVICE_URL || 'http://localhost:3001';
      
      // در محیط واقعی:
      // const response = await axios.post(`${walletServiceUrl}/api/v1/wallet/pay`, paymentData);
      // return response.data;
      
      // داده نمونه:
      return {
        success: true,
        transactionId: `wtx_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        remainingBalance: 500000,
        message: 'پرداخت موفقیت‌آمیز بود'
      };
      
    } catch (error) {
      logger.error('خطا در کسر از کیف پول:', error);
      throw new AppError('خطا در پردازش پرداخت کیف پول', 500);
    }
  },
  
  /**
   * به‌روزرسانی تراکنش کیف پول با شناسه سفارش
   * @param {string} orderId - شناسه سفارش
   * @param {string} transactionId - شناسه تراکنش
   * @returns {Promise<void>}
   */
  updateWalletTransaction: async (orderId, transactionId) => {
    try {
      // به‌روزرسانی تراکنش در سرویس کیف پول
      const walletServiceUrl = process.env.WALLET_SERVICE_URL || 'http://localhost:3001';
      
      // در محیط واقعی:
      // await axios.put(`${walletServiceUrl}/api/v1/wallet/transactions/${transactionId}`, {
      //   orderId,
      //   metadata: { updated: true }
      // });
      
      logger.info(`تراکنش کیف پول به‌روزرسانی شد`, {
        transactionId,
        orderId
      });
      
    } catch (error) {
      logger.error('خطا در به‌روزرسانی تراکنش کیف پول:', error);
      // این خطا نباید فرآیند اصلی را مختل کند
    }
  },
  
  /**
   * کاهش موجودی محصولات پس از سفارش
   * @param {Array} items - آیتم‌های سفارش
   * @returns {Promise<void>}
   */
  decreaseProductStock: async (items) => {
    const session = await Product.startSession();
    
    try {
      session.startTransaction();
      
      for (const item of items) {
        const product = await Product.findById(item.product).session(session);
        
        if (!product) {
          throw new AppError(`محصول ${item.product} یافت نشد`, 404);
        }
        
        if (product.stock < item.quantity) {
          throw new AppError(
            `موجودی محصول ${product.name} کافی نیست. موجودی: ${product.stock}, فروخته شده: ${item.quantity}`,
            400
          );
        }
        
        product.stock -= item.quantity;
        product.inStock = product.stock > 0;
        
        await product.save({ session });
      }
      
      await session.commitTransaction();
      
      logger.info(`موجودی ${items.length} محصول کاهش یافت`);
      
    } catch (error) {
      await session.abortTransaction();
      logger.error('خطا در کاهش موجودی محصولات:', error);
      throw error;
    } finally {
      session.endSession();
    }
  },
  
  /**
   * بازگرداندن موجودی محصولات پس از لغو سفارش
   * @param {Array} items - آیتم‌های سفارش
   * @returns {Promise<void>}
   */
  restoreProductStock: async (items) => {
    const session = await Product.startSession();
    
    try {
      session.startTransaction();
      
      for (const item of items) {
        const product = await Product.findById(item.product).session(session);
        
        if (!product) {
          // اگر محصول حذف شده، ادامه بده
          continue;
        }
        
        product.stock += item.quantity;
        product.inStock = true;
        
        await product.save({ session });
      }
      
      await session.commitTransaction();
      
      logger.info(`موجودی ${items.length} محصول بازگردانده شد`);
      
    } catch (error) {
      await session.abortTransaction();
      logger.error('خطا در بازگرداندن موجودی محصولات:', error);
      throw error;
    } finally {
      session.endSession();
    }
  },
  
  /**
   * ایجاد درخواست پرداخت زرین‌پال
   * @param {Object} order - سفارش
   * @returns {Promise<Object>} - اطلاعات پرداخت
   */
  createZarinpalPayment: async (order) => {
    try {
      const zarinpalConfig = {
        merchantId: process.env.ZARINPAL_MERCHANT_ID,
        callbackUrl: `${process.env.BACKEND_URL}/api/v1/orders/payment/verify`,
        description: `پرداخت سفارش ${order.orderNumber} - HTLand`,
        amount: order.totalAmount,
        metadata: {
          orderId: order._id.toString(),
          userId: order.user.toString(),
          mobile: order.shippingAddress.recipientPhone
        }
      };
      
      // در محیط واقعی:
      // const response = await axios.post('https://api.zarinpal.com/pg/v4/payment/request.json', {
      //   merchant_id: zarinpalConfig.merchantId,
      //   amount: zarinpalConfig.amount,
      //   description: zarinpalConfig.description,
      //   callback_url: zarinpalConfig.callbackUrl,
      //   metadata: zarinpalConfig.metadata
      // });
      
      // داده نمونه:
      const paymentResponse = {
        data: {
          authority: 'A00000000000000000000000000000000000',
          code: 100,
          message: 'عملیات موفقیت‌آمیز بود'
        }
      };
      
      if (paymentResponse.data.code !== 100) {
        throw new AppError('خطا در ایجاد درخواست پرداخت زرین‌پال', 400);
      }
      
      const paymentUrl = `https://www.zarinpal.com/pg/StartPay/${paymentResponse.data.authority}`;
      
      return {
        success: true,
        authority: paymentResponse.data.authority,
        paymentUrl,
        amount: zarinpalConfig.amount
      };
      
    } catch (error) {
      logger.error('خطا در ایجاد درخواست پرداخت زرین‌پال:', error);
      throw new AppError('خطا در ارتباط با درگاه پرداخت', 500);
    }
  },
  
  /**
   * تایید پرداخت زرین‌پال
   * @param {string} authority - کد authority
   * @param {number} amount - مبلغ
   * @returns {Promise<Object>} - نتیجه تایید
   */
  verifyZarinpalPayment: async (authority, amount) => {
    try {
      const zarinpalConfig = {
        merchantId: process.env.ZARINPAL_MERCHANT_ID
      };
      
      // در محیط واقعی:
      // const response = await axios.post('https://api.zarinpal.com/pg/v4/payment/verify.json', {
      //   merchant_id: zarinpalConfig.merchantId,
      //   authority: authority,
      //   amount: amount
      // });
      
      // داده نمونه:
      const verificationResponse = {
        data: {
          code: 100,
          ref_id: 123456789,
          card_pan: '5022-29**-****-2328',
          card_hash: '1234567890ABCDEF',
          fee_type: 'Merchant',
          fee: 1000
        }
      };
      
      if (verificationResponse.data.code !== 100) {
        throw new AppError('تایید پرداخت ناموفق بود', 400);
      }
      
      return {
        success: true,
        refId: verificationResponse.data.ref_id,
        cardPan: verificationResponse.data.card_pan,
        cardHash: verificationResponse.data.card_hash,
        fee: verificationResponse.data.fee
      };
      
    } catch (error) {
      logger.error('خطا در تایید پرداخت زرین‌پال:', error);
      throw error;
    }
  },
  
  /**
   * بازگشت وجه سفارش
   * @param {Object} order - سفارش
   * @returns {Promise<Object>} - نتیجه بازگشت وجه
   */
  refundPayment: async (order) => {
    try {
      if (order.payment.method === 'wallet') {
        // بازگشت به کیف پول
        return await orderService.refundToWallet(order);
      } else if (order.payment.method === 'zarinpal') {
        // بازگشت از زرین‌پال
        return await orderService.refundZarinpalPayment(order);
      } else {
        // برای سایر روش‌ها، فقط وضعیت را تغییر می‌دهیم
        order.payment.status = 'refunded';
        await order.save();
        
        return {
          success: true,
          message: 'وضعیت پرداخت به بازگشت وجه تغییر یافت',
          refundId: `ref_${Date.now()}`
        };
      }
      
    } catch (error) {
      logger.error('خطا در بازگشت وجه:', error);
      throw new AppError('خطا در فرآیند بازگشت وجه', 500);
    }
  },
  
  /**
   * بازگشت وجه به کیف پول
   * @param {Object} order - سفارش
   * @returns {Promise<Object>} - نتیجه بازگشت
   */
  refundToWallet: async (order) => {
    try {
      const walletServiceUrl = process.env.WALLET_SERVICE_URL || 'http://localhost:3001';
      
      // در محیط واقعی:
      // const response = await axios.post(`${walletServiceUrl}/api/v1/wallet/refund`, {
      //   userId: order.user,
      //   amount: order.payment.amount,
      //   originalTransactionId: order.payment.transactionId,
      //   reason: `بازگشت وجه سفارش ${order.orderNumber}`
      // });
      
      // داده نمونه:
      const refundResult = {
        success: true,
        transactionId: `rtx_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        message: 'وجه با موفقیت بازگشت داده شد'
      };
      
      if (!refundResult.success) {
        throw new AppError('بازگشت وجه ناموفق بود', 400);
      }
      
      order.payment.status = 'refunded';
      await order.save();
      
      return refundResult;
      
    } catch (error) {
      logger.error('خطا در بازگشت وجه به کیف پول:', error);
      throw error;
    }
  },
  
  /**
   * بازگشت وجه از زرین‌پال
   * @param {Object} order - سفارش
   * @returns {Promise<Object>} - نتیجه بازگشت
   */
  refundZarinpalPayment: async (order) => {
    try {
      // اینجا باید API بازگشت وجه زرین‌پال فراخوانی شود
      // برای نمونه:
      
      return {
        success: true,
        refundId: `zref_${Date.now()}`,
        message: 'درخواست بازگشت وجه ثبت شد. طی ۷۲ ساعت کاری انجام می‌شود.'
      };
      
    } catch (error) {
      logger.error('خطا در بازگشت وجه زرین‌پال:', error);
      throw error;
    }
  },
  
  /**
   * ارسال نوتیفیکیشن سفارش
   * @param {Object} order - سفارش
   * @param {string} event - رویداد
   * @returns {Promise<void>}
   */
  sendOrderNotification: async (order, event) => {
    try {
      const notifications = {
        created: {
          title: 'سفارش جدید ثبت شد',
          message: `سفارش ${order.orderNumber} با موفقیت ثبت شد.`,
          type: 'info'
        },
        paid: {
          title: 'پرداخت تایید شد',
          message: `پرداخت سفارش ${order.orderNumber} با موفقیت انجام شد.`,
          type: 'success'
        },
        status_updated: {
          title: 'وضعیت سفارش تغییر کرد',
          message: `وضعیت سفارش ${order.orderNumber} به "${order.statusFa}" تغییر یافت.`,
          type: 'info'
        },
        shipped: {
          title: 'سفارش ارسال شد',
          message: `سفارش ${order.orderNumber} ارسال شد. ${order.trackingCode ? `کد رهگیری: ${order.trackingCode}` : ''}`,
          type: 'info'
        },
        delivered: {
          title: 'سفارش تحویل داده شد',
          message: `سفارش ${order.orderNumber} با موفقیت تحویل داده شد.`,
          type: 'success'
        },
        cancelled: {
          title: 'سفارش لغو شد',
          message: `سفارش ${order.orderNumber} لغو شد.`,
          type: 'warning'
        }
      };
      
      const notification = notifications[event];
      if (!notification) return;
      
      // ارسال ایمیل
      await orderService.sendEmailNotification(order, notification);
      
      // ارسال پیامک
      await orderService.sendSMSNotification(order, notification);
      
      // ارسال نوتیفیکیشن درون‌برنامه‌ای (در صورت وجود)
      await orderService.sendPushNotification(order, notification);
      
      logger.info(`نوتیفیکیشن سفارش ارسال شد`, {
        orderId: order._id,
        orderNumber: order.orderNumber,
        event,
        userId: order.user
      });
      
    } catch (error) {
      logger.error('خطا در ارسال نوتیفیکیشن:', error);
      // این خطا نباید فرآیند اصلی را مختل کند
    }
  },
  
  /**
   * ارسال ایمیل نوتیفیکیشن
   */
  sendEmailNotification: async (order, notification) => {
    // پیاده‌سازی ارسال ایمیل
    // می‌توان از سرویس‌هایی مثل SendGrid, Mailgun, یا SMTP مستقیم استفاده کرد
  },
  
  /**
   * ارسال پیامک نوتیفیکیشن
   */
  sendSMSNotification: async (order, notification) => {
    // پیاده‌سازی ارسال پیامک
    // می‌توان از سرویس‌های ایرانی مثل پیامک، کاوه‌نگار، یا سیگنال استفاده کرد
  },
  
  /**
   * ارسال نوتیفیکیشن درون‌برنامه‌ای
   */
  sendPushNotification: async (order, notification) => {
    // پیاده‌سازی ارسال push notification
    // می‌توان از FCM (Firebase Cloud Messaging) استفاده کرد
  },
  
  /**
   * دریافت آمار مدیریتی
   * @returns {Promise<Object>} - آمار ادمین
   */
  getAdminStatistics: async () => {
    try {
      const stats = await Order.aggregate([
        {
          $facet: {
            // آمار روزانه
            dailyStats: [
              {
                $group: {
                  _id: {
                    year: { $year: '$createdAt' },
                    month: { $month: '$createdAt' },
                    day: { $dayOfMonth: '$createdAt' }
                  },
                  count: { $sum: 1 },
                  revenue: { $sum: '$totalAmount' }
                }
              },
              { $sort: { '_id.year': -1, '_id.month': -1, '_id.day': -1 } },
              { $limit: 7 }
            ],
            
            // آمار بر اساس استان
            provinceStats: [
              {
                $group: {
                  _id: '$shippingAddress.province',
                  count: { $sum: 1 },
                  revenue: { $sum: '$totalAmount' }
                }
              },
              { $sort: { count: -1 } },
              { $limit: 5 }
            ],
            
            // آمار بر اساس محصول
            productStats: [
              { $unwind: '$items' },
              {
                $group: {
                  _id: '$items.product',
                  productName: { $first: '$items.productName' },
                  quantity: { $sum: '$items.quantity' },
                  revenue: { $sum: '$items.totalPrice' },
                  orderCount: { $sum: 1 }
                }
              },
              { $sort: { quantity: -1 } },
              { $limit: 10 }
            ],
            
            // آمار بازگشت وجه
            refundStats: [
              { $match: { 'payment.status': 'refunded' } },
              {
                $group: {
                  _id: null,
                  count: { $sum: 1 },
                  amount: { $sum: '$payment.amount' }
                }
              }
            ]
          }
        }
      ]);
      
      return {
        dailyStats: stats[0]?.dailyStats || [],
        provinceStats: stats[0]?.provinceStats || [],
        productStats: stats[0]?.productStats || [],
        refundStats: stats[0]?.refundStats[0] || { count: 0, amount: 0 }
      };
      
    } catch (error) {
      logger.error('خطا در دریافت آمار ادمین:', error);
      return {};
    }
  },
  
  /**
   * گزارش‌گیری سفارشات
   * @param {Object} filters - فیلترها
   * @returns {Promise<Array>} - گزارش
   */
  generateOrderReport: async (filters = {}) => {
    try {
      const match = { isDeleted: false, ...filters };
      
      const orders = await Order.find(match)
        .populate('user', 'name email phone')
        .populate('items.product', 'name categoryFa')
        .sort('-createdAt')
        .lean();
      
      // فرمت گزارش
      const report = orders.map(order => ({
        orderNumber: order.orderNumber,
        customer: {
          name: order.user?.name || 'ناشناس',
          phone: order.shippingAddress.recipientPhone
        },
        items: order.items.map(item => ({
          name: item.productName,
          quantity: item.quantity,
          unitPrice: item.finalUnitPrice,
          total: item.totalPrice
        })),
        totals: {
          subtotal: order.subtotal,
          discount: order.discount,
          shipping: order.shippingCost,
          tax: order.tax || 0,
          total: order.totalAmount
        },
        status: order.status,
        statusFa: order.statusFa,
        orderedAt: order.timeline.orderedAt,
        paidAt: order.timeline.paidAt,
        deliveredAt: order.timeline.deliveredAt,
        shippingAddress: {
          province: order.shippingAddress.province,
          city: order.shippingAddress.city,
          address: order.shippingAddress.address
        },
        payment: {
          method: order.payment.method,
          status: order.payment.status,
          amount: order.payment.amount
        }
      }));
      
      return report;
      
    } catch (error) {
      logger.error('خطا در تولید گزارش سفارشات:', error);
      throw error;
    }
  }
};

module.exports = orderService;