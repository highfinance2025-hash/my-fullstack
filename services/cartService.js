/**
 * @file سرویس سبد خرید HTLand
 * @description منطق کسب‌وکار و عملیات مربوط به سبد خرید
 */

const Cart = require('../models/Cart.model');
const Product = require('../models/Product.model');
const AppError = require('../utils/AppError');
const logger = require('../utils/logger');

/**
 * سرویس مدیریت سبد خرید
 */
const cartService = {
  
  /**
   * بررسی موجودی تمام محصولات در سبد خرید
   * @param {Object} cart - سبد خرید
   * @returns {Promise<Object>} - نتیجه اعتبارسنجی
   */
  validateCartItems: async (cart) => {
    const invalidItems = [];
    let allValid = true;
    
    for (const item of cart.items) {
      try {
        const product = await Product.findById(item.productId);
        
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
            productId: item.productId,
            reason: 'محصول غیرفعال شده است',
            itemName: product.name
          });
          allValid = false;
          continue;
        }
        
        if (!product.inStock) {
          invalidItems.push({
            productId: item.productId,
            reason: 'محصول موجود نیست',
            itemName: product.name
          });
          allValid = false;
          continue;
        }
        
        if (product.stock < item.quantity) {
          invalidItems.push({
            productId: item.productId,
            reason: `موجودی کافی نیست (موجودی: ${product.stock})`,
            itemName: product.name,
            requested: item.quantity,
            available: product.stock
          });
          allValid = false;
        }
        
        // بررسی تغییر قیمت
        const currentFinalPrice = product.discountPrice || product.price;
        if (currentFinalPrice !== item.finalPriceAtTime) {
          // قیمت تغییر کرده، اما خطا نیست - فقط اطلاع می‌دهیم
          logger.info(`قیمت محصول تغییر کرده`, {
            productId: product._id,
            oldPrice: item.finalPriceAtTime,
            newPrice: currentFinalPrice
          });
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
      totalItems: cart.items.length,
      validItems: cart.items.length - invalidItems.length
    };
  },
  
  /**
   * همگام‌سازی سبد خرید با اطلاعات به‌روز محصولات
   * @param {Object} cart - سبد خرید
   * @returns {Promise<Object>} - نتیجه همگام‌سازی
   */
  syncCartWithProducts: async (cart) => {
    const updatedItems = [];
    const removedItems = [];
    
    for (let i = cart.items.length - 1; i >= 0; i--) {
      const item = cart.items[i];
      
      try {
        const product = await Product.findById(item.productId);
        
        if (!product || !product.active) {
          // محصول حذف یا غیرفعال شده
          removedItems.push({
            productId: item.productId,
            productName: item.productName,
            reason: !product ? 'حذف شده' : 'غیرفعال شده'
          });
          cart.items.splice(i, 1);
          continue;
        }
        
        // به‌روزرسانی اطلاعات محصول
        const needsUpdate = 
          item.productName !== product.name ||
          item.productImage !== product.image ||
          item.category !== product.category;
        
        if (needsUpdate) {
          updatedItems.push({
            productId: product._id,
            oldName: item.productName,
            newName: product.name
          });
          
          item.productName = product.name;
          item.productImage = product.image;
          item.category = product.category;
        }
        
        // به‌روزرسانی وضعیت موجودی
        item.productAvailable = product.inStock;
        item.productActive = product.active;
        
        // به‌روزرسانی قیمت‌ها
        const currentPrice = product.price;
        const currentFinalPrice = product.discountPrice || product.price;
        
        if (item.priceAtTime !== currentPrice || 
            item.finalPriceAtTime !== currentFinalPrice) {
          
          item.priceAtTime = currentPrice;
          item.finalPriceAtTime = currentFinalPrice;
          
          if (!updatedItems.find(ui => ui.productId.equals(product._id))) {
            updatedItems.push({
              productId: product._id,
              priceUpdated: true,
              oldPrice: item.finalPriceAtTime,
              newPrice: currentFinalPrice
            });
          }
        }
        
      } catch (error) {
        logger.error(`خطا در همگام‌سازی محصول ${item.productId}:`, error);
      }
    }
    
    // ذخیره تغییرات
    if (updatedItems.length > 0 || removedItems.length > 0) {
      await cart.save();
    }
    
    return {
      updatedItems,
      removedItems,
      cartUpdated: updatedItems.length > 0 || removedItems.length > 0
    };
  },
  
  /**
   * محاسبه جمع کل سبد خرید
   * @param {Array} items - آیتم‌های سبد خرید
   * @returns {Object} - محاسبات مالی
   */
  calculateCartTotals: (items) => {
    let subtotal = 0;
    let totalDiscount = 0;
    let totalItems = 0;
    
    items.forEach(item => {
      const itemTotal = item.finalPriceAtTime * item.quantity;
      subtotal += itemTotal;
      totalItems += item.quantity;
      
      // محاسبه تخفیف آیتم
      if (item.priceAtTime > item.finalPriceAtTime) {
        totalDiscount += (item.priceAtTime - item.finalPriceAtTime) * item.quantity;
      }
    });
    
    return {
      subtotal,
      totalDiscount,
      totalItems,
      formatted: {
        subtotal: subtotal.toLocaleString('fa-IR'),
        totalDiscount: totalDiscount.toLocaleString('fa-IR'),
        totalItems: totalItems.toLocaleString('fa-IR')
      }
    };
  },
  
  /**
   * بررسی امکان پرداخت با کیف پول
   * @param {string} userId - شناسه کاربر
   * @param {number} requiredAmount - مبلغ مورد نیاز
   * @returns {Promise<Object>} - وضعیت پرداخت
   */
  checkWalletPayment: async (userId, requiredAmount) => {
    try {
      // در اینجا باید به سرویس کیف پول متصل شویم
      // برای نمونه، یک شبیه‌سازی:
      
      // این آدرس باید از config خوانده شود
      const walletServiceUrl = process.env.WALLET_SERVICE_URL || 'http://localhost:3001';
      
      // در محیط واقعی:
      // const response = await fetch(`${walletServiceUrl}/api/v1/wallet/balance/${userId}`);
      // const walletData = await response.json();
      
      // برای نمونه:
      const walletData = {
        success: true,
        data: {
          balance: 500000, // موجودی نمونه
          currency: 'تومان'
        }
      };
      
      const hasSufficientBalance = walletData.data.balance >= requiredAmount;
      
      return {
        canPay: hasSufficientBalance,
        walletBalance: walletData.data.balance,
        requiredAmount,
        deficit: hasSufficientBalance ? 0 : requiredAmount - walletData.data.balance,
        currency: walletData.data.currency
      };
      
    } catch (error) {
      logger.error('خطا در بررسی کیف پول:', error);
      return {
        canPay: false,
        error: 'خطا در ارتباط با سرویس کیف پول',
        walletBalance: 0,
        requiredAmount,
        deficit: requiredAmount,
        currency: 'تومان'
      };
    }
  },
  
  /**
   * پردازش خرید با کیف پول
   * @param {string} userId - شناسه کاربر
   * @param {string} cartId - شناسه سبد خرید
   * @param {number} amount - مبلغ پرداخت
   * @returns {Promise<Object>} - نتیجه پرداخت
   */
  processWalletPayment: async (userId, cartId, amount) => {
    try {
      // یافتن سبد خرید
      const cart = await Cart.findOne({ _id: cartId, user: userId, status: 'active' });
      
      if (!cart) {
        throw new AppError('سبد خرید یافت نشد', 404);
      }
      
      // بررسی مجدد موجودی محصولات
      const validation = await cartService.validateCartItems(cart);
      
      if (!validation.valid) {
        throw new AppError(
          'برخی محصولات موجود نیستند',
          400,
          { invalidItems: validation.invalidItems }
        );
      }
      
      // درخواست کسر از کیف پول
      // در محیط واقعی:
      // const paymentResponse = await fetch(`${walletServiceUrl}/api/v1/wallet/pay`, {
      //   method: 'POST',
      //   headers: { 'Content-Type': 'application/json' },
      //   body: JSON.stringify({
      //     userId,
      //     amount,
      //     description: `پرداخت سبد خرید ${cartId}`,
      //     referenceId: cartId
      //   })
      // });
      
      // برای نمونه، پرداخت موفق:
      const paymentResult = {
        success: true,
        transactionId: `txn_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        remainingBalance: 250000,
        timestamp: new Date().toISOString()
      };
      
      if (!paymentResult.success) {
        throw new AppError('پرداخت ناموفق بود', 400);
      }
      
      // تغییر وضعیت سبد خرید به "تبدیل شده به سفارش"
      cart.status = 'converted_to_order';
      cart.expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 روز
      await cart.save();
      
      // کاهش موجودی محصولات
      await cartService.decreaseProductStocks(cart.items);
      
      logger.info(`پرداخت با کیف پول موفق بود`, {
        userId,
        cartId,
        amount,
        transactionId: paymentResult.transactionId,
        itemsCount: cart.items.length
      });
      
      return {
        success: true,
        transactionId: paymentResult.transactionId,
        cartId,
        amount,
        items: cart.items.map(item => ({
          productId: item.productId,
          productName: item.productName,
          quantity: item.quantity,
          price: item.finalPriceAtTime
        })),
        remainingBalance: paymentResult.remainingBalance,
        orderCreated: true
      };
      
    } catch (error) {
      logger.error('خطا در پردازش پرداخت کیف پول:', error);
      throw error;
    }
  },
  
  /**
   * کاهش موجودی محصولات پس از خرید موفق
   * @param {Array} items - آیتم‌های خریداری شده
   * @returns {Promise<void>}
   */
  decreaseProductStocks: async (items) => {
    const session = await Product.startSession();
    
    try {
      session.startTransaction();
      
      for (const item of items) {
        const product = await Product.findById(item.productId).session(session);
        
        if (!product) {
          throw new AppError(`محصول ${item.productId} یافت نشد`, 404);
        }
        
        if (product.stock < item.quantity) {
          throw new AppError(
            `موجودی محصول ${product.name} کافی نیست`,
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
   * انتقال سبد خرید بین دستگاه‌ها
   * @param {string} userId - شناسه کاربر
   * @param {Object} deviceInfo - اطلاعات دستگاه جدید
   * @returns {Promise<Object>} - نتیجه انتقال
   */
  transferCartToDevice: async (userId, deviceInfo) => {
    const cart = await Cart.findOne({ user: userId, status: 'active' });
    
    if (!cart) {
      return { transferred: false, message: 'سبد خرید یافت نشد' };
    }
    
    // به‌روزرسانی اطلاعات دستگاه
    cart.userIp = deviceInfo.ip;
    cart.userAgent = deviceInfo.userAgent;
    cart.expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    
    await cart.save();
    
    logger.info(`سبد خرید به دستگاه جدید انتقال یافت`, {
      userId,
      cartId: cart._id,
      newDevice: deviceInfo.userAgent?.substr(0, 50)
    });
    
    return {
      transferred: true,
      cartId: cart._id,
      itemsCount: cart.items.length,
      totalAmount: cart.totalAmount,
      deviceUpdated: true
    };
  },
  
  /**
   * پاکسازی سبد خرید‌های منقضی شده
   * @returns {Promise<Object>} - نتیجه پاکسازی
   */
  cleanupExpiredCarts: async () => {
    try {
      const expiredDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      
      const result = await Cart.deleteMany({
        status: 'active',
        updatedAt: { $lt: expiredDate }
      });
      
      logger.info(`سبد خرید‌های منقضی پاکسازی شدند`, {
        deletedCount: result.deletedCount
      });
      
      return {
        cleaned: true,
        deletedCount: result.deletedCount,
        message: `${result.deletedCount} سبد خرید منقضی پاکسازی شد`
      };
    } catch (error) {
      logger.error('خطا در پاکسازی سبد خرید‌های منقضی:', error);
      return {
        cleaned: false,
        error: error.message
      };
    }
  },
  
  /**
   * دریافت آمار سبد خرید
   * @returns {Promise<Object>} - آمار سبد خرید
   */
  getCartStatistics: async () => {
    try {
      const stats = await Cart.aggregate([
        {
          $facet: {
            totalCarts: [
              { $count: 'count' }
            ],
            activeCarts: [
              { $match: { status: 'active' } },
              { $count: 'count' }
            ],
            averageItems: [
              { $match: { status: 'active' } },
              {
                $group: {
                  _id: null,
                  avgItems: { $avg: '$totalItems' },
                  avgAmount: { $avg: '$totalAmount' }
                }
              }
            ],
            topProducts: [
              { $unwind: '$items' },
              {
                $group: {
                  _id: '$items.productId',
                  productName: { $first: '$items.productName' },
                  totalQuantity: { $sum: '$items.quantity' },
                  cartCount: { $sum: 1 }
                }
              },
              { $sort: { totalQuantity: -1 } },
              { $limit: 10 }
            ]
          }
        }
      ]);
      
      return {
        success: true,
        data: {
          totalCarts: stats[0]?.totalCarts[0]?.count || 0,
          activeCarts: stats[0]?.activeCarts[0]?.count || 0,
          averageItems: stats[0]?.averageItems[0]?.avgItems || 0,
          averageAmount: stats[0]?.averageItems[0]?.avgAmount || 0,
          topProducts: stats[0]?.topProducts || []
        }
      };
    } catch (error) {
      logger.error('خطا در دریافت آمار سبد خرید:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }
};

module.exports = cartService;