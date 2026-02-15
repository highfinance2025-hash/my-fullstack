/**
 * @file سرویس محصولات HTLand
 * @description منطق کسب‌وکار و عملیات مربوط به محصولات
 */

const Product = require('../models/Product.model');
const cloudinary = require('../config/cloudinary');
const AppError = require('../utils/AppError');
const logger = require('../utils/logger');

/**
 * سرویس مدیریت محصولات
 */
const productService = {
  
  /**
   * آپلود تصویر به Cloudinary
   * @param {Object} file - فایل آپلود شده توسط multer
   * @returns {Promise<string>} - آدرس تصویر در CDN
   */
  uploadImage: async (file) => {
    try {
      if (!file) {
        throw new AppError('فایل تصویر ارسال نشده است', 400);
      }
      
      // آپلود به Cloudinary
      const result = await cloudinary.uploader.upload(file.path, {
        folder: 'htland/products',
        use_filename: true,
        unique_filename: true,
        overwrite: false,
        transformation: [
          { width: 800, height: 800, crop: 'limit' },
          { quality: 'auto:good' },
          { format: 'webp' }
        ]
      });
      
      logger.info(`تصویر با موفقیت آپلود شد: ${result.public_id}`);
      
      return result.secure_url;
    } catch (error) {
      logger.error(`خطا در آپلود تصویر: ${error.message}`);
      throw new AppError('خطا در آپلود تصویر', 500);
    }
  },
  
  /**
   * حذف تصویر از Cloudinary
   * @param {string} imageUrl - آدرس تصویر
   * @returns {Promise<void>}
   */
  deleteImage: async (imageUrl) => {
    try {
      // استخراج public_id از URL
      const publicId = imageUrl.match(/\/upload\/v\d+\/(.+?)\./)?.[1];
      
      if (!publicId) {
        logger.warn(`آدرس تصویر نامعتبر برای حذف: ${imageUrl}`);
        return;
      }
      
      await cloudinary.uploader.destroy(publicId);
      logger.info(`تصویر حذف شد: ${publicId}`);
    } catch (error) {
      logger.error(`خطا در حذف تصویر: ${error.message}`);
      // پرتاب نکنیم چون حذف تصویر نباید عملیات اصلی را مختل کند
    }
  },
  
  /**
   * ایجاد slug یکتا از نام محصول
   * @param {string} name - نام محصول
   * @param {string} excludeId - شناسه محصول برای حذف از بررسی تکراری بودن
   * @returns {Promise<string>} - slug یکتا
   */
  generateSlug: async (name, excludeId = null) => {
    const slugify = (await import('slugify')).default;
    
    let slug = slugify(name, {
      replacement: '-',
      remove: /[*+~.()'"!:@]/g,
      lower: true,
      strict: true,
      locale: 'fa'
    });
    
    // بررسی تکراری نبودن
    let counter = 1;
    let originalSlug = slug;
    
    while (true) {
      const existing = await Product.findOne({
        slug,
        _id: { $ne: excludeId }
      });
      
      if (!existing) {
        break;
      }
      
      slug = `${originalSlug}-${counter}`;
      counter++;
    }
    
    return slug;
  },
  
  /**
   * اعتبارسنجی موجودی برای سفارش
   * @param {string} productId - شناسه محصول
   * @param {number} quantity - تعداد مورد نیاز
   * @returns {Promise<Object>} - اطلاعات محصول و وضعیت موجودی
   */
  validateStock: async (productId, quantity) => {
    const product = await Product.findOne({
      _id: productId,
      active: true,
      inStock: true
    });
    
    if (!product) {
      throw new AppError('محصول یافت نشد یا موجود نیست', 404);
    }
    
    if (product.stock < quantity) {
      throw new AppError(
        `موجودی محصول "${product.name}" کافی نیست. موجودی: ${product.stock}`,
        400
      );
    }
    
    return {
      product,
      available: true,
      stock: product.stock
    };
  },
  
  /**
   * کاهش موجودی چند محصول
   * @param {Array} items - آرایه‌ای از آیتم‌های سفارش
   * @returns {Promise<void>}
   */
  decreaseMultipleStocks: async (items) => {
    const session = await Product.startSession();
    
    try {
      session.startTransaction();
      
      for (const item of items) {
        const product = await Product.findById(item.productId).session(session);
        
        if (!product) {
          throw new AppError(`محصول با شناسه ${item.productId} یافت نشد`, 404);
        }
        
        if (product.stock < item.quantity) {
          throw new AppError(
            `موجودی محصول "${product.name}" کافی نیست. موجودی: ${product.stock}, درخواست: ${item.quantity}`,
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
      throw error;
    } finally {
      session.endSession();
    }
  },
  
  /**
   * افزایش موجودی محصول
   * @param {string} productId - شناسه محصول
   * @param {number} quantity - تعداد
   * @returns {Promise<void>}
   */
  increaseStock: async (productId, quantity) => {
    const product = await Product.findById(productId);
    
    if (!product) {
      throw new AppError('محصول یافت نشد', 404);
    }
    
    product.stock += quantity;
    product.inStock = true;
    await product.save();
    
    logger.info(`موجودی محصول "${product.name}" افزایش یافت`, {
      productId,
      quantity,
      newStock: product.stock
    });
  },
  
  /**
   * محاسبه قیمت نهایی محصول
   * @param {Object} product - شیء محصول
   * @returns {number} - قیمت نهایی
   */
  calculateFinalPrice: (product) => {
    return product.discountPrice && product.discountPrice > 0
      ? product.discountPrice
      : product.price;
  },
  
  /**
   * محاسبه درصد تخفیف
   * @param {Object} product - شیء محصول
   * @returns {number} - درصد تخفیف
   */
  calculateDiscountPercentage: (product) => {
    if (!product.discountPrice || product.discountPrice >= product.price) {
      return 0;
    }
    return Math.round(((product.price - product.discountPrice) / product.price) * 100);
  },
  
  /**
   * فرمت محصول برای نمایش در فرانت‌اند
   * @param {Object} product - محصول از دیتابیس
   * @returns {Object} - محصول فرمت شده
   */
  formatForFrontend: (product) => {
    const finalPrice = productService.calculateFinalPrice(product);
    const discountPercentage = productService.calculateDiscountPercentage(product);
    
    return {
      id: product._id,
      name: product.name,
      slug: product.slug,
      description: product.description,
      shortDescription: product.shortDescription,
      price: product.price,
      discountPrice: product.discountPrice,
      finalPrice,
      discountPercentage,
      category: product.category,
      categoryFa: product.categoryFa,
      image: product.image,
      gallery: product.gallery || [],
      stock: product.stock,
      inStock: product.inStock,
      featured: product.featured,
      tags: product.tags || [],
      specifications: product.specifications || {},
      rating: product.rating,
      reviewsCount: product.reviewsCount,
      views: product.views,
      createdAt: product.createdAt,
      updatedAt: product.updatedAt
    };
  },
  
  /**
   * تولید اطلاعات متا برای SEO
   * @param {Object} product - محصول
   * @returns {Object} - اطلاعات متا
   */
  generateMetaData: (product) => {
    return {
      title: `${product.name} - HTLand | سرزمین مزه سالم`,
      description: product.shortDescription || product.description.substring(0, 160),
      keywords: [
        ...(product.tags || []),
        product.categoryFa,
        'خرید آنلاین',
        'محصولات ارگانیک شمال',
        'برنج شمال',
        'خاویار ایرانی',
        'ماهی تازه شمال',
        'عسل طبیعی',
        'مرغ محلی',
        'سوغات شمال'
      ].join(', '),
      ogImage: product.image,
      canonical: `/products/${product.slug}`,
      product: {
        name: product.name,
        price: product.finalPrice,
        currency: 'IRR',
        availability: product.inStock ? 'in_stock' : 'out_of_stock',
        category: product.categoryFa
      }
    };
  },
  
  /**
   * به‌روزرسانی امتیاز محصول
   * @param {string} productId - شناسه محصول
   * @returns {Promise<void>}
   */
  updateProductRating: async (productId) => {
    const Review = require('../models/Review.model');
    
    const stats = await Review.aggregate([
      { $match: { product: productId, approved: true } },
      {
        $group: {
          _id: '$product',
          averageRating: { $avg: '$rating' },
          reviewCount: { $sum: 1 }
        }
      }
    ]);
    
    if (stats.length > 0) {
      await Product.findByIdAndUpdate(productId, {
        rating: Math.round(stats[0].averageRating * 10) / 10,
        reviewsCount: stats[0].reviewCount
      });
    }
  },
  
  /**
   * دریافت محصولات مرتبط
   * @param {Object} product - محصول اصلی
   * @param {number} limit - تعداد محصولات مرتبط
   * @returns {Promise<Array>} - محصولات مرتبط
   */
  getRelatedProducts: async (product, limit = 4) => {
    return await Product.find({
      _id: { $ne: product._id },
      category: product.category,
      active: true,
      inStock: true
    })
    .limit(limit)
    .select('name slug price discountPrice image categoryFa rating')
    .sort('-rating -createdAt');
  }
};

module.exports = productService;