/**
 * @file کنترلر محصولات HTLand
 * @description مدیریت کامل عملیات CRUD محصولات
 */

const Product = require('../models/Product.model');
const productService = require('../services/productService');
const asyncHandler = require('../utils/asyncHandler');
const AppError = require('../utils/AppError');
const logger = require('../utils/logger');

/**
 * کنترلر محصولات
 */
const productController = {
  
  /**
   * دریافت لیست محصولات با فیلتر، صفحه‌بندی و جستجو
   * @route GET /api/v1/products
   * @access عمومی
   */
  getAllProducts: asyncHandler(async (req, res, next) => {
    const {
      page = 1,
      limit = 12,
      category,
      categoryFa,
      inStock,
      featured,
      minPrice,
      maxPrice,
      sort = '-createdAt',
      search,
      tags
    } = req.query;
    
    // ساخت فیلترهای جستجو
    const filter = { active: true };
    
    if (category) filter.category = category;
    if (categoryFa) filter.categoryFa = categoryFa;
    if (inStock !== undefined) filter.inStock = inStock === 'true';
    if (featured !== undefined) filter.featured = featured === 'true';
    if (tags) filter.tags = { $in: tags.split(',') };
    
    // فیلتر قیمت
    if (minPrice || maxPrice) {
      filter.$and = [];
      if (minPrice) filter.$and.push({ price: { $gte: Number(minPrice) } });
      if (maxPrice) filter.$and.push({ price: { $lte: Number(maxPrice) } });
    }
    
    // جستجوی متنی
    if (search) {
      filter.$text = { $search: search };
    }
    
    // گزینه‌های صفحه‌بندی
    const options = {
      page: parseInt(page),
      limit: parseInt(limit),
      sort,
      select: '-__v -createdBy -updatedBy -metadata',
      populate: []
    };
    
    // اجرای کوئری با صفحه‌بندی
    const products = await Product.paginate(filter, options);
    
    logger.info(`تعداد ${products.docs.length} محصول دریافت شد`, {
      page,
      limit,
      filter,
      user: req.user?._id
    });
    
    // فرمت پاسخ
    const response = {
      success: true,
      message: 'لیست محصولات با موفقیت دریافت شد',
      data: products.docs.map(product => ({
        ...product.toObject(),
        discountPercentage: product.discountPercentage,
        finalPrice: product.finalPrice
      })),
      pagination: {
        total: products.totalDocs,
        limit: products.limit,
        page: products.page,
        pages: products.totalPages,
        hasNext: products.hasNextPage,
        hasPrev: products.hasPrevPage
      }
    };
    
    res.status(200).json(response);
  }),
  
  /**
   * دریافت یک محصول با شناسه یا slug
   * @route GET /api/v1/products/:id
   * @access عمومی
   */
  getProductById: asyncHandler(async (req, res, next) => {
    const { id } = req.params;
    
    // افزایش تعداد بازدید
    await Product.findByIdAndUpdate(id, { $inc: { views: 1 } });
    
    // پیدا کردن محصول
    const product = await Product.findOne({
      $or: [
        { _id: id },
        { slug: id }
      ],
      active: true
    }).select('-__v');
    
    if (!product) {
      return next(new AppError('محصول یافت نشد', 404));
    }
    
    logger.info(`محصول "${product.name}" مشاهده شد`, {
      productId: product._id,
      userId: req.user?._id
    });
    
    res.status(200).json({
      success: true,
      message: 'محصول با موفقیت دریافت شد',
      data: {
        ...product.toObject(),
        discountPercentage: product.discountPercentage,
        finalPrice: product.finalPrice
      }
    });
  }),
  
  /**
   * ایجاد محصول جدید
   * @route POST /api/v1/products
   * @access خصوصی (فقط ادمین)
   */
  createProduct: asyncHandler(async (req, res, next) => {
    if (!req.user.isAdmin) {
      return next(new AppError('شما مجوز ایجاد محصول را ندارید', 403));
    }
    
    const productData = req.body;
    const userId = req.user._id;
    
    // اضافه کردن اطلاعات کاربر
    productData.createdBy = userId;
    productData.updatedBy = userId;
    
    // آپلود تصویر اگر وجود دارد
    if (req.file) {
      productData.image = await productService.uploadImage(req.file);
    }
    
    // آپلود گالری اگر وجود دارد
    if (req.files && req.files.gallery) {
      productData.gallery = await Promise.all(
        req.files.gallery.map(file => productService.uploadImage(file))
      );
    }
    
    // ایجاد محصول
    const product = await Product.create(productData);
    
    logger.info(`محصول جدید "${product.name}" ایجاد شد`, {
      productId: product._id,
      userId,
      category: product.category
    });
    
    res.status(201).json({
      success: true,
      message: 'محصول با موفقیت ایجاد شد',
      data: product
    });
  }),
  
  /**
   * به‌روزرسانی محصول
   * @route PUT /api/v1/products/:id
   * @access خصوصی (فقط ادمین)
   */
  updateProduct: asyncHandler(async (req, res, next) => {
    if (!req.user.isAdmin) {
      return next(new AppError('شما مجوز ویرایش محصول را ندارید', 403));
    }
    
    const { id } = req.params;
    const updateData = req.body;
    const userId = req.user._id;
    
    // اضافه کردن اطلاعات ویرایش‌کننده
    updateData.updatedBy = userId;
    
    // پیدا کردن محصول
    const product = await Product.findById(id);
    if (!product) {
      return next(new AppError('محصول یافت نشد', 404));
    }
    
    // آپلود تصویر جدید اگر وجود دارد
    if (req.file) {
      // حذف تصویر قبلی از CDN
      if (product.image) {
        await productService.deleteImage(product.image);
      }
      updateData.image = await productService.uploadImage(req.file);
    }
    
    // آپلود گالری جدید اگر وجود دارد
    if (req.files && req.files.gallery) {
      // حذف گالری قبلی از CDN
      if (product.gallery && product.gallery.length > 0) {
        await Promise.all(product.gallery.map(img => productService.deleteImage(img)));
      }
      updateData.gallery = await Promise.all(
        req.files.gallery.map(file => productService.uploadImage(file))
      );
    }
    
    // به‌روزرسانی محصول
    const updatedProduct = await Product.findByIdAndUpdate(
      id,
      updateData,
      { new: true, runValidators: true }
    ).select('-__v');
    
    logger.info(`محصول "${updatedProduct.name}" به‌روزرسانی شد`, {
      productId: updatedProduct._id,
      userId,
      updates: Object.keys(updateData)
    });
    
    res.status(200).json({
      success: true,
      message: 'محصول با موفقیت به‌روزرسانی شد',
      data: updatedProduct
    });
  }),
  
  /**
   * حذف محصول (غیرفعال کردن)
   * @route DELETE /api/v1/products/:id
   * @access خصوصی (فقط ادمین)
   */
  deleteProduct: asyncHandler(async (req, res, next) => {
    if (!req.user.isAdmin) {
      return next(new AppError('شما مجوز حذف محصول را ندارید', 403));
    }
    
    const { id } = req.params;
    const userId = req.user._id;
    
    // پیدا کردن محصول
    const product = await Product.findById(id);
    if (!product) {
      return next(new AppError('محصول یافت نشد', 404));
    }
    
    // غیرفعال کردن محصول (Soft Delete)
    product.active = false;
    product.updatedBy = userId;
    await product.save();
    
    logger.info(`محصول "${product.name}" غیرفعال شد`, {
      productId: product._id,
      userId
    });
    
    res.status(200).json({
      success: true,
      message: 'محصول با موفقیت غیرفعال شد'
    });
  }),
  
  /**
   * دریافت محصولات ویژه
   * @route GET /api/v1/products/featured
   * @access عمومی
   */
  getFeaturedProducts: asyncHandler(async (req, res, next) => {
    const { limit = 8 } = req.query;
    
    const products = await Product.find({
      featured: true,
      active: true,
      inStock: true
    })
    .sort('-createdAt')
    .limit(parseInt(limit))
    .select('name slug price discountPrice image category categoryFa rating inStock');
    
    // افزودن محاسبات قیمت
    const formattedProducts = products.map(product => ({
      ...product.toObject(),
      discountPercentage: product.discountPercentage,
      finalPrice: product.finalPrice
    }));
    
    res.status(200).json({
      success: true,
      message: 'محصولات ویژه با موفقیت دریافت شدند',
      data: formattedProducts
    });
  }),
  
  /**
   * جستجوی پیشرفته محصولات
   * @route GET /api/v1/products/search
   * @access عمومی
   */
  searchProducts: asyncHandler(async (req, res, next) => {
    const { q, category, minPrice, maxPrice, inStock, sort = 'relevance' } = req.query;
    
    if (!q) {
      return next(new AppError('عبارت جستجو الزامی است', 400));
    }
    
    // ساخت فیلترها
    const filters = {};
    if (category) filters.category = category;
    if (inStock !== undefined) filters.inStock = inStock === 'true';
    if (minPrice || maxPrice) {
      filters.price = {};
      if (minPrice) filters.price.$gte = Number(minPrice);
      if (maxPrice) filters.price.$lte = Number(maxPrice);
    }
    
    // اجرای جستجو
    const products = await Product.search(q, filters);
    
    logger.info(`جستجوی "${q}" انجام شد. ${products.length} نتیجه یافت شد`, {
      query: q,
      filters,
      results: products.length
    });
    
    res.status(200).json({
      success: true,
      message: 'نتایج جستجو',
      data: products.map(product => ({
        ...product.toObject(),
        discountPercentage: product.discountPercentage,
        finalPrice: product.finalPrice
      }))
    });
  }),
  
  /**
   * دریافت دسته‌بندی‌ها و تعداد محصولات
   * @route GET /api/v1/products/categories/stats
   * @access عمومی
   */
  getCategoryStats: asyncHandler(async (req, res, next) => {
    const stats = await Product.aggregate([
      { $match: { active: true } },
      {
        $group: {
          _id: '$category',
          count: { $sum: 1 },
          categoryFa: { $first: '$categoryFa' }
        }
      },
      { $sort: { count: -1 } }
    ]);
    
    res.status(200).json({
      success: true,
      message: 'آمار دسته‌بندی‌ها دریافت شد',
      data: stats
    });
  }),
  
  /**
   * بررسی موجودی محصول
   * @route POST /api/v1/products/:id/check-stock
   * @access عمومی
   */
  checkStock: asyncHandler(async (req, res, next) => {
    const { id } = req.params;
    const { quantity = 1 } = req.body;
    
    const product = await Product.findOne({
      $or: [{ _id: id }, { slug: id }],
      active: true
    });
    
    if (!product) {
      return next(new AppError('محصول یافت نشد', 404));
    }
    
    const available = product.inStock && product.stock >= quantity;
    
    res.status(200).json({
      success: true,
      message: available ? 'موجودی کافی است' : 'موجودی کافی نیست',
      data: {
        available,
        inStock: product.inStock,
        stock: product.stock,
        requested: quantity,
        hasEnough: product.stock >= quantity
      }
    });
  }),
  
  /**
   * کاهش موجودی (پس از سفارش)
   * @route POST /api/v1/products/:id/decrease-stock
   * @access خصوصی (سیستم سفارشات)
   */
  decreaseStock: asyncHandler(async (req, res, next) => {
    const { id } = req.params;
    const { quantity } = req.body;
    
    if (!quantity || quantity <= 0) {
      return next(new AppError('تعداد معتبر نیست', 400));
    }
    
    const product = await Product.findById(id);
    if (!product) {
      return next(new AppError('محصول یافت نشد', 404));
    }
    
    if (product.stock < quantity) {
      return next(new AppError('موجودی کافی نیست', 400));
    }
    
    product.stock -= quantity;
    product.inStock = product.stock > 0;
    await product.save();
    
    logger.info(`موجودی محصول "${product.name}" کاهش یافت`, {
      productId: product._id,
      quantity,
      remainingStock: product.stock
    });
    
    res.status(200).json({
      success: true,
      message: 'موجودی با موفقیت کاهش یافت',
      data: {
        productId: product._id,
        productName: product.name,
        newStock: product.stock,
        inStock: product.inStock
      }
    });
  })
};

module.exports = productController;