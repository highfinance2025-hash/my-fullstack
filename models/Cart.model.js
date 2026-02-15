/**
 * @file مدل سبد خرید HTLand
 * @description مدل Mongoose برای سبد خرید کاربران
 */

const mongoose = require('mongoose');

const cartItemSchema = new mongoose.Schema({
  // شناسه محصول
  productId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Product',
    required: [true, 'شناسه محصول الزامی است']
  },
  
  // تعداد محصول
  quantity: {
    type: Number,
    required: [true, 'تعداد محصول الزامی است'],
    min: [1, 'تعداد نمی‌تواند کمتر از ۱ باشد'],
    max: [99, 'تعداد نمی‌تواند بیشتر از ۹۹ باشد'],
    default: 1
  },
  
  // قیمت محصول در زمان اضافه شدن به سبد
  priceAtTime: {
    type: Number,
    required: [true, 'قیمت محصول الزامی است'],
    min: [0, 'قیمت نمی‌تواند منفی باشد']
  },
  
  // نام محصول در زمان اضافه شدن (برای نمایش در تاریخچه)
  productName: {
    type: String,
    required: [true, 'نام محصول الزامی است']
  },
  
  // تصویر محصول در زمان اضافه شدن
  productImage: {
    type: String,
    required: [true, 'تصویر محصول الزامی است']
  },
  
  // دسته‌بندی محصول
  category: {
    type: String,
    required: [true, 'دسته‌بندی محصول الزامی است']
  },
  
  // قیمت نهایی (با در نظر گرفتن تخفیف)
  finalPriceAtTime: {
    type: Number,
    required: [true, 'قیمت نهایی الزامی است'],
    min: [0, 'قیمت نهایی نمی‌تواند منفی باشد']
  },
  
  // آیا محصول هنوز موجود است؟
  productAvailable: {
    type: Boolean,
    default: true
  },
  
  // آیا محصول فعال است؟
  productActive: {
    type: Boolean,
    default: true
  }
}, { _id: false });

const cartSchema = new mongoose.Schema({
  // کاربر مالک سبد خرید
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'کاربر الزامی است'],
    unique: true,
    index: true
  },
  
  // آیتم‌های سبد خرید
  items: [cartItemSchema],
  
  // جمع کل قیمت سبد خرید (محاسبه شده)
  totalAmount: {
    type: Number,
    default: 0,
    min: [0, 'جمع کل نمی‌تواند منفی باشد']
  },
  
  // تعداد کل آیتم‌ها
  totalItems: {
    type: Number,
    default: 0
  },
  
  // تخفیف کل (اگر اعمال شود)
  totalDiscount: {
    type: Number,
    default: 0
  },
  
  // هزینه ارسال
  shippingFee: {
    type: Number,
    default: 0
  },
  
  // جمع نهایی (با احتساب هزینه ارسال)
  finalAmount: {
    type: Number,
    default: 0
  },
  
  // وضعیت سبد خرید
  status: {
    type: String,
    enum: ['active', 'converted_to_order', 'abandoned'],
    default: 'active',
    index: true
  },
  
  // زمان انقضای سبد خرید (برای پاکسازی خودکار)
  expiresAt: {
    type: Date,
    default: () => new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 روز
    index: { expireAfterSeconds: 0 }
  },
  
  // آی‌پی کاربر
  userIp: String,
  
  // اطلاعات دستگاه کاربر
  userAgent: String,
  
  // کد کوپن تخفیف
  couponCode: {
    type: String,
    trim: true,
    uppercase: true
  },
  
  // درصد تخفیف کوپن
  couponDiscount: {
    type: Number,
    min: 0,
    max: 100,
    default: 0
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Virtual برای محاسبه جمع کل
cartSchema.virtual('calculatedTotal').get(function() {
  return this.items.reduce((total, item) => {
    return total + (item.finalPriceAtTime * item.quantity);
  }, 0);
});

// Virtual برای محاسبه تعداد کل آیتم‌ها
cartSchema.virtual('calculatedItems').get(function() {
  return this.items.reduce((total, item) => total + item.quantity, 0);
});

// Middleware برای به‌روزرسانی خودکار جمع‌ها
cartSchema.pre('save', function(next) {
  this.totalAmount = this.calculatedTotal;
  this.totalItems = this.calculatedItems;
  
  // محاسبه تخفیف کل
  this.totalDiscount = this.items.reduce((total, item) => {
    const discount = (item.priceAtTime - item.finalPriceAtTime) * item.quantity;
    return total + (discount > 0 ? discount : 0);
  }, 0);
  
  // محاسبه جمع نهایی با تخفیف کوپن
  let final = this.totalAmount;
  
  if (this.couponDiscount > 0) {
    const couponDiscountAmount = (this.totalAmount * this.couponDiscount) / 100;
    final -= couponDiscountAmount;
  }
  
  // اضافه کردن هزینه ارسال
  final += this.shippingFee;
  
  this.finalAmount = Math.max(0, final);
  
  next();
});

// متدهای استاتیک
cartSchema.statics.findByUserId = function(userId) {
  return this.findOne({ user: userId, status: 'active' })
    .populate('items.productId', 'name price discountPrice image category inStock active')
    .exec();
};

cartSchema.statics.findOrCreateByUserId = async function(userId) {
  let cart = await this.findOne({ user: userId, status: 'active' });
  
  if (!cart) {
    cart = await this.create({ user: userId });
  }
  
  return cart;
};

// متدهای نمونه
cartSchema.methods.addItem = async function(product, quantity = 1) {
  const Product = require('./Product.model');
  
  // بررسی وجود محصول در سبد
  const existingItemIndex = this.items.findIndex(
    item => item.productId.toString() === product._id.toString()
  );
  
  if (existingItemIndex > -1) {
    // به‌روزرسانی تعداد
    this.items[existingItemIndex].quantity += quantity;
    
    // به‌روزرسانی قیمت‌ها در صورت تغییر
    this.items[existingItemIndex].priceAtTime = product.price;
    this.items[existingItemIndex].finalPriceAtTime = product.discountPrice || product.price;
    this.items[existingItemIndex].productAvailable = product.inStock;
    this.items[existingItemIndex].productActive = product.active;
  } else {
    // اضافه کردن آیتم جدید
    this.items.push({
      productId: product._id,
      quantity,
      priceAtTime: product.price,
      productName: product.name,
      productImage: product.image,
      category: product.category,
      finalPriceAtTime: product.discountPrice || product.price,
      productAvailable: product.inStock,
      productActive: product.active
    });
  }
  
  // محدودیت حداکثر ۲۰ محصول در سبد
  if (this.items.length > 20) {
    this.items = this.items.slice(0, 20);
  }
  
  return await this.save();
};

cartSchema.methods.removeItem = async function(productId) {
  this.items = this.items.filter(
    item => item.productId.toString() !== productId.toString()
  );
  
  return await this.save();
};

cartSchema.methods.updateItemQuantity = async function(productId, quantity) {
  const itemIndex = this.items.findIndex(
    item => item.productId.toString() === productId.toString()
  );
  
  if (itemIndex === -1) {
    throw new Error('محصول در سبد خرید یافت نشد');
  }
  
  if (quantity < 1) {
    // اگر تعداد صفر یا منفی شد، محصول حذف شود
    return await this.removeItem(productId);
  }
  
  if (quantity > 99) {
    throw new Error('حداکثر تعداد ۹۹ عدد است');
  }
  
  this.items[itemIndex].quantity = quantity;
  return await this.save();
};

cartSchema.methods.clearCart = async function() {
  this.items = [];
  return await this.save();
};

cartSchema.methods.getTotal = function() {
  return this.calculatedTotal;
};

cartSchema.methods.getSummary = function() {
  return {
    totalItems: this.calculatedItems,
    totalAmount: this.calculatedTotal,
    totalDiscount: this.totalDiscount,
    shippingFee: this.shippingFee,
    couponDiscount: this.couponDiscount,
    finalAmount: this.finalAmount,
    items: this.items.map(item => ({
      productId: item.productId,
      productName: item.productName,
      quantity: item.quantity,
      price: item.finalPriceAtTime,
      total: item.finalPriceAtTime * item.quantity,
      available: item.productAvailable,
      active: item.productActive,
      image: item.productImage
    }))
  };
};

// ایندکس‌ها برای بهبود کارایی
cartSchema.index({ user: 1, status: 1 });
cartSchema.index({ 'items.productId': 1 });
cartSchema.index({ updatedAt: -1 });

const Cart = mongoose.model('Cart', cartSchema);

module.exports = Cart;