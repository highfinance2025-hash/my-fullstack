/**
 * @file مدل سفارشات HTLand
 * @description مدل Mongoose برای سفارشات کاربران
 */

const mongoose = require('mongoose');
const mongoosePaginate = require('mongoose-paginate-v2');

const orderItemSchema = new mongoose.Schema({
  // شناسه محصول
  product: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Product',
    required: [true, 'محصول الزامی است']
  },
  
  // نام محصول در زمان سفارش
  productName: {
    type: String,
    required: [true, 'نام محصول الزامی است']
  },
  
  // تصویر محصول در زمان سفارش
  productImage: {
    type: String,
    required: [true, 'تصویر محصول الزامی است']
  },
  
  // دسته‌بندی محصول
  category: {
    type: String,
    required: [true, 'دسته‌بندی محصول الزامی است']
  },
  
  // دسته‌بندی فارسی
  categoryFa: {
    type: String,
    required: [true, 'دسته‌بندی فارسی الزامی است']
  },
  
  // تعداد
  quantity: {
    type: Number,
    required: [true, 'تعداد الزامی است'],
    min: [1, 'تعداد نمی‌تواند کمتر از ۱ باشد'],
    max: [99, 'تعداد نمی‌تواند بیشتر از ۹۹ باشد']
  },
  
  // قیمت واحد در زمان سفارش
  unitPrice: {
    type: Number,
    required: [true, 'قیمت واحد الزامی است'],
    min: [0, 'قیمت واحد نمی‌تواند منفی باشد']
  },
  
  // قیمت نهایی (با تخفیف) در زمان سفارش
  finalUnitPrice: {
    type: Number,
    required: [true, 'قیمت نهایی الزامی است'],
    min: [0, 'قیمت نهایی نمی‌تواند منفی باشد']
  },
  
  // مبلغ کل این آیتم
  totalPrice: {
    type: Number,
    required: [true, 'مبلغ کل الزامی است'],
    min: [0, 'مبلغ کل نمی‌تواند منفی باشد']
  },
  
  // وزن محصول
  weight: {
    value: Number,
    unit: {
      type: String,
      enum: ['گرم', 'کیلوگرم', 'لیتر', 'عدد', 'بسته'],
      default: 'کیلوگرم'
    }
  },
  
  // تاریخ تولید
  productionDate: Date,
  
  // تاریخ انقضا
  expiryDate: Date
}, { _id: false });

const shippingAddressSchema = new mongoose.Schema({
  // نام گیرنده
  recipientName: {
    type: String,
    required: [true, 'نام گیرنده الزامی است'],
    trim: true,
    maxlength: [100, 'نام گیرنده نمی‌تواند بیشتر از ۱۰۰ کاراکتر باشد']
  },
  
  // تلفن گیرنده
  recipientPhone: {
    type: String,
    required: [true, 'تلفن گیرنده الزامی است'],
    match: [/^09[0-9]{9}$/, 'شماره تلفن معتبر نیست']
  },
  
  // استان
  province: {
    type: String,
    required: [true, 'استان الزامی است'],
    enum: {
      values: [
        'مازندران', 'گیلان', 'گلستان', 'تهران', 'البرز', 'قزوین', 'سمنان',
        'خراسان رضوی', 'خراسان شمالی', 'خراسان جنوبی', 'فارس', 'اصفهان',
        'یزد', 'کرمان', 'هرمزگان', 'سیستان و بلوچستان', 'آذربایجان شرقی',
        'آذربایجان غربی', 'اردبیل', 'زنجان', 'کردستان', 'همدان', 'لرستان',
        'ایلام', 'خوزستان', 'بوشهر', 'کهگیلویه و بویراحمد', 'چهارمحال و بختیاری',
        'مرکزی', 'قم'
      ],
      message: 'استان معتبر نیست'
    }
  },
  
  // شهر
  city: {
    type: String,
    required: [true, 'شهر الزامی است'],
    trim: true,
    maxlength: [100, 'نام شهر نمی‌تواند بیشتر از ۱۰۰ کاراکتر باشد']
  },
  
  // آدرس کامل
  address: {
    type: String,
    required: [true, 'آدرس الزامی است'],
    trim: true,
    maxlength: [500, 'آدرس نمی‌تواند بیشتر از ۵۰۰ کاراکتر باشد']
  },
  
  // کد پستی
  postalCode: {
    type: String,
    required: [true, 'کد پستی الزامی است'],
    match: [/^\d{10}$/, 'کد پستی باید ۱۰ رقمی باشد']
  },
  
  // مختصات جغرافیایی
  coordinates: {
    lat: Number,
    lng: Number
  },
  
  // یادداشت برای پیک
  deliveryNotes: {
    type: String,
    maxlength: [200, 'یادداشت نمی‌تواند بیشتر از ۲۰۰ کاراکتر باشد']
  },
  
  // آیا آدرس پیش‌فرض است؟
  isDefault: {
    type: Boolean,
    default: false
  }
}, { _id: false });

const paymentDetailsSchema = new mongoose.Schema({
  // روش پرداخت
  method: {
    type: String,
    required: [true, 'روش پرداخت الزامی است'],
    enum: {
      values: ['wallet', 'zarinpal', 'bank_transfer', 'cash_on_delivery'],
      message: 'روش پرداخت معتبر نیست'
    }
  },
  
  // مبلغ پرداخت شده
  amount: {
    type: Number,
    required: [true, 'مبلغ پرداخت الزامی است'],
    min: [0, 'مبلغ پرداخت نمی‌تواند منفی باشد']
  },
  
  // شناسه تراکنش
  transactionId: {
    type: String,
    trim: true
  },
  
  // شناسه پرداخت زرین‌پال
  zarinpalAuthority: String,
  
  // شناسه پیگیری بانکی
  bankTrackingCode: String,
  
  // تاریخ پرداخت
  paidAt: Date,
  
  // وضعیت پرداخت
  status: {
    type: String,
    enum: ['pending', 'completed', 'failed', 'refunded'],
    default: 'pending'
  },
  
  // اطلاعات کارت (در صورت پرداخت آنلاین)
  cardInfo: {
    lastFourDigits: String,
    bankName: String
  }
}, { _id: false });

const orderSchema = new mongoose.Schema({
  // شماره سفارش یکتا و خوانا
  orderNumber: {
    type: String,
    unique: true,
    index: true,
    required: [true, 'شماره سفارش الزامی است']
  },
  
  // کاربر سفارش‌دهنده
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'کاربر الزامی است'],
    index: true
  },
  
  // آیتم‌های سفارش
  items: [orderItemSchema],
  
  // آدرس ارسال
  shippingAddress: shippingAddressSchema,
  
  // جزئیات پرداخت
  payment: paymentDetailsSchema,
  
  // جمع مبلغ سفارش
  subtotal: {
    type: Number,
    required: [true, 'جمع مبلغ سفارش الزامی است'],
    min: [0, 'جمع مبلغ نمی‌تواند منفی باشد']
  },
  
  // تخفیف کل
  discount: {
    type: Number,
    default: 0,
    min: [0, 'تخفیف نمی‌تواند منفی باشد']
  },
  
  // هزینه ارسال
  shippingCost: {
    type: Number,
    default: 0,
    min: [0, 'هزینه ارسال نمی‌تواند منفی باشد']
  },
  
  // مالیات (در صورت نیاز)
  tax: {
    type: Number,
    default: 0,
    min: [0, 'مالیات نمی‌تواند منفی باشد']
  },
  
  // مبلغ نهایی
  totalAmount: {
    type: Number,
    required: [true, 'مبلغ نهایی الزامی است'],
    min: [0, 'مبلغ نهایی نمی‌تواند منفی باشد']
  },
  
  // وضعیت سفارش
  status: {
    type: String,
    required: [true, 'وضعیت سفارش الزامی است'],
    enum: {
      values: ['pending', 'paid', 'processing', 'shipped', 'delivered', 'cancelled', 'refunded'],
      message: 'وضعیت سفارش معتبر نیست'
    },
    default: 'pending',
    index: true
  },
  
  // تاریخ‌های مهم
  timeline: {
    orderedAt: {
      type: Date,
      default: Date.now
    },
    paidAt: Date,
    processingAt: Date,
    shippedAt: Date,
    deliveredAt: Date,
    cancelledAt: Date,
    refundedAt: Date
  },
  
  // کد رهگیری پستی
  trackingCode: {
    type: String,
    trim: true,
    uppercase: true
  },
  
  // شرکت ارسال‌کننده
  shippingProvider: {
    type: String,
    enum: ['post', 'tipax', 'snap', 'custom', 'pickup'],
    default: 'post'
  },
  
  // لینک رهگیری
  trackingUrl: String,
  
  // تخمین زمان تحویل
  estimatedDelivery: Date,
  
  // یادداشت‌های سفارش
  notes: {
    customer: {
      type: String,
      maxlength: [500, 'یادداشت مشتری نمی‌تواند بیشتر از ۵۰۰ کاراکتر باشد']
    },
    admin: {
      type: String,
      maxlength: [500, 'یادداشت ادمین نمی‌تواند بیشتر از ۵۰۰ کاراکتر باشد']
    }
  },
  
  // امتیاز سفارش (در صورت تکمیل)
  rating: {
    type: Number,
    min: 1,
    max: 5
  },
  
  // نظر کاربر درباره سفارش
  feedback: {
    type: String,
    maxlength: [1000, 'نظر نمی‌تواند بیشتر از ۱۰۰۰ کاراکتر باشد']
  },
  
  // آیا سفارش حذف شده (soft delete)
  isDeleted: {
    type: Boolean,
    default: false,
    index: true
  },
  
  // تاریخ انقضای سفارش لغو شده
  expiresAt: {
    type: Date,
    default: () => new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 روز
    index: { expireAfterSeconds: 0 }
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Virtual برای نمایش وضعیت فارسی
orderSchema.virtual('statusFa').get(function() {
  const statusMap = {
    'pending': 'در انتظار پرداخت',
    'paid': 'پرداخت شده',
    'processing': 'در حال آماده‌سازی',
    'shipped': 'ارسال شده',
    'delivered': 'تحویل داده شده',
    'cancelled': 'لغو شده',
    'refunded': 'عودت داده شده'
  };
  return statusMap[this.status] || this.status;
});

// Virtual برای تعداد آیتم‌ها
orderSchema.virtual('itemCount').get(function() {
  return this.items.reduce((sum, item) => sum + item.quantity, 0);
});

// Virtual برای تاریخ نمایش
orderSchema.virtual('displayDate').get(function() {
  return this.timeline.orderedAt.toLocaleDateString('fa-IR');
});

// Virtual برای زمان تخمینی باقی‌مانده
orderSchema.virtual('estimatedTimeRemaining').get(function() {
  if (!this.estimatedDelivery || this.status === 'delivered' || this.status === 'cancelled') {
    return null;
  }
  
  const now = new Date();
  const diff = this.estimatedDelivery - now;
  
  if (diff <= 0) return 'تحویل داده شده';
  
  const days = Math.floor(diff / (1000 * 60 * 60 * 24));
  const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
  
  if (days > 0) return `${days} روز و ${hours} ساعت`;
  if (hours > 0) return `${hours} ساعت`;
  
  return 'کمتر از یک ساعت';
});

// Middleware برای تولید شماره سفارش
orderSchema.pre('save', async function(next) {
  if (!this.isNew) return next();
  
  // تولید شماره سفارش به فرمت HT-YYYYMMDD-XXXXX
  const date = new Date();
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  const random = Math.floor(10000 + Math.random() * 90000);
  
  this.orderNumber = `HT-${year}${month}${day}-${random}`;
  
  next();
});

// Middleware برای به‌روزرسانی timeline
orderSchema.pre('save', function(next) {
  if (this.isModified('status')) {
    const now = new Date();
    
    switch (this.status) {
      case 'paid':
        this.timeline.paidAt = now;
        break;
      case 'processing':
        this.timeline.processingAt = now;
        break;
      case 'shipped':
        this.timeline.shippedAt = now;
        break;
      case 'delivered':
        this.timeline.deliveredAt = now;
        break;
      case 'cancelled':
        this.timeline.cancelledAt = now;
        break;
      case 'refunded':
        this.timeline.refundedAt = now;
        break;
    }
  }
  
  next();
});

// متدهای استاتیک
orderSchema.statics.findByOrderNumber = function(orderNumber, userId = null) {
  const query = { orderNumber, isDeleted: false };
  if (userId) query.user = userId;
  
  return this.findOne(query)
    .populate('user', 'name email phone')
    .populate('items.product', 'name image category categoryFa price discountPrice')
    .exec();
};

orderSchema.statics.findUserOrders = function(userId, filters = {}) {
  const query = { user: userId, isDeleted: false, ...filters };
  
  return this.find(query)
    .sort('-createdAt')
    .populate('items.product', 'name image')
    .exec();
};

orderSchema.statics.findRecentOrders = function(limit = 10) {
  return this.find({ isDeleted: false })
    .sort('-createdAt')
    .limit(limit)
    .populate('user', 'name')
    .populate('items.product', 'name')
    .exec();
};

orderSchema.statics.getStatistics = async function(userId = null) {
  const match = { isDeleted: false };
  if (userId) match.user = userId;
  
  const stats = await this.aggregate([
    { $match: match },
    {
      $group: {
        _id: null,
        totalOrders: { $sum: 1 },
        totalAmount: { $sum: '$totalAmount' },
        pendingOrders: {
          $sum: { $cond: [{ $eq: ['$status', 'pending'] }, 1, 0] }
        },
        deliveredOrders: {
          $sum: { $cond: [{ $eq: ['$status', 'delivered'] }, 1, 0] }
        },
        cancelledOrders: {
          $sum: { $cond: [{ $eq: ['$status', 'cancelled'] }, 1, 0] }
        }
      }
    }
  ]);
  
  return stats[0] || {
    totalOrders: 0,
    totalAmount: 0,
    pendingOrders: 0,
    deliveredOrders: 0,
    cancelledOrders: 0
  };
};

// متدهای نمونه
orderSchema.methods.cancel = async function(reason = 'لغو توسط کاربر') {
  if (this.status === 'delivered') {
    throw new Error('سفارش تحویل داده شده قابل لغو نیست');
  }
  
  if (this.status === 'cancelled') {
    throw new Error('سفارش قبلاً لغو شده است');
  }
  
  // اگر پرداخت انجام شده، بازگشت وجه
  if (this.payment.status === 'completed') {
    this.payment.status = 'refunded';
    this.timeline.refundedAt = new Date();
  }
  
  this.status = 'cancelled';
  this.notes.admin = reason;
  
  return await this.save();
};

orderSchema.methods.updateStatus = async function(newStatus, notes = '') {
  const validTransitions = {
    'pending': ['paid', 'cancelled'],
    'paid': ['processing', 'cancelled', 'refunded'],
    'processing': ['shipped', 'cancelled'],
    'shipped': ['delivered', 'cancelled'],
    'delivered': [],
    'cancelled': [],
    'refunded': []
  };
  
  if (!validTransitions[this.status]?.includes(newStatus)) {
    throw new Error(`تغییر وضعیت از ${this.status} به ${newStatus} مجاز نیست`);
  }
  
  this.status = newStatus;
  
  if (notes) {
    this.notes.admin = notes;
  }
  
  return await this.save();
};

orderSchema.methods.addTracking = async function(trackingCode, provider = 'post', trackingUrl = '') {
  if (this.status !== 'shipped' && this.status !== 'delivered') {
    throw new Error('فقط سفارش‌های ارسال شده یا تحویل داده شده می‌توانند کد رهگیری داشته باشند');
  }
  
  this.trackingCode = trackingCode;
  this.shippingProvider = provider;
  
  if (trackingUrl) {
    this.trackingUrl = trackingUrl;
  }
  
  return await this.save();
};

orderSchema.methods.getOrderSummary = function() {
  return {
    orderNumber: this.orderNumber,
    status: this.status,
    statusFa: this.statusFa,
    totalAmount: this.totalAmount,
    itemCount: this.itemCount,
    orderedAt: this.timeline.orderedAt,
    estimatedDelivery: this.estimatedDelivery,
    estimatedTimeRemaining: this.estimatedTimeRemaining,
    shippingAddress: {
      recipientName: this.shippingAddress.recipientName,
      city: this.shippingAddress.city,
      province: this.shippingAddress.province
    },
    payment: {
      method: this.payment.method,
      status: this.payment.status,
      amount: this.payment.amount
    }
  };
};

orderSchema.methods.getTimeline = function() {
  const timeline = [];
  
  if (this.timeline.orderedAt) {
    timeline.push({
      status: 'سفارش ثبت شد',
      date: this.timeline.orderedAt,
      description: 'سفارش شما با موفقیت ثبت شد'
    });
  }
  
  if (this.timeline.paidAt) {
    timeline.push({
      status: 'پرداخت تایید شد',
      date: this.timeline.paidAt,
      description: 'پرداخت شما با موفقیت انجام شد'
    });
  }
  
  if (this.timeline.processingAt) {
    timeline.push({
      status: 'در حال آماده‌سازی',
      date: this.timeline.processingAt,
      description: 'سفارش شما در حال آماده‌سازی است'
    });
  }
  
  if (this.timeline.shippedAt) {
    timeline.push({
      status: 'ارسال شد',
      date: this.timeline.shippedAt,
      description: this.trackingCode 
        ? `سفارش شما با کد رهگیری ${this.trackingCode} ارسال شد`
        : 'سفارش شما ارسال شد'
    });
  }
  
  if (this.timeline.deliveredAt) {
    timeline.push({
      status: 'تحویل داده شد',
      date: this.timeline.deliveredAt,
      description: 'سفارش شما با موفقیت تحویل داده شد'
    });
  }
  
  if (this.timeline.cancelledAt) {
    timeline.push({
      status: 'لغو شد',
      date: this.timeline.cancelledAt,
      description: this.notes.admin || 'سفارش شما لغو شد'
    });
  }
  
  return timeline.sort((a, b) => a.date - b.date);
};

// ایندکس‌ها
orderSchema.index({ orderNumber: 1, user: 1 });
orderSchema.index({ user: 1, status: 1, createdAt: -1 });
orderSchema.index({ status: 1, createdAt: -1 });
orderSchema.index({ 'shippingAddress.province': 1, createdAt: -1 });
orderSchema.index({ 'payment.status': 1 });
orderSchema.index({ trackingCode: 1 });

// پلاگین صفحه‌بندی
orderSchema.plugin(mongoosePaginate);

const Order = mongoose.model('Order', orderSchema);

module.exports = Order;