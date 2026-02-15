/**
 * @file مدل کاربر (User) برای سیستم احراز هویت HTLand
 * @description ذخیره اطلاعات کاربران، احراز هویت با موبایل و مدیریت پروفایل
 * @since 1.0.0
 */

const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

/**
 * @typedef {Object} Address
 * @property {string} title - عنوان آدرس (مثلا: خانه، محل کار)
 * @property {string} province - استان
 * @property {string} city - شهر
 * @property {string} postalCode - کد پستی
 * @property {string} address - متن کامل آدرس
 * @property {string} receiverName - نام تحویل‌گیرنده
 * @property {string} receiverPhone - تلفن تحویل‌گیرنده
 * @property {boolean} isDefault - آیا آدرس پیش‌فرض است
 */

/**
 * @typedef {Object} OTP
 * @property {string} code - کد OTP
 * @property {Date} expiresAt - تاریخ انقضا
 * @property {boolean} used - آیا استفاده شده است
 */

/**
 * @typedef {Object} UserSession
 * @property {string} token - توکن JWT
 * @property {Date} createdAt - زمان ایجاد
 * @property {Date} expiresAt - زمان انقضا
 * @property {string} deviceInfo - اطلاعات دستگاه
 * @property {string} ipAddress - آدرس IP
 */

const addressSchema = new mongoose.Schema({
  title: {
    type: String,
    required: [true, 'عنوان آدرس الزامی است'],
    trim: true,
    maxlength: [50, 'عنوان آدرس نمی‌تواند بیشتر از ۵۰ کاراکتر باشد']
  },
  province: {
    type: String,
    required: [true, 'استان الزامی است'],
    trim: true
  },
  city: {
    type: String,
    required: [true, 'شهر الزامی است'],
    trim: true
  },
  postalCode: {
    type: String,
    required: [true, 'کد پستی الزامی است'],
    match: [/^\d{10}$/, 'کد پستی باید ۱۰ رقمی باشد']
  },
  address: {
    type: String,
    required: [true, 'آدرس الزامی است'],
    trim: true,
    maxlength: [500, 'آدرس نمی‌تواند بیشتر از ۵۰۰ کاراکتر باشد']
  },
  receiverName: {
    type: String,
    required: [true, 'نام تحویل‌گیرنده الزامی است'],
    trim: true
  },
  receiverPhone: {
    type: String,
    required: [true, 'تلفن تحویل‌گیرنده الزامی است'],
    match: [/^09[0-9]{9}$/, 'شماره موبایل معتبر نیست']
  },
  isDefault: {
    type: Boolean,
    default: false
  },
  location: {
    type: {
      type: String,
      enum: ['Point'],
      default: 'Point'
    },
    coordinates: {
      type: [Number],
      default: [0, 0]
    }
  }
}, { _id: true });

const otpSchema = new mongoose.Schema({
  code: {
    type: String,
    required: true,
    length: [6, 'کد OTP باید ۶ رقمی باشد']
  },
  expiresAt: {
    type: Date,
    required: true
  },
  used: {
    type: Boolean,
    default: false
  },
  attemptCount: {
    type: Number,
    default: 0,
    max: 5
  }
}, { _id: false });

const sessionSchema = new mongoose.Schema({
  token: {
    type: String,
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  expiresAt: {
    type: Date,
    required: true
  },
  deviceInfo: {
    type: String,
    default: 'Unknown'
  },
  ipAddress: {
    type: String,
    default: '0.0.0.0'
  },
  isActive: {
    type: Boolean,
    default: true
  }
}, { _id: true });

const userSchema = new mongoose.Schema({
  // اطلاعات هویتی
  firstName: {
    type: String,
    trim: true,
    maxlength: [50, 'نام نمی‌تواند بیشتر از ۵۰ کاراکتر باشد']
  },
  lastName: {
    type: String,
    trim: true,
    maxlength: [50, 'نام خانوادگی نمی‌تواند بیشتر از ۵۰ کاراکتر باشد']
  },
  phone: {
    type: String,
    required: [true, 'شماره موبایل الزامی است'],
    unique: true,
    match: [/^09[0-9]{9}$/, 'شماره موبایل معتبر نیست'],
    index: true
  },
  email: {
    type: String,
    trim: true,
    lowercase: true,
    match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'ایمیل معتبر نیست']
  },
  nationalCode: {
    type: String,
    match: [/^\d{10}$/, 'کد ملی باید ۱۰ رقمی باشد']
  },
  
  // وضعیت احراز هویت
  isPhoneVerified: {
    type: Boolean,
    default: false
  },
  isEmailVerified: {
    type: Boolean,
    default: false
  },
  isActive: {
    type: Boolean,
    default: true
  },
  isAdmin: {
    type: Boolean,
    default: false
  },
  
  // OTP و رمز عبور
  otp: otpSchema,
  password: {
    type: String,
    minlength: [6, 'رمز عبور باید حداقل ۶ کاراکتر باشد'],
    select: false // در کوئری‌های معمول برگردانده نمی‌شود
  },
  lastPasswordChange: {
    type: Date
  },
  
  // آدرس‌ها
  addresses: [addressSchema],
  
  // اطلاعات تماس
  avatar: {
    type: String,
    default: '/images/avatars/default.png'
  },
  birthDate: {
    type: Date
  },
  gender: {
    type: String,
    enum: ['male', 'female', 'other', null],
    default: null
  },
  
  // جستجو و SEO
  searchKeywords: [{
    type: String,
    trim: true
  }],
  
  // تنظیمات کاربر
  settings: {
    notifications: {
      sms: { type: Boolean, default: true },
      email: { type: Boolean, default: true },
      push: { type: Boolean, default: true }
    },
    theme: {
      type: String,
      enum: ['light', 'dark', 'auto'],
      default: 'auto'
    },
    language: {
      type: String,
      enum: ['fa', 'en'],
      default: 'fa'
    }
  },
  
  // سشن‌ها و امنیت
  sessions: [sessionSchema],
  lastLogin: {
    type: Date
  },
  loginAttempts: {
    type: Number,
    default: 0,
    max: 5
  },
  lockUntil: {
    type: Date
  },
  
  // ارتباط با سایر مدل‌ها
  walletId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Wallet'
  },
  
  // آمار و آنالیتیکس
  stats: {
    totalOrders: { type: Number, default: 0 },
    totalSpent: { type: Number, default: 0 },
    favoriteCategories: [String]
  },
  
  // متادیتا
  referredBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  referralCode: {
    type: String,
    unique: true,
    sparse: true
  },
  acceptedTerms: {
    type: Boolean,
    default: false,
    required: true
  },
  acceptedPrivacy: {
    type: Boolean,
    default: false,
    required: true
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

/**
 * وایرچوال برای نام کامل کاربر
 */
userSchema.virtual('fullName').get(function() {
  if (this.firstName && this.lastName) {
    return `${this.firstName} ${this.lastName}`;
  }
  return this.firstName || this.lastName || 'کاربر HTLand';
});

/**
 * وایرچوال برای آدرس پیش‌فرض
 */
userSchema.virtual('defaultAddress').get(function() {
  return this.addresses.find(addr => addr.isDefault) || this.addresses[0];
});

/**
 * میانبر برای چک کردن قفل بودن حساب
 */
userSchema.virtual('isLocked').get(function() {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

/**
 * هش کردن رمز عبور قبل از ذخیره
 */
userSchema.pre('save', async function(next) {
  // فقط اگر رمز عبور تغییر کرده باشد
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    this.lastPasswordChange = Date.now();
    next();
  } catch (error) {
    next(error);
  }
});

/**
 * چک کردن رمز عبور
 */
userSchema.methods.comparePassword = async function(candidatePassword) {
  if (!this.password) return false;
  return await bcrypt.compare(candidatePassword, this.password);
};

/**
 * تولید توکن JWT
 */
userSchema.methods.generateAuthToken = function(deviceInfo = 'Unknown', ipAddress = '0.0.0.0') {
  const payload = {
    userId: this._id,
    phone: this.phone,
    isAdmin: this.isAdmin
  };
  
  const token = jwt.sign(
    payload,
    process.env.JWT_SECRET || 'htland-secret-key-change-in-production',
    { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
  );
  
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + 7); // 7 روز
  
  const session = {
    token,
    createdAt: new Date(),
    expiresAt,
    deviceInfo,
    ipAddress,
    isActive: true
  };
  
  // اضافه کردن سشن جدید
  this.sessions.push(session);
  
  return {
    token,
    expiresAt,
    sessionId: session._id
  };
};

/**
 * حذف توکن (خروج از سیستم)
 */
userSchema.methods.invalidateToken = function(token) {
  this.sessions = this.sessions.filter(session => session.token !== token);
};

/**
 * حذف تمام سشن‌ها (خروج از تمام دستگاه‌ها)
 */
userSchema.methods.invalidateAllTokens = function() {
  this.sessions = [];
};

/**
 * تولید کد OTP
 */
userSchema.methods.generateOTP = function() {
  // در محیط توسعه، کد ثابت استفاده می‌شود
  const code = process.env.NODE_ENV === 'production' 
    ? Math.floor(100000 + Math.random() * 900000).toString()
    : '123456';
  
  const expiresAt = new Date();
  expiresAt.setMinutes(expiresAt.getMinutes() + 5); // 5 دقیقه اعتبار
  
  this.otp = {
    code,
    expiresAt,
    used: false,
    attemptCount: 0
  };
  
  return code;
};

/**
 * اعتبارسنجی کد OTP
 */
userSchema.methods.validateOTP = function(code) {
  if (!this.otp || !this.otp.code) {
    return { isValid: false, reason: 'کد OTP وجود ندارد' };
  }
  
  if (this.otp.used) {
    return { isValid: false, reason: 'کد OTP قبلا استفاده شده است' };
  }
  
  if (new Date() > this.otp.expiresAt) {
    return { isValid: false, reason: 'کد OTP منقضی شده است' };
  }
  
  if (this.otp.attemptCount >= 5) {
    return { isValid: false, reason: 'تعداد تلاش‌های ناموفق بیش از حد مجاز' };
  }
  
  if (this.otp.code !== code) {
    this.otp.attemptCount += 1;
    return { isValid: false, reason: 'کد OTP نادرست است' };
  }
  
  // OTP معتبر است
  this.otp.used = true;
  this.isPhoneVerified = true;
  
  return { isValid: true };
};

/**
 * بررسی وجود آدرس
 */
userSchema.methods.hasAddress = function(addressId) {
  return this.addresses.some(addr => addr._id.toString() === addressId);
};

/**
 * افزودن آدرس جدید
 */
userSchema.methods.addAddress = function(addressData) {
  // اگر اولین آدرس باشد، پیش‌فرض می‌شود
  if (this.addresses.length === 0) {
    addressData.isDefault = true;
  }
  
  // اگر این آدرس پیش‌فرض باشد، بقیه را غیرپیش‌فرض می‌کنیم
  if (addressData.isDefault) {
    this.addresses.forEach(addr => {
      addr.isDefault = false;
    });
  }
  
  this.addresses.push(addressData);
  return this.addresses[this.addresses.length - 1];
};

/**
 * به‌روزرسانی آدرس
 */
userSchema.methods.updateAddress = function(addressId, addressData) {
  const addressIndex = this.addresses.findIndex(addr => addr._id.toString() === addressId);
  
  if (addressIndex === -1) {
    throw new Error('آدرس یافت نشد');
  }
  
  // اگر این آدرس پیش‌فرض می‌شود، بقیه را غیرپیش‌فرض می‌کنیم
  if (addressData.isDefault) {
    this.addresses.forEach(addr => {
      addr.isDefault = false;
    });
  }
  
  Object.assign(this.addresses[addressIndex], addressData);
  return this.addresses[addressIndex];
};

/**
 * حذف آدرس
 */
userSchema.methods.removeAddress = function(addressId) {
  const addressIndex = this.addresses.findIndex(addr => addr._id.toString() === addressId);
  
  if (addressIndex === -1) {
    throw new Error('آدرس یافت نشد');
  }
  
  const isDefault = this.addresses[addressIndex].isDefault;
  const removedAddress = this.addresses.splice(addressIndex, 1)[0];
  
  // اگر آدرس پیش‌فرض حذف شد، اولین آدرس باقی‌مانده را پیش‌فرض می‌کنیم
  if (isDefault && this.addresses.length > 0) {
    this.addresses[0].isDefault = true;
  }
  
  return removedAddress;
};

/**
 * افزایش تلاش‌های ناموفق ورود
 */
userSchema.methods.incLoginAttempts = function() {
  // اگر زمان قفل گذشته باشد یا اولین تلاش باشد
  if (this.lockUntil && this.lockUntil < Date.now()) {
    this.loginAttempts = 1;
    this.lockUntil = null;
    return;
  }
  
  this.loginAttempts += 1;
  
  // اگر بیش از ۵ تلاش ناموفق شد، حساب را قفل کن
  if (this.loginAttempts >= 5) {
    this.lockUntil = Date.now() + 15 * 60 * 1000; // 15 دقیقه قفل
  }
};

/**
 * ریست کردن تلاش‌های ورود پس از ورود موفق
 */
userSchema.methods.resetLoginAttempts = function() {
  this.loginAttempts = 0;
  this.lockUntil = null;
  this.lastLogin = new Date();
};

// ایندکس‌های مهم
userSchema.index({ phone: 1 }, { unique: true });
userSchema.index({ referralCode: 1 }, { sparse: true });
userSchema.index({ 'addresses.location': '2dsphere' });
userSchema.index({ createdAt: -1 });
userSchema.index({ 'stats.totalSpent': -1 });

module.exports = mongoose.model('User', userSchema);