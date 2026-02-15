/**
 * @file مدل کاربران HTLand (نسخه به‌روزشده)
 * @description مدیریت اطلاعات کاربران فروشگاه محصولات ارگانیک شمال
 * @since 1403/10/01
 */

const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const validator = require('validator');

const userSchema = new mongoose.Schema({
  // اطلاعات اصلی
  phone: {
    type: String,
    required: [true, 'شماره موبایل الزامی است'],
    unique: true,
    index: true,
    immutable: true, // غیرقابل تغییر پس از ایجاد
    validate: {
      validator: function(v) {
        return /^09[0-9]{9}$/.test(v);
      },
      message: 'شماره موبایل معتبر نیست (فرمت: 09123456789)'
    }
  },
  
  fullName: {
    type: String,
    trim: true,
    minlength: [3, 'نام کامل باید حداقل ۳ کاراکتر باشد'],
    maxlength: [100, 'نام کامل نباید بیش از ۱۰۰ کاراکتر باشد'],
    validate: {
      validator: function(v) {
        return /^[\u0600-\u06FF\s]+$/.test(v);
      },
      message: 'نام کامل باید فارسی باشد'
    }
  },
  
  email: {
    type: String,
    lowercase: true,
    trim: true,
    validate: {
      validator: validator.isEmail,
      message: 'ایمیل معتبر نیست'
    }
  },
  
  // احراز هویت
  password: {
    type: String,
    minlength: [6, 'رمز عبور باید حداقل ۶ کاراکتر باشد'],
    select: false // به صورت پیش‌فرض در کوئری‌ها برگردانده نمی‌شود
  },
  
  // اطلاعات پروفایل
  profileImage: {
    type: String,
    default: 'https://res.cloudinary.com/htland/image/upload/v1/default-avatar.png'
  },
  
  profileImagePublicId: {
    type: String,
    select: false
  },
  
  // وضعیت کاربر
  isActive: {
    type: Boolean,
    default: true
  },
  
  isVerified: {
    type: Boolean,
    default: false
  },
  
  verificationCode: {
    type: String,
    select: false
  },
  
  verificationCodeExpires: {
    type: Date,
    select: false
  },
  
  // نقش کاربر
  role: {
    type: String,
    enum: ['user', 'admin', 'seller'],
    default: 'user'
  },
  
  // اطلاعات تماس
  emailVerified: {
    type: Boolean,
    default: false
  },
  
  phoneVerified: {
    type: Boolean,
    default: false
  },
  
  // تنظیمات کاربر
  notifications: {
    sms: { type: Boolean, default: true },
    email: { type: Boolean, default: true },
    push: { type: Boolean, default: true }
  },
  
  language: {
    type: String,
    enum: ['fa', 'en'],
    default: 'fa'
  },
  
  currency: {
    type: String,
    enum: ['IRR', 'IRT'],
    default: 'IRT'
  },
  
  // اطلاعات آماری
  lastLogin: {
    type: Date
  },
  
  loginCount: {
    type: Number,
    default: 0
  },
  
  // اطلاعات کیف پول
  walletBalance: {
    type: Number,
    default: 0,
    min: [0, 'موجودی کیف پول نمی‌تواند منفی باشد']
  },
  
  walletTransactions: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Transaction'
  }],
  
  // اطلاعات ارجاع
  referralCode: {
    type: String,
    unique: true,
    sparse: true
  },
  
  referredBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  
  // آدرس‌های کاربر (ارجاع به مدل آدرس)
  addresses: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Address'
  }],
  
  // اطلاعات اضافی
  birthDate: {
    type: Date
  },
  
  gender: {
    type: String,
    enum: ['male', 'female', 'other']
  },
  
  nationalCode: {
    type: String,
    validate: {
      validator: function(v) {
        return /^\d{10}$/.test(v);
      },
      message: 'کد ملی باید ۱۰ رقم باشد'
    }
  },
  
  // علاقه‌مندی‌ها
  favoriteCategories: [{
    type: String,
    enum: ['rice', 'caviar', 'fish', 'honey', 'chicken', 'souvenirs']
  }],
  
  wishlist: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Product'
  }]
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// ایندکس‌ها
userSchema.index({ phone: 1 });
userSchema.index({ email: 1 }, { sparse: true });
userSchema.index({ referralCode: 1 }, { sparse: true });
userSchema.index({ createdAt: -1 });

// Virtual برای محاسبه سن کاربر
userSchema.virtual('age').get(function() {
  if (!this.birthDate) return null;
  const today = new Date();
  const birthDate = new Date(this.birthDate);
  let age = today.getFullYear() - birthDate.getFullYear();
  const monthDiff = today.getMonth() - birthDate.getMonth();
  
  if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birthDate.getDate())) {
    age--;
  }
  
  return age;
});

// Virtual برای مدت عضویت
userSchema.virtual('membershipDuration').get(function() {
  const now = new Date();
  const createdAt = new Date(this.createdAt);
  const diffTime = Math.abs(now - createdAt);
  const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
  
  if (diffDays < 30) {
    return `${diffDays} روز`;
  } else if (diffDays < 365) {
    const months = Math.floor(diffDays / 30);
    return `${months} ماه`;
  } else {
    const years = Math.floor(diffDays / 365);
    const remainingMonths = Math.floor((diffDays % 365) / 30);
    return `${years} سال و ${remainingMonths} ماه`;
  }
});

// میدلور: هش کردن رمز عبور قبل از ذخیره
userSchema.pre('save', async function(next) {
  // فقط اگر رمز عبور تغییر کرده باشد
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// میدلور: ایجاد کد ارجاع خودکار
userSchema.pre('save', function(next) {
  if (!this.referralCode) {
    this.referralCode = 'HT' + Math.random().toString(36).substr(2, 8).toUpperCase();
  }
  next();
});

// متد ایستا: پیدا کردن کاربر با شماره موبایل
userSchema.statics.findByPhone = function(phone) {
  return this.findOne({ phone });
};

// متد ایستا: بررسی موجود بودن شماره موبایل
userSchema.statics.isPhoneExists = async function(phone) {
  const user = await this.findOne({ phone }).select('_id');
  return !!user;
};

// متد نمونه: مقایسه رمز عبور
userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

// متد نمونه: آپدیت آخرین ورود
userSchema.methods.updateLastLogin = async function() {
  this.lastLogin = new Date();
  this.loginCount += 1;
  return await this.save();
};

// متد نمونه: تولید توکن JWT
userSchema.methods.generateAuthToken = function() {
  const jwt = require('jsonwebtoken');
  return jwt.sign(
    { 
      userId: this._id,
      phone: this.phone,
      role: this.role 
    },
    process.env.JWT_SECRET || 'htland-secret-key',
    { expiresIn: process.env.JWT_EXPIRES_IN || '30d' }
  );
};

// متد نمونه: پنهان کردن اطلاعات حساس
userSchema.methods.toSafeObject = function() {
  const userObject = this.toObject();
  
  // حذف فیلدهای حساس
  delete userObject.password;
  delete userObject.verificationCode;
  delete userObject.verificationCodeExpires;
  delete userObject.profileImagePublicId;
  delete userObject.__v;
  
  return userObject;
};

// متد نمونه: افزایش موجودی کیف پول
userSchema.methods.increaseWalletBalance = async function(amount) {
  if (amount <= 0) {
    throw new Error('مبلغ باید بزرگتر از صفر باشد');
  }
  
  this.walletBalance += amount;
  return await this.save();
};

// متد نمونه: کاهش موجودی کیف پول
userSchema.methods.decreaseWalletBalance = async function(amount) {
  if (amount <= 0) {
    throw new Error('مبلغ باید بزرگتر از صفر باشد');
  }
  
  if (this.walletBalance < amount) {
    throw new Error('موجودی کیف پول کافی نیست');
  }
  
  this.walletBalance -= amount;
  return await this.save();
};

const User = mongoose.model('User', userSchema);

module.exports = User;