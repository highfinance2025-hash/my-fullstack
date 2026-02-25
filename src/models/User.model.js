/**
 * @file مدل کاربران HTLand (نسخه نهایی اصلاح شده)
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
    validate: {
      validator: function(v) {
        return /^09[0-9]{9}$/.test(v);
      },
      message: 'شماره موبایل معتبر نیست'
    }
  },
  
  fullName: {
    type: String,
    trim: true,
    minlength: 3,
    maxlength: 100
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
  
  password: {
    type: String,
    minlength: [6, 'رمز عبور باید حداقل ۶ کاراکتر باشد'],
    select: false
  },
  
  // ✅ فیلد OTP که قبلاً جا افتاده بود
  otp: {
    code: {
      type: String
    },
    expiresAt: {
      type: Date
    }
  },

  profileImage: {
    type: String,
    default: 'https://res.cloudinary.com/htland/image/upload/v1/default-avatar.png'
  },
  
  isActive: {
    type: Boolean,
    default: true
  },
  
  role: {
    type: String,
    enum: ['user', 'admin', 'seller'],
    default: 'user'
  },
  
  phoneVerified: {
    type: Boolean,
    default: false
  },
  
  walletBalance: {
    type: Number,
    default: 0
  },
  
  referralCode: {
    type: String,
    unique: true,
    sparse: true
  },

  lastLogin: {
    type: Date
  }

}, {
  timestamps: true
});

// ایندکس‌ها
userSchema.index({ phone: 1 });

// میدلور: هش کردن رمز عبور قبل از ذخیره
userSchema.pre('save', async function(next) {
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

// متد نمونه: مقایسه رمز عبور
userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

// متد نمونه: تولید توکن JWT
// متد نمونه: تولید توکن JWT
userSchema.methods.generateAuthToken = function() {
  const jwt = require('jsonwebtoken');
  return jwt.sign(
    { 
      userId: this._id,
      phone: this.phone,
      role: this.role,
      type: 'access' 
    },
    process.env.JWT_SECRET || 'htland-secret-key',
    { expiresIn: process.env.JWT_EXPIRES_IN || '30d' }
  );
};

// ✅ متد نمونه: تولید کد OTP
userSchema.methods.generateOTP = function() {
  // تولید کد ۶ رقمی تصادفی
  const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
  
  // تنظیم زمان انقضا (۲ دقیقه دیگر)
  const expiresAt = new Date(Date.now() + 2 * 60 * 1000);

  // ذخیره در فیلد otp
  this.otp = {
    code: otpCode,
    expiresAt: expiresAt
  };

  return otpCode;
};

const User = mongoose.model('User', userSchema);

module.exports = User;