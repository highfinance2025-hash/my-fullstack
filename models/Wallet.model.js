const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const crypto = require('crypto');
const logger = require('../utils/logger');
const config = require('../config/env');

// شمای کیف پول
const walletSchema = new Schema({
  // کاربر
  user: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true,
    index: true
  },
  
  // موجودی
  balance: {
    type: Number,
    required: true,
    default: 0,
    min: 0,
    get: v => Math.round(v),
    set: v => Math.round(v)
  },
  
  // موجودی قفل شده
  lockedBalance: {
    type: Number,
    default: 0,
    min: 0,
    get: v => Math.round(v),
    set: v => Math.round(v),
    validate: {
      validator: function(v) {
        return v <= this.balance;
      },
      message: 'موجودی قفل شده نمی‌تواند از موجودی کل بیشتر باشد'
    }
  },
  
  // کل واریزی‌ها
  totalDeposits: {
    type: Number,
    default: 0,
    min: 0,
    get: v => Math.round(v),
    set: v => Math.round(v)
  },
  
  // کل برداشت‌ها
  totalWithdrawals: {
    type: Number,
    default: 0,
    min: 0,
    get: v => Math.round(v),
    set: v => Math.round(v)
  },
  
  // وضعیت فعال
  isActive: {
    type: Boolean,
    default: true,
    index: true
  },
  
  // نسخه برای کنترل همزمانی
  __v: {
    type: Number,
    select: false
  },
  
  // تأیید هویت
  verification: {
    verified: {
      type: Boolean,
      default: false
    },
    verifiedAt: Date,
    verifiedBy: {
      type: Schema.Types.ObjectId,
      ref: 'User'
    }
  },
  
  // محدودیت‌های روزانه
  dailyLimits: {
    maxDeposit: {
      type: Number,
      default: 50000000,
      get: v => Math.round(v),
      set: v => Math.round(v)
    },
    maxWithdrawal: {
      type: Number,
      default: 20000000,
      get: v => Math.round(v),
      set: v => Math.round(v)
    },
    depositCount: {
      type: Number,
      default: 0
    },
    withdrawalCount: {
      type: Number,
      default: 0
    },
    lastResetDate: {
      type: Date,
      default: Date.now
    }
  },
  
  // آمار
  stats: {
    totalTransactions: {
      type: Number,
      default: 0
    },
    successfulTransactions: {
      type: Number,
      default: 0
    },
    failedTransactions: {
      type: Number,
      default: 0
    },
    lastActivityDate: Date
  },
  
  // زمان‌بندی
  createdAt: {
    type: Date,
    default: Date.now,
    index: true
  },
  updatedAt: {
    type: Date,
    default: Date.now,
    index: true
  }
}, {
  timestamps: true,
  toJSON: { 
    getters: true,
    virtuals: true,
    transform: (doc, ret) => {
      delete ret.__v;
      return ret;
    }
  }
});

// فیلد مجازی برای موجودی قابل برداشت
walletSchema.virtual('availableBalance').get(function() {
  return this.balance - this.lockedBalance;
});

// فیلد مجازی برای بررسی محدودیت روزانه
walletSchema.virtual('dailyLimitStatus').get(function() {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  
  const lastReset = new Date(this.dailyLimits.lastResetDate);
  lastReset.setHours(0, 0, 0, 0);
  
  return {
    depositExceeded: this.dailyLimits.depositCount >= 10,
    withdrawalExceeded: this.dailyLimits.withdrawalCount >= 5,
    needsReset: today > lastReset
  };
});

// middleware برای ریست محدودیت‌های روزانه
walletSchema.pre('save', function(next) {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  
  const lastReset = new Date(this.dailyLimits.lastResetDate);
  lastReset.setHours(0, 0, 0, 0);
  
  if (today > lastReset) {
    this.dailyLimits.depositCount = 0;
    this.dailyLimits.withdrawalCount = 0;
    this.dailyLimits.totalDeposits = 0;
    this.dailyLimits.totalWithdrawals = 0;
    this.dailyLimits.lastResetDate = new Date();
  }
  
  this.updatedAt = Date.now();
  next();
});

// ایندکس‌ها
walletSchema.index({ user: 1 }, { unique: true });
walletSchema.index({ balance: 1 });
walletSchema.index({ createdAt: 1 });

// ایجاد مدل
const Wallet = mongoose.model('Wallet', walletSchema);

module.exports = Wallet;