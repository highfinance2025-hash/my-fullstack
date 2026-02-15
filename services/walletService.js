const mongoose = require('mongoose');
const Wallet = require('../models/Wallet.model');
const logger = require('../utils/logger');
const config = require('../config/env');

class WalletService {
  constructor() {
    this.encryptionKey = config.encryption.key;
  }

  // افزایش موجودی
  async increaseBalance(walletId, amount, userId, transactionData = {}) {
    const session = await mongoose.startSession();
    
    try {
      session.startTransaction();
      
      // 1. خواندن کیف پول با قفل
      const wallet = await Wallet.findById(walletId).session(session);
      
      if (!wallet) {
        throw new Error('کیف پول یافت نشد');
      }
      
      // 2. اعتبارسنجی مالکیت
      if (wallet.user.toString() !== userId.toString()) {
        throw new Error('دسترسی غیرمجاز به کیف پول');
      }
      
      // 3. اعتبارسنجی مقدار
      if (amount <= 0) {
        throw new Error('مبلغ باید مثبت باشد');
      }
      
      if (amount > config.financial.maxTransactionAmount) {
        throw new Error(`حداکثر مبلغ ${config.financial.maxTransactionAmount.toLocaleString('fa-IR')} تومان است`);
      }
      
      // 4. بررسی محدودیت روزانه
      const limitStatus = wallet.dailyLimitStatus;
      
      if (limitStatus.needsReset) {
        // محدودیت‌ها در pre-save middleware ریست می‌شوند
      }
      
      if (limitStatus.depositExceeded) {
        throw new Error('شما به حداکثر تعداد واریز روزانه رسیده‌اید');
      }
      
      if (wallet.dailyLimits.totalDeposits + amount > wallet.dailyLimits.maxDeposit) {
        throw new Error('شما به حداکثر مبلغ واریز روزانه رسیده‌اید');
      }
      
      // 5. به‌روزرسانی اتمیک
      const updatedWallet = await Wallet.findOneAndUpdate(
        {
          _id: walletId,
          __v: wallet.__v,
          isActive: true
        },
        {
          $inc: {
            balance: amount,
            totalDeposits: amount,
            'dailyLimits.depositCount': 1,
            'dailyLimits.totalDeposits': amount,
            'stats.totalTransactions': 1,
            'stats.successfulTransactions': 1,
            __v: 1
          },
          $set: {
            'stats.lastActivityDate': new Date(),
            updatedAt: new Date()
          }
        },
        {
          session,
          new: true,
          runValidators: true
        }
      );
      
      if (!updatedWallet) {
        throw new Error('تداخل در به‌روزرسانی کیف پول');
      }
      
      // 6. کامیت تراکنش
      await session.commitTransaction();
      
      logger.info('موجودی افزایش یافت', {
        walletId,
        userId,
        amount,
        newBalance: updatedWallet.balance,
        transactionId: transactionData.transactionId || 'N/A'
      });
      
      return updatedWallet;
      
    } catch (error) {
      await session.abortTransaction();
      
      // لاگ خطا
      logger.error('خطا در افزایش موجودی', {
        walletId,
        userId,
        amount,
        error: error.message,
        stack: error.stack
      });
      
      throw error;
      
    } finally {
      session.endSession();
    }
  }

  // کاهش موجودی
  async decreaseBalance(walletId, amount, userId, transactionData = {}) {
    const session = await mongoose.startSession();
    
    try {
      session.startTransaction();
      
      const wallet = await Wallet.findById(walletId).session(session);
      
      if (!wallet) {
        throw new Error('کیف پول یافت نشد');
      }
      
      // اعتبارسنجی مالکیت
      if (wallet.user.toString() !== userId.toString()) {
        throw new Error('دسترسی غیرمجاز به کیف پول');
      }
      
      // اعتبارسنجی مقدار
      if (amount <= 0) {
        throw new Error('مبلغ باید مثبت باشد');
      }
      
      if (amount > config.financial.maxTransactionAmount) {
        throw new Error(`حداکثر مبلغ ${config.financial.maxTransactionAmount.toLocaleString('fa-IR')} تومان است`);
      }
      
      // بررسی موجودی کافی
      const availableBalance = wallet.balance - wallet.lockedBalance;
      if (availableBalance < amount) {
        throw new Error('موجودی کافی نیست');
      }
      
      // بررسی محدودیت روزانه
      const limitStatus = wallet.dailyLimitStatus;
      
      if (limitStatus.withdrawalExceeded) {
        throw new Error('شما به حداکثر تعداد برداشت روزانه رسیده‌اید');
      }
      
      if (wallet.dailyLimits.totalWithdrawals + amount > wallet.dailyLimits.maxWithdrawal) {
        throw new Error('شما به حداکثر مبلغ برداشت روزانه رسیده‌اید');
      }
      
      // به‌روزرسانی اتمیک
      const updatedWallet = await Wallet.findOneAndUpdate(
        {
          _id: walletId,
          __v: wallet.__v,
          isActive: true,
          balance: { $gte: wallet.lockedBalance + amount }
        },
        {
          $inc: {
            balance: -amount,
            totalWithdrawals: amount,
            'dailyLimits.withdrawalCount': 1,
            'dailyLimits.totalWithdrawals': amount,
            'stats.totalTransactions': 1,
            'stats.successfulTransactions': 1,
            __v: 1
          },
          $set: {
            'stats.lastActivityDate': new Date(),
            updatedAt: new Date()
          }
        },
        {
          session,
          new: true,
          runValidators: true
        }
      );
      
      if (!updatedWallet) {
        throw new Error('تداخل در به‌روزرسانی یا موجودی ناکافی');
      }
      
      await session.commitTransaction();
      
      logger.info('موجودی کاهش یافت', {
        walletId,
        userId,
        amount,
        newBalance: updatedWallet.balance,
        transactionId: transactionData.transactionId || 'N/A'
      });
      
      return updatedWallet;
      
    } catch (error) {
      await session.abortTransaction();
      
      logger.error('خطا در کاهش موجودی', {
        walletId,
        userId,
        amount,
        error: error.message
      });
      
      throw error;
      
    } finally {
      session.endSession();
    }
  }

  // قفل کردن موجودی
  async lockBalance(walletId, amount, userId) {
    const session = await mongoose.startSession();
    
    try {
      session.startTransaction();
      
      const wallet = await Wallet.findById(walletId).session(session);
      
      if (!wallet) {
        throw new Error('کیف پول یافت نشد');
      }
      
      // اعتبارسنجی مالکیت
      if (wallet.user.toString() !== userId.toString()) {
        throw new Error('دسترسی غیرمجاز به کیف پول');
      }
      
      if (amount <= 0) {
        throw new Error('مبلغ باید مثبت باشد');
      }
      
      // بررسی موجودی کافی
      const availableBalance = wallet.balance - wallet.lockedBalance;
      if (availableBalance < amount) {
        throw new Error('موجودی کافی برای قفل کردن وجود ندارد');
      }
      
      // قفل کردن
      const updatedWallet = await Wallet.findOneAndUpdate(
        {
          _id: walletId,
          __v: wallet.__v,
          balance: { $gte: wallet.lockedBalance + amount }
        },
        {
          $inc: {
            lockedBalance: amount,
            __v: 1
          },
          $set: {
            updatedAt: new Date()
          }
        },
        {
          session,
          new: true,
          runValidators: true
        }
      );
      
      if (!updatedWallet) {
        throw new Error('تداخل در قفل کردن موجودی');
      }
      
      await session.commitTransaction();
      
      logger.info('موجودی قفل شد', {
        walletId,
        userId,
        amount,
        lockedBalance: updatedWallet.lockedBalance
      });
      
      return updatedWallet;
      
    } catch (error) {
      await session.abortTransaction();
      throw error;
    } finally {
      session.endSession();
    }
  }

  // آزاد کردن موجودی قفل شده
  async unlockBalance(walletId, amount, userId) {
    const session = await mongoose.startSession();
    
    try {
      session.startTransaction();
      
      const wallet = await Wallet.findById(walletId).session(session);
      
      if (!wallet) {
        throw new Error('کیف پول یافت نشد');
      }
      
      // اعتبارسنجی مالکیت
      if (wallet.user.toString() !== userId.toString()) {
        throw new Error('دسترسی غیرمجاز به کیف پول');
      }
      
      if (amount <= 0) {
        throw new Error('مبلغ باید مثبت باشد');
      }
      
      if (wallet.lockedBalance < amount) {
        throw new Error('موجودی قفل شده کافی نیست');
      }
      
      // آزاد کردن
      const updatedWallet = await Wallet.findOneAndUpdate(
        {
          _id: walletId,
          __v: wallet.__v,
          lockedBalance: { $gte: amount }
        },
        {
          $inc: {
            lockedBalance: -amount,
            __v: 1
          },
          $set: {
            updatedAt: new Date()
          }
        },
        {
          session,
          new: true,
          runValidators: true
        }
      );
      
      if (!updatedWallet) {
        throw new Error('تداخل در آزاد کردن موجودی');
      }
      
      await session.commitTransaction();
      
      logger.info('موجودی آزاد شد', {
        walletId,
        userId,
        amount,
        lockedBalance: updatedWallet.lockedBalance
      });
      
      return updatedWallet;
      
    } catch (error) {
      await session.abortTransaction();
      throw error;
    } finally {
      session.endSession();
    }
  }

  // ایجاد کیف پول
  async createWallet(userId) {
    try {
      // بررسی وجود کیف پول
      const existingWallet = await Wallet.findOne({ user: userId });
      
      if (existingWallet) {
        return existingWallet;
      }
      
      // ایجاد کیف پول جدید
      const wallet = new Wallet({
        user: userId,
        balance: 0,
        lockedBalance: 0,
        isActive: true,
        verification: {
          verified: false
        },
        dailyLimits: {
          maxDeposit: 50000000,
          maxWithdrawal: 20000000,
          lastResetDate: new Date()
        },
        stats: {
          totalTransactions: 0,
          successfulTransactions: 0,
          failedTransactions: 0
        }
      });
      
      await wallet.save();
      
      logger.info('کیف پول ایجاد شد', {
        walletId: wallet._id,
        userId
      });
      
      return wallet;
      
    } catch (error) {
      logger.error('خطا در ایجاد کیف پول', {
        userId,
        error: error.message
      });
      throw error;
    }
  }

  // دریافت اطلاعات کیف پول
  async getWallet(walletId, userId) {
    try {
      const wallet = await Wallet.findOne({
        _id: walletId,
        user: userId
      })
      .select('-__v')
      .lean();
      
      if (!wallet) {
        throw new Error('کیف پول یافت نشد');
      }
      
      // محاسبه موجودی قابل برداشت
      wallet.availableBalance = wallet.balance - wallet.lockedBalance;
      
      return wallet;
      
    } catch (error) {
      logger.error('خطا در دریافت کیف پول', {
        walletId,
        userId,
        error: error.message
      });
      throw error;
    }
  }
}

module.exports = new WalletService();