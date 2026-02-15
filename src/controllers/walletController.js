const walletService = require('../services/walletService');
const Wallet = require('../models/Wallet.model');
const logger = require('../utils/logger');

class WalletController {
  // ایجاد کیف پول
  async createWallet(req, res) {
    try {
      const userId = req.user.id; // از middleware احراز هویت
      
      const wallet = await walletService.createWallet(userId);
      
      res.status(201).json({
        success: true,
        message: 'کیف پول با موفقیت ایجاد شد',
        data: {
          walletId: wallet._id,
          balance: wallet.balance,
          availableBalance: wallet.balance - wallet.lockedBalance,
          createdAt: wallet.createdAt
        }
      });
      
    } catch (error) {
      logger.error('Create wallet error:', {
        error: error.message,
        userId: req.user?.id
      });
      
      res.status(500).json({
        success: false,
        error: 'خطا در ایجاد کیف پول'
      });
    }
  }

  // دریافت اطلاعات کیف پول
  async getWallet(req, res) {
    try {
      const { walletId } = req.params;
      const userId = req.user.id;
      
      const wallet = await walletService.getWallet(walletId, userId);
      
      res.json({
        success: true,
        data: wallet
      });
      
    } catch (error) {
      logger.error('Get wallet error:', {
        error: error.message,
        walletId: req.params.walletId,
        userId: req.user?.id
      });
      
      if (error.message === 'کیف پول یافت نشد') {
        return res.status(404).json({
          success: false,
          error: error.message
        });
      }
      
      res.status(500).json({
        success: false,
        error: 'خطا در دریافت اطلاعات کیف پول'
      });
    }
  }

  // افزایش موجودی
  async deposit(req, res) {
    try {
      const { walletId, amount, description } = req.body;
      const userId = req.user.id;
      
      // اعتبارسنجی اولیه
      if (!walletId || !amount) {
        return res.status(400).json({
          success: false,
          error: 'walletId و amount الزامی هستند'
        });
      }
      
      const wallet = await walletService.increaseBalance(
        walletId,
        amount,
        userId,
        {
          description: description || 'واریز به کیف پول'
        }
      );
      
      res.json({
        success: true,
        message: 'موجودی با موفقیت افزایش یافت',
        data: {
          walletId: wallet._id,
          newBalance: wallet.balance,
          availableBalance: wallet.balance - wallet.lockedBalance,
          depositCount: wallet.dailyLimits.depositCount,
          timestamp: new Date()
        }
      });
      
    } catch (error) {
      logger.error('Deposit error:', {
        error: error.message,
        body: req.body,
        userId: req.user?.id
      });
      
      const statusCode = error.message.includes('یافت نشد') ? 404 : 400;
      
      res.status(statusCode).json({
        success: false,
        error: error.message
      });
    }
  }

  // برداشت از کیف پول
  async withdraw(req, res) {
    try {
      const { walletId, amount, description } = req.body;
      const userId = req.user.id;
      
      if (!walletId || !amount) {
        return res.status(400).json({
          success: false,
          error: 'walletId و amount الزامی هستند'
        });
      }
      
      const wallet = await walletService.decreaseBalance(
        walletId,
        amount,
        userId,
        {
          description: description || 'برداشت از کیف پول'
        }
      );
      
      res.json({
        success: true,
        message: 'برداشت با موفقیت انجام شد',
        data: {
          walletId: wallet._id,
          newBalance: wallet.balance,
          availableBalance: wallet.balance - wallet.lockedBalance,
          withdrawalCount: wallet.dailyLimits.withdrawalCount,
          timestamp: new Date()
        }
      });
      
    } catch (error) {
      logger.error('Withdraw error:', {
        error: error.message,
        body: req.body,
        userId: req.user?.id
      });
      
      const statusCode = error.message.includes('یافت نشد') ? 404 : 400;
      
      res.status(statusCode).json({
        success: false,
        error: error.message
      });
    }
  }

  // قفل کردن موجودی
  async lockBalance(req, res) {
    try {
      const { walletId, amount } = req.body;
      const userId = req.user.id;
      
      if (!walletId || !amount) {
        return res.status(400).json({
          success: false,
          error: 'walletId و amount الزامی هستند'
        });
      }
      
      const wallet = await walletService.lockBalance(walletId, amount, userId);
      
      res.json({
        success: true,
        message: 'موجودی با موفقیت قفل شد',
        data: {
          walletId: wallet._id,
          lockedBalance: wallet.lockedBalance,
          availableBalance: wallet.balance - wallet.lockedBalance,
          timestamp: new Date()
        }
      });
      
    } catch (error) {
      logger.error('Lock balance error:', {
        error: error.message,
        body: req.body,
        userId: req.user?.id
      });
      
      res.status(400).json({
        success: false,
        error: error.message
      });
    }
  }

  // آزاد کردن موجودی
  async unlockBalance(req, res) {
    try {
      const { walletId, amount } = req.body;
      const userId = req.user.id;
      
      if (!walletId || !amount) {
        return res.status(400).json({
          success: false,
          error: 'walletId و amount الزامی هستند'
        });
      }
      
      const wallet = await walletService.unlockBalance(walletId, amount, userId);
      
      res.json({
        success: true,
        message: 'موجودی با موفقیت آزاد شد',
        data: {
          walletId: wallet._id,
          lockedBalance: wallet.lockedBalance,
          availableBalance: wallet.balance - wallet.lockedBalance,
          timestamp: new Date()
        }
      });
      
    } catch (error) {
      logger.error('Unlock balance error:', {
        error: error.message,
        body: req.body,
        userId: req.user?.id
      });
      
      res.status(400).json({
        success: false,
        error: error.message
      });
    }
  }

  // لیست کیف پول‌های کاربر
  async getUserWallets(req, res) {
    try {
      const userId = req.user.id;
      
      const wallets = await Wallet.find({ user: userId })
        .select('-__v -verification.nationalId')
        .sort({ createdAt: -1 })
        .lean();
      
      // محاسبه موجودی قابل برداشت برای هر کیف پول
      const walletsWithAvailableBalance = wallets.map(wallet => ({
        ...wallet,
        availableBalance: wallet.balance - wallet.lockedBalance
      }));
      
      res.json({
        success: true,
        data: {
          wallets: walletsWithAvailableBalance,
          totalWallets: wallets.length,
          totalBalance: wallets.reduce((sum, w) => sum + w.balance, 0),
          totalAvailableBalance: wallets.reduce((sum, w) => sum + (w.balance - w.lockedBalance), 0)
        }
      });
      
    } catch (error) {
      logger.error('Get user wallets error:', {
        error: error.message,
        userId: req.user?.id
      });
      
      res.status(500).json({
        success: false,
        error: 'خطا در دریافت کیف پول‌ها'
      });
    }
  }
}

module.exports = new WalletController();