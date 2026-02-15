const express = require('express');
const router = express.Router();
const walletController = require('../controllers/walletController');
const { validate, authMiddleware } = require('../middlewares/validation');

// همه routes نیاز به احراز هویت دارند
router.use(authMiddleware);

// ایجاد کیف پول جدید
router.post('/create', walletController.createWallet);

// دریافت اطلاعات کیف پول خاص
router.get('/:walletId', walletController.getWallet);

// دریافت تمام کیف پول‌های کاربر
router.get('/', walletController.getUserWallets);

// افزایش موجودی
router.post('/deposit', 
  validate('deposit'),
  walletController.deposit
);

// برداشت از کیف پول
router.post('/withdraw',
  validate('withdrawal'),
  walletController.withdraw
);

// قفل کردن موجودی
router.post('/lock',
  validate('lock'),
  walletController.lockBalance
);

// آزاد کردن موجودی قفل شده
router.post('/unlock',
  validate('unlock'),
  walletController.unlockBalance
);

module.exports = router;