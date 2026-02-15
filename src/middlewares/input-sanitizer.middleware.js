const xss = require('xss');
const { body, query, param } = require('express-validator');

const sanitizeInput = (req, res, next) => {
  // Sanitize request body
  if (req.body) {
    Object.keys(req.body).forEach(key => {
      if (typeof req.body[key] === 'string') {
        req.body[key] = xss(req.body[key].trim());
      }
    });
  }

  // Sanitize query parameters
  if (req.query) {
    Object.keys(req.query).forEach(key => {
      if (typeof req.query[key] === 'string') {
        req.query[key] = xss(req.query[key].trim());
      }
    });
  }

  // Sanitize URL parameters
  if (req.params) {
    Object.keys(req.params).forEach(key => {
      if (typeof req.params[key] === 'string') {
        req.params[key] = xss(req.params[key].trim());
      }
    });
  }

  next();
};

// Validation chains
const validateWalletCreation = [
  body('userId').isMongoId().withMessage('شناسه کاربر نامعتبر است'),
  body('balance').optional().isFloat({ min: 0 }).withMessage('موجودی باید عدد مثبت باشد'),
  body('currency').optional().isIn(['IRT', 'IRR', 'USD']).withMessage('ارز نامعتبر است')
];

const validatePayment = [
  body('amount').isFloat({ min: 1000 }).withMessage('مبلغ پرداخت باید حداقل ۱,۰۰۰ تومان باشد'),
  body('description').optional().isLength({ max: 500 }).withMessage('توضیحات نمی‌تواند بیش از ۵۰۰ کاراکتر باشد'),
  body('callbackUrl').isURL().withMessage('آدرس بازگشت نامعتبر است')
];

module.exports = { 
  sanitizeInput, 
  validateWalletCreation, 
  validatePayment 
};