const Joi = require('joi');

const validationSchemas = {
  // اعتبارسنجی واریز
  deposit: Joi.object({
    walletId: Joi.string().hex().length(24).required()
      .messages({
        'string.hex': 'شناسه کیف پول نامعتبر است',
        'string.length': 'شناسه کیف پول باید 24 کاراکتر باشد',
        'any.required': 'شناسه کیف پول الزامی است'
      }),
    amount: Joi.number().min(10000).max(50000000).required()
      .messages({
        'number.min': 'حداقل مبلغ واریز ۱۰,۰۰۰ تومان است',
        'number.max': 'حداکثر مبلغ واریز ۵۰,۰۰۰,۰۰۰ تومان است',
        'any.required': 'مبلغ الزامی است'
      }),
    description: Joi.string().max(200).optional()
      .messages({
        'string.max': 'توضیحات نمی‌تواند بیش از ۲۰۰ کاراکتر باشد'
      })
  }),
  
  // اعتبارسنجی برداشت
  withdrawal: Joi.object({
    walletId: Joi.string().hex().length(24).required()
      .messages({
        'string.hex': 'شناسه کیف پول نامعتبر است',
        'string.length': 'شناسه کیف پول باید 24 کاراکتر باشد',
        'any.required': 'شناسه کیف پول الزامی است'
      }),
    amount: Joi.number().min(10000).max(20000000).required()
      .messages({
        'number.min': 'حداقل مبلغ برداشت ۱۰,۰۰۰ تومان است',
        'number.max': 'حداکثر مبلغ برداشت ۲۰,۰۰۰,۰۰۰ تومان است',
        'any.required': 'مبلغ الزامی است'
      }),
    description: Joi.string().max(200).optional()
  }),
  
  // اعتبارسنجی قفل کردن
  lock: Joi.object({
    walletId: Joi.string().hex().length(24).required(),
    amount: Joi.number().min(1000).max(50000000).required()
  }),
  
  // اعتبارسنجی آزاد کردن
  unlock: Joi.object({
    walletId: Joi.string().hex().length(24).required(),
    amount: Joi.number().min(1000).max(50000000).required()
  })
};

const validate = (schemaName) => {
  return (req, res, next) => {
    const schema = validationSchemas[schemaName];
    
    if (!schema) {
      return res.status(500).json({
        success: false,
        error: 'Schema validation not found'
      });
    }
    
    const { error } = schema.validate(req.body, {
      abortEarly: false,
      convert: true
    });
    
    if (error) {
      const errors = error.details.map(detail => ({
        field: detail.path[0],
        message: detail.message
      }));
      
      return res.status(400).json({
        success: false,
        error: 'اعتبارسنجی ناموفق',
        details: errors
      });
    }
    
    next();
  };
};

// middleware ساده برای احراز هویت (موقت)
const authMiddleware = (req, res, next) => {
  // اینجا باید JWT token بررسی شود
  // برای تست، یک user ساختگی می‌گذاریم
  req.user = {
    id: '65a1b2c3d4e5f67890123456', // آی‌دی کاربر تستی
    email: 'test@htland.ir',
    role: 'user'
  };
  
  next();
};

module.exports = {
  validate,
  authMiddleware
};