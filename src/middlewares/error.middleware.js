// src/middlewares/error.middleware.js - Production Grade (نسخه نهایی)
const logger = require('../utils/logger');
const config = require('../config/env.config');
const { AppError, ErrorBuilder } = require('../utils/error-builder');

class ErrorMiddleware {
  static notFoundHandler(req, res) {
    const error = new AppError(
      `مسیر ${req.originalUrl} پیدا نشد`,
      404,
      'NOT_FOUND',
      {
        method: req.method,
        path: req.originalUrl,
        requestId: req.id,
        timestamp: new Date().toISOString()
      }
    );
    
    throw error;
  }

  static errorHandler(err, req, res, next) {
    let error = err;
    
    // 🛡️ Security: Ensure error is an instance of AppError
    if (!(error instanceof AppError)) {
      // Mongoose Validation Error
      if (error.name === 'ValidationError') {
        error = ErrorBuilder.fromMongooseValidation(error);
      }
      // MongoDB Duplicate Key
      else if (error.code === 11000) {
        error = ErrorBuilder.fromMongoDuplicate(error);
      }
      // JWT Errors
      else if (error.name === 'JsonWebTokenError') {
        error = ErrorBuilder.fromJwtError(error);
      }
      // Syntax Error (malformed JSON)
      else if (error instanceof SyntaxError && error.status === 400 && 'body' in error) {
        error = ErrorBuilder.fromJsonParseError(error);
      }
      // Cast Error (invalid ID)
      else if (error.name === 'CastError') {
        error = ErrorBuilder.fromCastError(error);
      }
      // Rate limit error
      else if (error.name === 'RateLimitError') {
        error = ErrorBuilder.rateLimit(error.message);
      }
      // Default to internal server error
      else {
        error = ErrorBuilder.fromUnknown(error);
      }
    }

    // 📊 Log the error appropriately
    this.logError(error, req);

    // 🎯 Prepare response for client
    const response = {
      success: false,
      error: {
        message: this.getClientMessage(error),
        code: error.code || 'INTERNAL_ERROR',
        timestamp: new Date().toISOString(),
        requestId: req.id,
        ...(config.env !== 'production' && error.details && { details: error.details })
      }
    };

    // 🔐 Security: Don't expose stack trace in production
    if (config.env !== 'production' && error.stack) {
      response.error.stack = error.stack;
    }

    // 📝 Add validation errors if present
    if (error.validationErrors) {
      response.error.validation = error.validationErrors.map(err => ({
        field: err.field,
        message: err.message,
        type: err.type
      }));
    }

    // 📡 Send response
    res.status(error.statusCode || 500).json(response);
  }

  static logError(error, req) {
    const logData = {
      requestId: req.id,
      path: req.path,
      method: req.method,
      ip: req.ip,
      userId: req.user?.id,
      errorCode: error.code,
      statusCode: error.statusCode,
      isOperational: error.isOperational,
      userAgent: req.get('user-agent'),
      timestamp: new Date().toISOString()
    };

    if (error.statusCode >= 500) {
      // Server errors - log with full details
      logger.error('Server Error:', {
        ...logData,
        error: error.message,
        stack: error.stack,
        details: error.details
      });
    } else if (error.statusCode >= 400) {
      // Client errors - log warnings
      logger.warn('Client Error:', logData);
    } else {
      // Other errors
      logger.info('Application Error:', logData);
    }
  }

  static getClientMessage(error) {
    // 🎯 User-friendly messages in Farsi
    const messages = {
      VALIDATION_ERROR: 'خطا در اعتبارسنجی داده‌ها',
      AUTH_REQUIRED: 'برای دسترسی نیاز به ورود دارید',
      FORBIDDEN: 'دسترسی غیرمجاز',
      NOT_FOUND: 'منبع مورد نظر یافت نشد',
      DUPLICATE_KEY_ERROR: 'رکورد تکراری',
      INVALID_TOKEN: 'توکن معتبر نیست',
      TOKEN_EXPIRED: 'توکن منقضی شده است',
      RATE_LIMIT_EXCEEDED: 'تعداد درخواست‌های شما بیش از حد مجاز است',
      PAYMENT_FAILED: 'پرداخت ناموفق بود',
      INSUFFICIENT_BALANCE: 'موجودی کافی نیست',
      INTERNAL_ERROR: 'خطای داخلی سرور',
      INVALID_JSON: 'JSON ارسالی نامعتبر است',
      INVALID_PHONE: 'شماره موبایل معتبر نیست',
      ACCOUNT_INACTIVE: 'حساب کاربری غیرفعال است',
      PASSWORD_CHANGED: 'رمز عبور تغییر کرده است',
      INVALID_SESSION: 'جلسه کاربری معتبر نیست'
    };

    return messages[error.code] || error.message || 'خطای ناشناخته';
  }
}

// 🛡️ Async handler wrapper for controllers
const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

module.exports = {
  ErrorMiddleware,
  asyncHandler,
  notFoundHandler: ErrorMiddleware.notFoundHandler,
  errorHandler: ErrorMiddleware.errorHandler
};