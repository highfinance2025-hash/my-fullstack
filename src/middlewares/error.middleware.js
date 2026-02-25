// src/middlewares/error.middleware.js
const logger = require('../utils/logger');
const config = require('../config/env.config');
const { AppError, ErrorBuilder } = require('../utils/error-builder');

class ErrorMiddleware {
  // هندل کردن خطاهای 404
  static notFoundHandler(req, res, next) {
    const error = new AppError(
      `مسیر ${req.originalUrl} پیدا نشد`,
      404,
      'NOT_FOUND'
    );
    next(error);
  }

  // هندل کننده اصلی خطاها
  static errorHandler(err, req, res, next) {
    let error = err;

    // تبدیل خطاهای شناخته شده به AppError
    if (!(error instanceof AppError)) {
      if (error.name === 'ValidationError') {
        error = ErrorBuilder.fromMongooseValidation(error);
      } else if (error.code === 11000) {
        error = ErrorBuilder.fromMongoDuplicate(error);
      } else if (error.name === 'JsonWebTokenError') {
        error = ErrorBuilder.fromJwtError(error);
      } else if (error instanceof SyntaxError && error.status === 400 && 'body' in error) {
        error = ErrorBuilder.fromJsonParseError(error);
      } else if (error.name === 'CastError') {
        error = ErrorBuilder.fromCastError(error);
      } else {
        error = ErrorBuilder.fromUnknown(error);
      }
    }

    // ✅ اصلاح شده: صدا زدن متد استاتیک با نام کلاس
    ErrorMiddleware.logError(error, req);

    // آماده‌سازی پاسخ
    const response = {
      success: false,
      error: {
        message: error.message || 'خطای داخلی سرور',
        code: error.code || 'ERROR',
        timestamp: new Date().toISOString(),
        requestId: req.id
      }
    };

    // در محیط توسعه، جزئیات بیشتر نشان داده شود
    if (config.env !== 'production') {
      if (error.details) response.error.details = error.details;
      if (error.stack) response.error.stack = error.stack;
    }

    res.status(error.statusCode || 500).json(response);
  }

  // ✅ متد لاگ کردن (استاتیک)
  static logError(error, req) {
    const logData = {
      requestId: req.id,
      path: req.path,
      method: req.method,
      ip: req.ip,
      userId: req.user?.id,
      errorCode: error.code,
      statusCode: error.statusCode
    };

    if (error.statusCode >= 500) {
      logger.error('Server Error:', { ...logData, message: error.message, stack: error.stack });
    } else if (error.statusCode >= 400) {
      logger.warn('Client Error:', logData);
    } else {
      logger.info('Info:', logData);
    }
  }
}

// خروجی‌ها
const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

module.exports = {
  ErrorMiddleware,
  asyncHandler,
  notFoundHandler: ErrorMiddleware.notFoundHandler,
  errorHandler: ErrorMiddleware.errorHandler
};