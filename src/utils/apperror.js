/**
 * کلاس خطای سفارشی
 */
class AppError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode;
    this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
    this.isOperational = true;
    
    Error.captureStackTrace(this, this.constructor);
  }
}

module.exports = AppError;
// error.middleware.js - نسخه نهایی
const logger = require('../utils/logger');
const AppError = require('../utils/AppError'); // <-- این خط اضافه شه

const notFoundHandler = (req, res) => {
  res.status(404).json({
    success: false,
    error: 'مسیر یافت نشد',
    path: req.originalUrl,
    requestId: req.id
  });
};

const errorHandler = (err, req, res, next) => {
  // استفاده از AppError اگر نبود
  if (!(err instanceof AppError)) {
    err = AppError.internal(err.message);
  }

  // لاگ خطا
  logger.error('Error occurred:', {
    requestId: req.id,
    error: err.message,
    stack: err.stack,
    statusCode: err.statusCode,
    path: req.path,
    method: req.method,
    ip: req.ip,
    userId: req.user?.id,
    isOperational: err.isOperational
  });

  // ثبت متریک
  if (logger.metrics) {
    logger.metrics.recordError(err.name, req.path);
  }

  // پاسخ به کاربر
  const isProduction = process.env.NODE_ENV === 'production';
  const response = {
    success: false,
    error: isProduction && !err.isOperational ? 'خطای داخلی سرور' : err.message,
    requestId: req.id,
    timestamp: new Date().toISOString()
  };

  // جزئیات فقط در non-production
  if (!isProduction && err.details) {
    response.details = err.details;
  }

  // stack trace فقط در development
  if (!isProduction && err.stack) {
    response.stack = err.stack;
  }

  res.status(err.statusCode || 500).json(response);
};

// Wrapper برای async functions
const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

module.exports = {
  notFoundHandler,
  errorHandler,
  asyncHandler,
  AppError // <-- این خط اضافه شه
};
// utils/AppError.js - کلاس خطای سفارشی
class AppError extends Error {
  constructor(message, statusCode, isOperational = true, details = null) {
    super(message);
    
    this.name = this.constructor.name;
    this.statusCode = statusCode;
    this.isOperational = isOperational;
    this.details = details;
    this.timestamp = new Date().toISOString();
    
    Error.captureStackTrace(this, this.constructor);
  }
  
  static badRequest(message = 'درخواست نامعتبر', details = null) {
    return new AppError(message, 400, true, details);
  }
  
  static unauthorized(message = 'دسترسی غیرمجاز') {
    return new AppError(message, 401, true);
  }
  
  static forbidden(message = 'ممنوع') {
    return new AppError(message, 403, true);
  }
  
  static notFound(message = 'پیدا نشد') {
    return new AppError(message, 404, true);
  }
  
  static internal(message = 'خطای داخلی سرور') {
    return new AppError(message, 500, false);
  }
  
  static validation(errors) {
    return new AppError('خطای اعتبارسنجی', 400, true, { errors });
  }
}

module.exports = AppError;