// src/utils/AppError.js

/**
 * کلاس خطای سفارشی
 */
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
  
  // متدهای استاتیک برای راحتی در استفاده
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