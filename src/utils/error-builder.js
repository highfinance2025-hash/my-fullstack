// src/utils/error-builder.js - Error Factory
class AppError extends Error {
  constructor(message, statusCode, code, details = null) {
    super(message);
    this.statusCode = statusCode;
    this.code = code || 'INTERNAL_ERROR';
    this.details = details;
    this.isOperational = true;
    this.timestamp = new Date().toISOString();
    
    Error.captureStackTrace(this, this.constructor);
  }
}

class ErrorBuilder {
  static validationError(errors) {
    return new AppError(
      'خطا در اعتبارسنجی داده‌ها',
      400,
      'VALIDATION_ERROR',
      { validationErrors: errors }
    );
  }

  static bulkValidationError(errors) {
    return new AppError(
      'خطا در اعتبارسنجی داده‌های دسته‌ای',
      400,
      'BULK_VALIDATION_ERROR',
      { bulkErrors: errors }
    );
  }

  static fromMongooseValidation(error) {
    const errors = Object.values(error.errors).map(err => ({
      field: err.path,
      message: err.message,
      type: err.kind,
      value: err.value
    }));

    return new AppError(
      'خطا در اعتبارسنجی داده‌های پایگاه داده',
      400,
      'MONGOOSE_VALIDATION_ERROR',
      { validationErrors: errors }
    );
  }

  static fromMongoDuplicate(error) {
    const field = Object.keys(error.keyPattern)[0];
    const value = error.keyValue[field];
    
    return new AppError(
      `مقدار '${value}' برای فیلد '${field}' تکراری است`,
      409,
      'DUPLICATE_KEY_ERROR',
      { field, value }
    );
  }

  static fromJwtError(error) {
    const messages = {
      'JsonWebTokenError': 'توکن نامعتبر است',
      'TokenExpiredError': 'توکن منقضی شده است',
      'NotBeforeError': 'توکن هنوز فعال نشده است'
    };

    return new AppError(
      messages[error.name] || 'خطا در احراز هویت',
      401,
      'JWT_ERROR',
      { jwtError: error.name }
    );
  }

  static fromJsonParseError(error) {
    return new AppError(
      'JSON ارسالی نامعتبر است',
      400,
      'INVALID_JSON',
      { syntaxError: error.message }
    );
  }

  static fromCastError(error) {
    return new AppError(
      `شناسه '${error.value}' نامعتبر است`,
      400,
      'INVALID_ID',
      { 
        field: error.path,
        value: error.value,
        kind: error.kind 
      }
    );
  }

  static fromUnknown(error) {
    // 🔐 Security: Hide internal errors in production
    const isProduction = process.env.NODE_ENV === 'production';
    
    return new AppError(
      isProduction ? 'خطای داخلی سرور' : error.message,
      500,
      'INTERNAL_ERROR',
      isProduction ? null : { originalError: error.message }
    );
  }

  static notFound(resource = 'منبع', id = null) {
    const message = id 
      ? `${resource} با شناسه '${id}' یافت نشد`
      : `${resource} یافت نشد`;
    
    return new AppError(message, 404, 'NOT_FOUND');
  }

  static unauthorized(message = 'دسترسی غیرمجاز') {
    return new AppError(message, 401, 'UNAUTHORIZED');
  }

  static forbidden(message = 'شما مجوز دسترسی به این بخش را ندارید') {
    return new AppError(message, 403, 'FORBIDDEN');
  }

  static rateLimit(message = 'تعداد درخواست‌های شما بیش از حد مجاز است') {
    return new AppError(message, 429, 'RATE_LIMIT_EXCEEDED');
  }

  static paymentFailed(message = 'پرداخت ناموفق بود') {
    return new AppError(message, 402, 'PAYMENT_FAILED');
  }

  static insufficientBalance(required, available) {
    return new AppError(
      'موجودی کافی نیست',
      400,
      'INSUFFICIENT_BALANCE',
      { required, available }
    );
  }
}

module.exports = {
  AppError,
  ErrorBuilder
};