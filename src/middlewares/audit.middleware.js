// middlewares/audit.middleware.js
const logger = require('../utils/logger');

class AuditMiddleware {
  static logRequest(req, res, next) {
    const startTime = Date.now();
    const originalSend = res.send;

    // Intercept response
    res.send = function(body) {
      const duration = Date.now() - startTime;
      
      // لاگ درخواست
      logger.http('Request completed', {
        requestId: req.id,
        method: req.method,
        url: req.url,
        statusCode: res.statusCode,
        duration: `${duration}ms`,
        userId: req.user?.id,
        userAgent: req.get('user-agent'),
        ip: req.ip,
        query: Object.keys(req.query).length > 0 ? req.query : undefined,
        params: Object.keys(req.params).length > 0 ? req.params : undefined,
        responseSize: typeof body === 'string' ? Buffer.byteLength(body) : 0
      });

      // Audit log برای درخواست‌های حساس
      if (this.shouldAudit(req)) {
        this.auditLog(req, res, duration, body);
      }

      return originalSend.call(this, body);
    }.bind(this);

    next();
  }

  static shouldAudit(req) {
    const sensitivePaths = ['/auth/login', '/auth/register', '/wallet/withdraw', '/payment'];
    const sensitiveMethods = ['POST', 'PUT', 'DELETE'];
    
    return sensitiveMethods.includes(req.method) || 
           sensitivePaths.some(path => req.url.includes(path));
  }

  static async auditLog(req, res, duration, responseBody) {
    const auditData = {
      requestId: req.id,
      timestamp: new Date().toISOString(),
      userId: req.user?.id,
      action: `${req.method} ${req.url}`,
      ip: req.ip,
      userAgent: req.get('user-agent'),
      duration,
      statusCode: res.statusCode,
      requestBody: this.sanitize(req.body), // حذف اطلاعات حساس
      responseBody: this.sanitize(JSON.parse(responseBody || '{}'))
    };

    // ذخیره در دیتابیس یا Elasticsearch
    await AuditLog.create(auditData);
  }

  static sanitize(data) {
    const sensitiveFields = ['password', 'token', 'secret', 'creditCard', 'cvv'];
    
    const sanitized = { ...data };
    sensitiveFields.forEach(field => {
      if (sanitized[field]) {
        sanitized[field] = '***HIDDEN***';
      }
    });
    
    return sanitized;
  }
}