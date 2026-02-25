// src/middlewares/auth.middleware.js - Production Ready (نسخه نهایی اصلاح شده)
const jwt = require('jsonwebtoken');
const config = require('../config/env.config');
const logger = require('../utils/logger');
const { AppError, ErrorBuilder } = require('../utils/error-builder');
const User = require('../models/User.model');

class AuthMiddleware {
  static authenticate(roles = []) {
    return async (req, res, next) => {
      try {
        // 1. Get token from header
        const token = this.extractToken(req);
        
        if (!token) {
          throw new AppError('توکن احراز هویت ارسال نشده', 401, 'AUTH_REQUIRED');
        }

        // 2. Verify token
        const decoded = await this.verifyToken(token);
        
        // 3. Check token type (access vs refresh)
        if (decoded.type !== 'access') {
          throw new AppError('نوع توکن نامعتبر است', 401, 'INVALID_TOKEN_TYPE');
        }

        // 4. Check if user still exists
        const user = await this.findUserById(decoded.userId);
        
        if (!user) {
          throw new AppError('کاربر وجود ندارد', 401, 'USER_NOT_FOUND');
        }

        // 5. Check if user is active
        if (!user.isActive) {
          throw new AppError('حساب کاربری غیرفعال است', 403, 'ACCOUNT_INACTIVE');
        }

        // 6. Check if user changed password after token was issued
        if (this.isPasswordChanged(user, decoded.iat)) {
          throw new AppError('رمز عبور تغییر کرده است', 401, 'PASSWORD_CHANGED');
        }

        // 7. Check if token is in active sessions
        // Note: Sessions are optional, only check if they exist
        if (user.sessions && user.sessions.length > 0) {
          const activeSession = user.sessions.find(
            session => session.token === token && 
            session.isActive && 
            session.expiresAt > new Date()
          );
          
          if (!activeSession) {
            throw new AppError('توکن منقضی شده یا معتبر نیست', 401, 'INVALID_SESSION');
          }
        }

        // 8. Role-based authorization
        if (roles.length > 0 && !roles.includes(user.role)) {
          throw new AppError('دسترسی غیرمجاز', 403, 'FORBIDDEN');
        }

        // 9. Attach user to request
        req.user = {
          id: user._id || user.id,
          phone: user.phone,
          email: user.email,
          role: user.role || (user.isAdmin ? 'admin' : 'user'),
          permissions: user.permissions || [],
          isAdmin: user.isAdmin || false
        };

        // 10. Log successful authentication
        logger.info('User authenticated', {
          userId: user._id,
          ip: req.ip,
          userAgent: req.get('user-agent'),
          roles: roles.length > 0 ? roles : 'any'
        });

        next();

      } catch (error) {
        // 🛡️ Security: Don't expose specific JWT errors
        if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
          error = new AppError('توکن نامعتبر یا منقضی شده', 401, 'INVALID_TOKEN');
        }
        next(error);
      }
    };
  }

  static extractToken(req) {
    const authHeader = req.headers.authorization;
    
    if (authHeader && authHeader.startsWith('Bearer ')) {
      return authHeader.substring(7);
    }
    
    // Also check cookies for web applications
    return req.cookies?.accessToken || req.query?.token;
  }

  // ✅ تابع صحیح و واحد verifyToken
  static async verifyToken(token) {
    return new Promise((resolve, reject) => {
      const secret = process.env.JWT_SECRET || 'htland-secret-key';
      
      jwt.verify(token, secret, (err, decoded) => {
        if (err) {
          if (err.name === 'TokenExpiredError') {
            reject(new AppError('توکن منقضی شده', 401, 'TOKEN_EXPIRED'));
          } else {
            reject(new AppError('توکن نامعتبر', 401, 'INVALID_TOKEN'));
          }
        } else {
          resolve(decoded);
        }
      });
    });
  }

  static async findUserById(userId) {
    try {
      return await User.findById(userId)
        .select('_id phone email role permissions isActive isAdmin sessions passwordChangedAt')
        .lean();
    } catch (error) {
      logger.error('Error finding user:', error);
      return null;
    }
  }

  static isPasswordChanged(user, tokenIssuedAt) {
    if (!user.passwordChangedAt) return false;
    
    const changedTimestamp = Math.floor(user.passwordChangedAt.getTime() / 1000);
    return tokenIssuedAt < changedTimestamp;
  }

  // 🔐 Rate limiting for authentication endpoints
  static createAuthLimiter() {
    const rateLimit = require('express-rate-limit');
    
    return rateLimit({
      windowMs: 15 * 60 * 1000,
      max: 5,
      message: {
        success: false,
        error: 'تعداد تلاش‌های ناموفق بیش از حد مجاز',
        retryAfter: '15 دقیقه'
      },
      skipSuccessfulRequests: true,
      keyGenerator: (req) => {
        const username = req.body.email || req.body.phone || req.body.username || 'unknown';
        return `${req.ip}_${username}`;
      },
      handler: (req, res) => {
        logger.warn('Authentication rate limit exceeded', {
          ip: req.ip,
          username: req.body.email || req.body.phone || req.body.username,
          endpoint: req.path
        });
        
        res.status(429).json({
          success: false,
          error: 'تعداد تلاش‌های ناموفق بیش از حد مجاز است. لطفاً 15 دقیقه دیگر تلاش کنید.',
          code: 'RATE_LIMIT_EXCEEDED'
        });
      }
    });
  }

  // 🔄 Refresh token middleware
  static refreshToken(req, res, next) {
    const refreshToken = req.cookies?.refreshToken || req.body.refreshToken;
    
    if (!refreshToken) {
      return next(new AppError('Refresh token required', 400, 'REFRESH_TOKEN_REQUIRED'));
    }

    jwt.verify(refreshToken, config.jwt.secret, (err, decoded) => {
      if (err) {
        return next(new AppError('Refresh token invalid', 401, 'INVALID_REFRESH_TOKEN'));
      }

      if (decoded.type !== 'refresh') {
        return next(new AppError('Invalid token type', 401, 'INVALID_TOKEN_TYPE'));
      }

      req.userId = decoded.userId;
      next();
    });
  }

  // 👥 Role-based middleware generators
  static adminOnly() {
    return this.authenticate(['admin']);
  }

  static userOnly() {
    return this.authenticate(['user', 'admin']);
  }

  static merchantOnly() {
    return this.authenticate(['merchant', 'admin']);
  }

  // 📱 Validate Iranian phone number
  static validateIranianPhone(req, res, next) {
    const { phone } = req.body;
    
    if (!phone || !/^09[0-9]{9}$/.test(phone)) {
      return next(new AppError(
        'شماره موبایل معتبر نیست. لطفا شماره موبایل ایرانی وارد کنید.',
        400,
        'INVALID_PHONE'
      ));
    }
    
    next();
  }

  // 🔒 XSS Protection middleware
  static xssProtection(req, res, next) {
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    
    const sanitize = (obj) => {
      if (!obj || typeof obj !== 'object') return obj;
      
      Object.keys(obj).forEach(key => {
        if (typeof obj[key] === 'string') {
          obj[key] = obj[key]
            .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
            .replace(/<[^>]*>/g, '')
            .replace(/javascript:/gi, '')
            .replace(/on\w+=/gi, '');
        } else if (typeof obj[key] === 'object') {
          sanitize(obj[key]);
        }
      });
      
      return obj;
    };
    
    if (req.body) sanitize(req.body);
    if (req.query) sanitize(req.query);
    if (req.params) sanitize(req.params);
    
    next();
  }

  static authorize(roles = []) {
    return this.authenticate(roles);
  }
  
}

module.exports = AuthMiddleware;