// src/middlewares/security.middleware.js - Security Middleware Collection
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');

class SecurityMiddleware {
  static helmet() {
    return helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          scriptSrc: ["'self'"],
          imgSrc: ["'self'", "data:", "https:"],
          fontSrc: ["'self'"],
          connectSrc: ["'self'"],
          frameSrc: ["'none'"],
          objectSrc: ["'none'"]
        }
      },
      hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
      }
    });
  }

  static cors(allowedOrigins = []) {
    const corsOptions = {
      origin: (origin, callback) => {
        // Allow requests with no origin (mobile apps, curl, etc.) in non-production
        if (!origin && process.env.NODE_ENV !== 'production') {
          return callback(null, true);
        }
        
        // Block requests with no origin in production
        if (!origin && process.env.NODE_ENV === 'production') {
          return callback(new Error('CORS policy requires origin'), false);
        }
        
        // Allow if origin is in allowed list
        if (allowedOrigins.includes(origin)) {
          return callback(null, true);
        }
        
        callback(new Error(`Origin ${origin} not allowed by CORS`), false);
      },
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'Accept', 'X-Request-ID'],
      maxAge: 86400
    };
    
    return cors(corsOptions);
  }

  static rateLimit(config = {}) {
    const defaultConfig = {
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 100,
      standardHeaders: true,
      legacyHeaders: false,
      message: {
        success: false,
        error: 'تعداد درخواست‌های شما بیش از حد مجاز است. لطفا بعدا تلاش کنید.',
        code: 'RATE_LIMIT_EXCEEDED'
      },
      skip: (req) => {
        // Skip for health checks and static files
        return req.path === '/health' || 
               req.path.startsWith('/uploads') ||
               req.path === '/favicon.ico';
      },
      keyGenerator: (req) => {
        // Use X-Forwarded-For header in production (behind proxy)
        return process.env.NODE_ENV === 'production' 
          ? req.headers['x-forwarded-for'] || req.ip
          : req.ip;
      }
    };
    
    return rateLimit({ ...defaultConfig, ...config });
  }

  static sanitize() {
    return mongoSanitize({
      replaceWith: '_',
      onSanitize: ({ req, key }) => {
        console.warn(`MongoDB injection attempt detected:`, {
          key,
          value: req.body[key],
          ip: req.ip,
          path: req.path
        });
      }
    });
  }

  static xssFilter() {
    return xss();
  }

  static apiRateLimiter(options = {}) {
    return rateLimit({
      windowMs: 15 * 60 * 1000,
      max: 100,
      standardHeaders: true,
      legacyHeaders: false,
      ...options
    });
  }

  static createAuthLimiter() {
    return rateLimit({
      windowMs: 15 * 60 * 1000,
      max: 5,
      skipSuccessfulRequests: true,
      keyGenerator: (req) => {
        const username = req.body.email || req.body.phone || req.body.username || 'unknown';
        return `${req.ip}_${username}`;
      },
      handler: (req, res) => {
        res.status(429).json({
          success: false,
          error: 'تعداد تلاش‌های ناموفق بیش از حد مجاز است. لطفاً 15 دقیقه دیگر تلاش کنید.',
          code: 'RATE_LIMIT_EXCEEDED'
        });
      }
    });
  }
}

module.exports = SecurityMiddleware;