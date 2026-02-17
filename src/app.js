// src/app.js - Single Source of Truth (نسخه نهایی)
const express = require('express');
const path = require('path');
const config = require('./config/env.config');
const logger = require('./utils/logger');

// Middleware imports
const securityMiddleware = require('./middlewares/security.middleware');
const { ErrorMiddleware, asyncHandler } = require('./middlewares/error.middleware');
const { apiResponse } = require('./utils/api-response');

// Import routes
// Import routes
const walletRoutes = require('./routes/wallet.routes');
const authRoutes = require('./routes/auth.routes');
const productRoutes = require('./routes/product.routes');
const cartRoutes = require('./routes/cart.routes');
const orderRoutes = require('./routes/order.routes');
const addressRoutes = require('./routes/address.routes');
const profileRoutes = require('./routes/profile.routes');

class HTLandApp {
  constructor() {
    this.app = express();
    this.config = config;
    this.logger = logger;
    
    this.initializeMiddlewares();
    this.initializeRoutes();
    this.initializeErrorHandling();
    this.setupGracefulShutdown();
  }

  initializeMiddlewares() {
    // 🛡️ Security First
    this.app.use(securityMiddleware.helmet());
    this.app.use(securityMiddleware.cors(this.config.cors.allowedOrigins));
    this.app.use(securityMiddleware.rateLimit(this.config.rateLimit));
    this.app.use(securityMiddleware.sanitize());
    this.app.use(securityMiddleware.xssFilter());
    
    // 📊 Logging & Monitoring
    this.app.use(logger.middleware());
    
    // 🔄 Request Processing
    this.app.use(express.json({ 
      limit: this.config.file.maxSize || '10mb',
      verify: this.rawBodyMiddleware()
    }));
    
    this.app.use(express.urlencoded({ 
      extended: true, 
      limit: this.config.file.maxSize || '10mb' 
    }));
    
    // ✅ API Response Formatter
    this.app.use(apiResponse);
    
    // 🔍 Request ID for tracing
    this.app.use((req, res, next) => {
      req.id = req.headers['x-request-id'] || 
               Date.now().toString(36) + Math.random().toString(36).substr(2);
      res.setHeader('X-Request-ID', req.id);
      next();
    });
  }

  rawBodyMiddleware() {
    return (req, res, buf) => {
      if (buf && buf.length) {
        req.rawBody = buf.toString();
        
        // 🔐 Verify JSON is valid (security against malformed JSON attacks)
        try {
          if (req.is('application/json')) {
            JSON.parse(buf.toString());
          }
        } catch (e) {
          throw new Error('JSON ارسالی نامعتبر است');
        }
      }
    };
  }

  initializeRoutes() {
    // 🩺 Health Check (Public)
    this.app.get('/health', async (req, res) => {
      const health = await this.healthCheck();
      res.api.success(health, 'Service is healthy');
    });

    // 📚 API Documentation (Public)
    this.app.get('/api/docs', (req, res) => {
      res.api.success({
        service: 'HTLand Wallet API',
        version: this.config.app.version,
        environment: this.config.env,
        endpoints: this.getApiEndpoints(),
        documentation: 'https://docs.htland.ir',
        timestamp: new Date().toISOString()
      });
    });

    // 🛡️ Protected Routes (with rate limiting per endpoint)
    const apiLimiter = securityMiddleware.apiRateLimiter({
      windowMs: 15 * 60 * 1000,
      max: 100
    });

    // Authentication routes with stricter rate limiting
    const authLimiter = securityMiddleware.createAuthLimiter();
    
   this.app.use('/api/v1/auth', authLimiter, authRoutes);
this.app.use('/api/v1/wallet', apiLimiter, walletRoutes);
this.app.use('/api/v1/products', apiLimiter, productRoutes);
this.app.use('/api/v1/cart', apiLimiter, cartRoutes);
this.app.use('/api/v1/orders', apiLimiter, orderRoutes);
this.app.use('/api/v1/address', apiLimiter, addressRoutes);
this.app.use('/api/v1/profile', apiLimiter, profileRoutes);

    // 📁 Static Files (Secure)
    if (this.config.file?.uploadPath) {
      this.app.use('/uploads', express.static(
        path.resolve(this.config.file.uploadPath), 
        this.getStaticFileOptions()
      ));
    }
  }

  getApiEndpoints() {
    return {
      auth: {
        register: { method: 'POST', path: '/api/v1/auth/register', auth: false },
        login: { method: 'POST', path: '/api/v1/auth/login', auth: false },
        refresh: { method: 'POST', path: '/api/v1/auth/refresh', auth: true },
        logout: { method: 'POST', path: '/api/v1/auth/logout', auth: true }
      },
      wallet: {
        balance: { method: 'GET', path: '/api/v1/wallet/balance', auth: true },
        deposit: { method: 'POST', path: '/api/v1/wallet/deposit', auth: true },
        withdraw: { method: 'POST', path: '/api/v1/wallet/withdraw', auth: true },
        history: { method: 'GET', path: '/api/v1/wallet/history', auth: true }
      },
      products: {
        list: { method: 'GET', path: '/api/v1/products', auth: false },
        detail: { method: 'GET', path: '/api/v1/products/:id', auth: false },
        create: { method: 'POST', path: '/api/v1/products', auth: true },
        update: { method: 'PUT', path: '/api/v1/products/:id', auth: true },
        delete: { method: 'DELETE', path: '/api/v1/products/:id', auth: true }
      }
    };
  }

  getStaticFileOptions() {
    return {
      maxAge: this.config.env === 'production' ? '365d' : '1h',
      setHeaders: (res, filePath) => {
        // 🔒 Security headers for static files
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'DENY');
        res.setHeader('X-Content-Type-Options', 'nosniff');
        
        // 🚫 Prevent execution of uploaded files
        const executableRegex = /\.(php|exe|sh|bat|cmd|ps1|js|html)$/i;
        if (executableRegex.test(filePath)) {
          res.setHeader('Content-Type', 'text/plain');
          res.setHeader('Content-Disposition', 'inline');
        }
        
        // 🏷️ Cache control
        const imageRegex = /\.(jpg|jpeg|png|gif|webp|svg)$/i;
        if (imageRegex.test(filePath)) {
          res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
        }
        
        // 🔐 Prevent directory listing
        res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
      }
    };
  }

  async healthCheck() {
    const checks = {
      api: { 
        status: 'healthy', 
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
      },
      database: { status: 'unknown', latency: null },
      redis: { status: 'unknown', latency: null },
      payment: { status: 'unknown' },
      memory: {
        used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
        total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024),
        rss: Math.round(process.memoryUsage().rss / 1024 / 1024)
      },
      system: {
        platform: process.platform,
        nodeVersion: process.version,
        pid: process.pid
      }
    };

    try {
      // 🗄️ Database health check
      const database = require('./config/database.config');
      const dbHealth = await database.healthCheck();
      checks.database = dbHealth;

      // 🔄 Redis health check (if configured)
      if (this.config.redis?.url) {
        const redis = require('./config/redis.config');
        const redisHealth = await redis.healthCheck();
        checks.redis = redisHealth;
      }

      // 💳 Payment gateway health check
      if (this.config.payment?.zarinpal?.merchantId) {
        const zarinpalConfig = require('./config/zarinpal.config');
        const paymentHealth = await zarinpalConfig.healthCheck();
        checks.payment = paymentHealth;
      }

      // 💽 Disk space check
      const checkDiskSpace = require('check-disk-space').default;
      const diskSpace = await checkDiskSpace(__dirname);
      checks.disk = {
        free: Math.round(diskSpace.free / 1024 / 1024 / 1024),
        total: Math.round(diskSpace.size / 1024 / 1024 / 1024),
        path: diskSpace.diskPath
      };

      // ✅ Determine overall status
      const criticalServices = [dbHealth.status];
      if (checks.redis.status) criticalServices.push(checks.redis.status);
      
      const allHealthy = criticalServices.every(s => s === 'healthy');
      checks.overall = allHealthy ? 'healthy' : 'degraded';

    } catch (error) {
      checks.overall = 'unhealthy';
      checks.error = error.message;
      this.logger.error('Health check failed:', error);
    }

    return checks;
  }

  initializeErrorHandling() {
    // 404 Handler
    this.app.use(ErrorMiddleware.notFoundHandler);
    
    // Global Error Handler (MUST be last)
    this.app.use(ErrorMiddleware.errorHandler);
  }

  setupGracefulShutdown() {
    const shutdown = async (signal) => {
      this.logger.warn(`Received ${signal}, shutting down gracefully...`);
      
      // Wait for existing connections to close
      setTimeout(() => {
        this.logger.info('Graceful shutdown complete');
        process.exit(0);
      }, 10000);
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
  }

  getApp() {
    return this.app;
  }
}

// Singleton export
module.exports = new HTLandApp().getApp();