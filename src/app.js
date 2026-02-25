const express = require('express');
const path = require('path');
const config = require('./config/env.config');
const logger = require('./utils/logger');

// ✅ اضافه کردن Swagger
const swaggerUi = require('swagger-ui-express');
const swaggerSpec = require('./config/swagger.config');

// Middleware imports
const securityMiddleware = require('./middlewares/security.middleware');
const { ErrorMiddleware } = require('./middlewares/error.middleware');
const { apiResponse } = require('./utils/api-response');

// Import routes
const walletRoutes = require('./routes/wallet.routes');
const authRoutes = require('./routes/auth.routes');
const productRoutes = require('./routes/product.routes');
// ✅ اضافه کردن index routes
const indexRoutes = require('./routes/index');

class HTLandApp {
  constructor() {
    this.app = express();
    this.config = config;
    this.logger = logger;
    
    this.initializeMiddlewares();
    this.initializeRoutes();
    this.initializeFrontendServing(); // ✅ اضافه شده برای سرو فایل‌های ریشه
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
      limit: this.config?.file?.maxSize || '20mb',
      verify: this.rawBodyMiddleware()
    }));
    
    this.app.use(express.urlencoded({ 
      extended: true, 
     limit: this.config?.file?.maxSize || '20mb',
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

    // ✅ Index Route - خوش آمدگویی
    this.app.use('/', indexRoutes);

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

    // ✅ Swagger Documentation (فقط در محیط توسعه)
    if (this.config.env !== 'production') {
      this.app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));
      console.log('📚 Swagger docs available at /api-docs');
    }

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

    // 📁 Static Files (Secure) - فایل‌های آپلود شده کاربران
    if (this.config.file?.uploadPath) {
      this.app.use('/uploads', express.static(
        path.resolve(this.config.file.uploadPath), 
        this.getStaticFileOptions()
      ));
    }
  }

  // ✅ متد جدید: سرو کردن فایل‌های فرانت‌اند (index.html, css, js)
  initializeFrontendServing() {
    // مسیر ریشه پروژه (خروج از پوشه src)
    const rootPath = path.resolve(__dirname, '..');

    // سرو کردن پوشه‌های استاتیک موجود در ریشه پروژه
    this.app.use('/css', express.static(path.join(rootPath, 'css')));
    this.app.use('/js', express.static(path.join(rootPath, 'js')));
    this.app.use('/images', express.static(path.join(rootPath, 'images')));

    // سرو کردن فایل index.html اصلی
    this.app.get('/', (req, res) => {
      res.sendFile(path.join(rootPath, 'index.html'));
    });
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
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'DENY');
        
        const executableRegex = /\.(php|exe|sh|bat|cmd|ps1|js|html)$/i;
        if (executableRegex.test(filePath)) {
          res.setHeader('Content-Type', 'text/plain');
          res.setHeader('Content-Disposition', 'inline');
        }
        
        const imageRegex = /\.(jpg|jpeg|png|gif|webp|svg)$/i;
        if (imageRegex.test(filePath)) {
          res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
        }
        
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
      const database = require('./config/database.config');
      const dbHealth = await database.healthCheck();
      checks.database = dbHealth;

      if (this.config.redis?.url) {
        const redis = require('./config/redis.config');
        const redisHealth = await redis.healthCheck();
        checks.redis = redisHealth;
      }

      if (this.config.payment?.zarinpal?.merchantId) {
        const zarinpalConfig = require('./config/zarinpal.config');
        const paymentHealth = await zarinpalConfig.healthCheck();
        checks.payment = paymentHealth;
      }

      const criticalServices = [checks.database.status];
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
    this.app.use(ErrorMiddleware.notFoundHandler);
    this.app.use(ErrorMiddleware.errorHandler);
  }

  setupGracefulShutdown() {
    const shutdown = async (signal) => {
      this.logger.warn(`Received ${signal}, shutting down gracefully...`);
      
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

module.exports = new HTLandApp().getApp();