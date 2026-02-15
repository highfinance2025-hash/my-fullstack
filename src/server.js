const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const path = require('path');
const mongoose = require('mongoose'); // اضافه شده برای اتصال به دیتابیس
const config = require('./config/env.config');
const logger = require('./utils/logger');

// ساده‌سازی مدیریت خطا برای جلوگیری از ارورهای احتمالی
const notFoundHandler = (req, res, next) => {
  res.status(404).json({ status: 'error', message: 'Not Found' });
};
const errorHandler = (err, req, res, next) => {
  logger.error(err.message);
  res.status(500).json({ status: 'error', message: 'Internal Server Error' });
};

const app = express();

// ========================
// SECURITY MIDDLEWARES
// ========================

app.use(helmet({
  contentSecurityPolicy: false, // برای راحتی توسعه غیرفعال شده
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true }
}));

// CORS Configuration
const corsOptions = {
  origin: config.cors.allowedOrigins || '*',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept']
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: config.rateLimit?.maxRequests || 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { status: 'error', message: 'Too many requests' }
});

app.use('/api/', limiter);

// ========================
// BASIC MIDDLEWARES
// ========================

app.use(compression({ threshold: 1024 }));
if (config.env !== 'test') {
  app.use(morgan(config.env === 'production' ? 'combined' : 'dev'));
}

// Request ID
app.use((req, res, next) => {
  req.id = Date.now().toString(36) + Math.random().toString(36).substr(2);
  res.setHeader('X-Request-ID', req.id);
  next();
});

// Body Parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ========================
// ROUTES
// ========================

// Health Check
app.get('/health', (req, res) => {
  const dbState = mongoose.connection.readyState;
  // 0 = disconnected, 1 = connected, 2 = connecting, 3 = disconnecting
  res.json({
    status: dbState === 1 ? 'healthy' : 'degraded',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    database: dbState === 1 ? 'connected' : 'disconnected',
    service: config.app.name
  });
});

// Mount API Routes
try {
  const apiRouter = require('./routes');
  app.use('/api/v1', apiRouter);
} catch (e) {
  logger.warn('Warning: routes/index.js missing');
  app.use('/api/v1', (req, res) => res.json({ message: 'API V1 Root - Routes missing' }));
}

// Static Files
if (config.file?.uploadPath) {
  app.use('/uploads', express.static(path.resolve(config.file.uploadPath)));
}

// Error Handlers
app.use(notFoundHandler);
app.use(errorHandler);

// ========================
// DATABASE CONNECTION & START SERVER
// ========================

const startServer = async () => {
  try {
    // اتصال به دیتابیس (MongoDB)
    const conn = await mongoose.connect(config.mongoose.url, config.mongoose.options);
    logger.info(`✅ MongoDB Connected: ${conn.connection.host}`);

    // روشن کردن سرور
    const PORT = config.port || 3000;
    app.listen(PORT, () => {
      logger.info(`🚀 Server running on port ${PORT}`);
      logger.info(`Environment: ${config.env}`);
      console.log(`------------------------------------------------`);
      console.log(`🚀 Server is live at http://localhost:${PORT}`);
      console.log(`------------------------------------------------`);
    });

  } catch (error) {
    logger.error(`❌ MongoDB Connection Error: ${error.message}`);
    console.error(`❌ Error: ${error.message}`);
    process.exit(1);
  }
};

startServer();

module.exports = app;