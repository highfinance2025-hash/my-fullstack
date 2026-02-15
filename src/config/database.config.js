const mongoose = require('mongoose');
const logger = require('../utils/logger');
const config = require('./env.config');

class Database {
  constructor() {
    this.connection = null;
    this.config = config.mongoose;
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 10;
    this.reconnectInterval = 5000;
    this.isConnecting = false;
  }

  async connect() {
    // جلوگیری از اتصال موازی
    if (this.isConnecting) {
      logger.warn('اتصال در حال انجام است...');
      return;
    }

    if (this.connection && mongoose.connection.readyState === 1) {
      logger.debug('MongoDB از قبل متصل است');
      return this.connection;
    }

    this.isConnecting = true;

    try {
      // تنظیمات mongoose
      mongoose.set('strictQuery', true);
      
      // تنظیمات connection
      const connectionOptions = {
        ...this.config.options,
        serverSelectionTimeoutMS: 15000, // افزایش timeout
        socketTimeoutMS: 45000,
        connectTimeoutMS: 30000,
        maxPoolSize: 50, // افزایش pool size برای تولید
        minPoolSize: 5,
        maxIdleTimeMS: 10000,
        waitQueueTimeoutMS: 10000,
        retryWrites: true,
        retryReads: true,
        family: 4 // فقط IPv4
      };

      // در production از replica set استفاده کن
      if (config.env === 'production') {
        connectionOptions.replicaSet = process.env.MONGO_REPLICA_SET || 'rs0';
        connectionOptions.readPreference = 'secondaryPreferred';
      }

      logger.info('🔄 در حال اتصال به MongoDB...', {
        environment: config.env,
        database: this._maskUrl(this.config.url)
      });

      this.connection = await mongoose.connect(this.config.url, connectionOptions);
      
      this.reconnectAttempts = 0; // reset counter
      
      logger.persian.success('MongoDB متصل شد', {
        database: mongoose.connection.db?.databaseName || 'unknown',
        host: mongoose.connection.host || 'unknown',
        port: mongoose.connection.port || 'unknown',
        readyState: this._getReadyStateName(mongoose.connection.readyState)
      });

      // ========================
      // 📡 Event Listeners
      // ========================
      
      // Connection error
      mongoose.connection.on('error', (err) => {
        logger.error('خطای اتصال MongoDB:', {
          error: err.message,
          code: err.code,
          name: err.name
        });
        
        // در تولید، reconnect اتوماتیک
        if (config.env === 'production' && !this.isConnecting) {
          this._handleReconnection();
        }
      });

      // Disconnected
      mongoose.connection.on('disconnected', () => {
        logger.warn('MongoDB قطع شد', {
          readyState: this._getReadyStateName(mongoose.connection.readyState)
        });
        
        if (config.env === 'production') {
          this._handleReconnection();
        }
      });

      // Connected
      mongoose.connection.on('connected', () => {
        logger.info('MongoDB متصل شد', {
          readyState: this._getReadyStateName(mongoose.connection.readyState)
        });
      });

      // Reconnected
      mongoose.connection.on('reconnected', () => {
        logger.success('MongoDB دوباره متصل شد', {
          attempt: this.reconnectAttempts
        });
        this.reconnectAttempts = 0;
      });

      // Close
      mongoose.connection.on('close', () => {
        logger.info('اتصال MongoDB بسته شد');
      });

      // Index creation
      mongoose.connection.on('index', (message) => {
        logger.debug('ایندکس MongoDB:', { message });
      });

      this.isConnecting = false;
      return this.connection;

    } catch (error) {
      this.isConnecting = false;
      
      logger.error('❌ اتصال به MongoDB ناموفق بود:', {
        error: error.message,
        code: error.code,
        name: error.name,
        url: this._maskUrl(this.config.url),
        attempt: this.reconnectAttempts + 1
      });

      // مدیریت خطاها
      if (error.name === 'MongoServerSelectionError') {
        logger.error('سرور MongoDB در دسترس نیست');
      } else if (error.name === 'MongoNetworkError') {
        logger.error('خطای شبکه در اتصال به MongoDB');
      } else if (error.name === 'MongoAuthenticationError') {
        logger.error('خطای احراز هویت MongoDB');
      }

      // در production reconnect اتوماتیک
      if (config.env === 'production' && this.reconnectAttempts < this.maxReconnectAttempts) {
        this._handleReconnection();
        return null;
      }

      // در development خطا را throw کن
      if (config.env === 'development') {
        throw error;
      }

      // در production اگر نتوانستیم وصل شویم، برنامه را متوقف کن
      if (config.env === 'production' && this.reconnectAttempts >= this.maxReconnectAttempts) {
        logger.fatal('تعداد مجاز reconnect به MongoDB تمام شد. برنامه متوقف می‌شود.');
        process.exit(1);
      }
    }
  }

  // ========================
  // 🔄 مدیریت Reconnection
  // ========================
  
  _handleReconnection() {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      logger.error(`حداکثر تلاش‌ها برای اتصال به MongoDB انجام شد (${this.maxReconnectAttempts} بار)`);
      return;
    }

    this.reconnectAttempts++;
    const delay = this.reconnectInterval * Math.pow(1.5, this.reconnectAttempts - 1); // Exponential backoff
    
    logger.warn(`تلاش مجدد برای اتصال به MongoDB (تلاش ${this.reconnectAttempts}/${this.maxReconnectAttempts})`, {
      delay: `${delay}ms`,
      nextAttemptIn: new Date(Date.now() + delay).toLocaleTimeString('fa-IR')
    });

    setTimeout(async () => {
      try {
        await this.connect();
      } catch (retryError) {
        logger.error('تلاش مجدد برای اتصال ناموفق بود:', {
          error: retryError.message,
          attempt: this.reconnectAttempts
        });
      }
    }, delay);
  }

  // ========================
  // ⚙️ متدهای کمکی
  // ========================

  async disconnect() {
    try {
      if (mongoose.connection.readyState !== 0) {
        await mongoose.disconnect();
        logger.persian.success('MongoDB قطع شد');
        this.connection = null;
      }
    } catch (error) {
      logger.error('خطا در قطع اتصال MongoDB:', {
        error: error.message
      });
      throw error;
    }
  }

  async healthCheck() {
    const healthData = {
      status: 'unhealthy',
      service: 'mongodb',
      timestamp: new Date().toISOString(),
      environment: config.env,
      readyState: this._getReadyStateName(mongoose.connection.readyState),
      readyStateCode: mongoose.connection.readyState,
      modelsCount: Object.keys(mongoose.connection.models).length,
      collectionsCount: 0,
      latency: 0
    };

    try {
      if (mongoose.connection.readyState !== 1) {
        healthData.error = 'اتصال برقرار نیست';
        return healthData;
      }

      const startTime = Date.now();
      const adminDb = mongoose.connection.db.admin();
      const pingResult = await adminDb.ping();
      const latency = Date.now() - startTime;

      // گرفتن اطلاعات دیتابیس
      const dbStats = await mongoose.connection.db.stats();
      const collections = await mongoose.connection.db.listCollections().toArray();

      healthData.status = pingResult.ok === 1 ? 'healthy' : 'degraded';
      healthData.ping = pingResult.ok === 1;
      healthData.latency = `${latency}ms`;
      healthData.database = {
        name: mongoose.connection.db.databaseName,
        size: `${(dbStats.dataSize / 1024 / 1024).toFixed(2)} MB`,
        collections: collections.length,
        indexes: dbStats.indexes,
        objects: dbStats.objects
      };
      healthData.connection = {
        host: mongoose.connection.host,
        port: mongoose.connection.port,
        poolSize: mongoose.connection.poolSize || 'unknown'
      };

      // بررسی critical thresholds
      if (dbStats.dataSize > 100 * 1024 * 1024) { // بیش از 100MB
        healthData.warnings = ['حجم دیتابیس در حال افزایش است'];
      }

    } catch (error) {
      healthData.error = error.message;
      healthData.stack = config.env === 'development' ? error.stack : undefined;
    }

    return healthData;
  }

  // ========================
  // 🛡️ Utility Methods
  // ========================

  _maskUrl(url) {
    if (!url) return 'unknown';
    // مخفی کردن username و password
    return url.replace(/\/\/(.*):(.*)@/, '//***:***@');
  }

  _getReadyStateName(state) {
    const states = {
      0: 'disconnected',
      1: 'connected',
      2: 'connecting',
      3: 'disconnecting',
      99: 'uninitialized'
    };
    return states[state] || `unknown (${state})`;
  }

  // ========================
  // 📊 اطلاعات دیتابیس
  // ========================

  async getDatabaseInfo() {
    try {
      if (mongoose.connection.readyState !== 1) {
        throw new Error('اتصال برقرار نیست');
      }

      const db = mongoose.connection.db;
      const [stats, collections] = await Promise.all([
        db.stats(),
        db.listCollections().toArray()
      ]);

      return {
        name: db.databaseName,
        size: {
          dataSize: `${(stats.dataSize / 1024 / 1024).toFixed(2)} MB`,
          storageSize: `${(stats.storageSize / 1024 / 1024).toFixed(2)} MB`,
          indexSize: `${(stats.indexSize / 1024 / 1024).toFixed(2)} MB`
        },
        collections: collections.map(col => ({
          name: col.name,
          type: col.type
        })),
        indexes: stats.indexes,
        objects: stats.objects,
        averageObjectSize: `${(stats.avgObjSize / 1024).toFixed(2)} KB`
      };
    } catch (error) {
      logger.error('خطا در دریافت اطلاعات دیتابیس:', {
        error: error.message
      });
      throw error;
    }
  }

  // ========================
  // 🔧 Connection Management
  // ========================

  getConnection() {
    return mongoose.connection;
  }

  getModel(name) {
    return mongoose.model(name);
  }

  isConnected() {
    return mongoose.connection.readyState === 1;
  }

  async waitForConnection(timeout = 30000) {
    if (this.isConnected()) {
      return true;
    }

    return new Promise((resolve, reject) => {
      const startTime = Date.now();
      
      const checkInterval = setInterval(() => {
        if (this.isConnected()) {
          clearInterval(checkInterval);
          resolve(true);
        }
        
        if (Date.now() - startTime > timeout) {
          clearInterval(checkInterval);
          reject(new Error(`Timeout waiting for MongoDB connection (${timeout}ms)`));
        }
      }, 100);
    });
  }
}

// ایجاد و export singleton instance
const database = new Database();

// Graceful shutdown handler
process.on('SIGTERM', async () => {
  logger.info('دریافت SIGTERM، قطع اتصال MongoDB...');
  await database.disconnect();
});

process.on('SIGINT', async () => {
  logger.info('دریافت SIGINT، قطع اتصال MongoDB...');
  await database.disconnect();
});

module.exports = database;