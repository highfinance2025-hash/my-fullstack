// utils/cacheManager.js
const NodeCache = require('node-cache');
const redis = require('../config/redis.config');

class CacheManager {
  constructor() {
    this.localCache = new NodeCache({ stdTTL: 300, checkperiod: 600 }); // 5 دقیقه
    this.useRedis = process.env.USE_REDIS === 'true';
  }

  async get(key) {
    // 1. بررسی کش لوکال
    const local = this.localCache.get(key);
    if (local) return local;

    if (this.useRedis) {
      // 2. بررسی Redis
      const redisData = await redis.get(key);
      if (redisData) {
        const parsed = JSON.parse(redisData);
        this.localCache.set(key, parsed); // ذخیره در کش لوکال
        return parsed;
      }
    }

    return null;
  }

  async set(key, value, ttl = 300) {
    this.localCache.set(key, value, ttl);
    
    if (this.useRedis) {
      await redis.setex(key, ttl, JSON.stringify(value));
    }
  }

  async invalidate(pattern) {
    this.localCache.keys().forEach(k => {
      if (k.includes(pattern)) {
        this.localCache.del(k);
      }
    });

    if (this.useRedis) {
      const keys = await redis.keys(`${pattern}*`);
      if (keys.length > 0) {
        await redis.del(...keys);
      }
    }
  }
}