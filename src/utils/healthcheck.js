// utils/healthCheck.js
const mongoose = require('mongoose');
const redis = require('../config/redis.config');
const os = require('os');
const disk = require('diskusage');

class HealthChecker {
  async check() {
    const checks = [];

    // 1. Database Health
    const dbStart = Date.now();
    try {
      await mongoose.connection.db.admin().ping();
      checks.push({
        service: 'mongodb',
        status: 'healthy',
        latency: `${Date.now() - dbStart}ms`
      });
    } catch (error) {
      checks.push({
        service: 'mongodb',
        status: 'unhealthy',
        error: error.message
      });
    }

    // 2. Redis Health
    const redisStart = Date.now();
    try {
      await redis.ping();
      checks.push({
        service: 'redis',
        status: 'healthy',
        latency: `${Date.now() - redisStart}ms`
      });
    } catch (error) {
      checks.push({
        service: 'redis',
        status: 'unhealthy',
        error: error.message
      });
    }

    // 3. Memory Usage
    const memory = process.memoryUsage();
    const memoryUsage = (memory.heapUsed / memory.heapTotal) * 100;
    checks.push({
      service: 'memory',
      status: memoryUsage < 80 ? 'healthy' : 'warning',
      usage: `${memoryUsage.toFixed(2)}%`,
      details: {
        heapUsed: `${(memory.heapUsed / 1024 / 1024).toFixed(2)} MB`,
        heapTotal: `${(memory.heapTotal / 1024 / 1024).toFixed(2)} MB`,
        rss: `${(memory.rss / 1024 / 1024).toFixed(2)} MB`
      }
    });

    // 4. CPU Load
    const load = os.loadavg();
    checks.push({
      service: 'cpu',
      status: load[0] < os.cpus().length * 0.7 ? 'healthy' : 'warning',
      loadAverage: load.map(l => l.toFixed(2))
    });

    // 5. Disk Space
    try {
      const diskInfo = disk.checkSync('/');
      const diskUsage = ((diskInfo.total - diskInfo.free) / diskInfo.total) * 100;
      checks.push({
        service: 'disk',
        status: diskUsage < 90 ? 'healthy' : 'warning',
        usage: `${diskUsage.toFixed(2)}%`,
        free: `${(diskInfo.free / 1024 / 1024 / 1024).toFixed(2)} GB`
      });
    } catch (error) {
      checks.push({
        service: 'disk',
        status: 'unhealthy',
        error: error.message
      });
    }

    // 6. External Services
    const externalServices = await this.checkExternalServices();
    checks.push(...externalServices);

    return {
      status: checks.every(c => c.status === 'healthy') ? 'healthy' : 'degraded',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      version: process.env.APP_VERSION,
      checks
    };
  }

  async checkExternalServices() {
    const services = [];
    
    // زرین‌پال
    try {
      const response = await fetch('https://api.zarinpal.com/pg/v4/payment/health');
      services.push({
        service: 'zarinpal',
        status: response.ok ? 'healthy' : 'degraded',
        latency: `${Date.now() - start}ms`
      });
    } catch (error) {
      services.push({
        service: 'zarinpal',
        status: 'unhealthy',
        error: error.message
      });
    }

    return services;
  }
}