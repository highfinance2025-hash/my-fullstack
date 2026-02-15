// utils/metrics.js
const client = require('prom-client');

class MetricsCollector {
  constructor() {
    this.register = new client.Registry();
    
    // HTTP Metrics
    this.httpRequestDuration = new client.Histogram({
      name: 'http_request_duration_seconds',
      help: 'Duration of HTTP requests in seconds',
      labelNames: ['method', 'route', 'status_code'],
      buckets: [0.1, 0.5, 1, 2, 5]
    });

    // Database Metrics
    this.dbQueryDuration = new client.Histogram({
      name: 'db_query_duration_seconds',
      help: 'Duration of database queries in seconds',
      labelNames: ['operation', 'collection'],
      buckets: [0.01, 0.05, 0.1, 0.5, 1]
    });

    // Business Metrics
    this.walletTransactions = new client.Counter({
      name: 'wallet_transactions_total',
      help: 'Total wallet transactions',
      labelNames: ['type', 'status']
    });

    this.register.registerMetric(this.httpRequestDuration);
    this.register.registerMetric(this.dbQueryDuration);
    this.register.registerMetric(this.walletTransactions);
  }

  startCollection() {
    client.collectDefaultMetrics({ register: this.register });
  }

  middleware() {
    return (req, res, next) => {
      const start = Date.now();
      
      res.on('finish', () => {
        const duration = (Date.now() - start) / 1000;
        const route = req.route?.path || req.url;
        
        this.httpRequestDuration
          .labels(req.method, route, res.statusCode)
          .observe(duration);
      });
      
      next();
    };
  }

  async getMetrics() {
    return await this.register.metrics();
  }
}