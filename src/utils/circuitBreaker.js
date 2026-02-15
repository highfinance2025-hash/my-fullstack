// utils/circuitBreaker.js
const axios = require('axios');
const logger = require('./logger');

class CircuitBreaker {
  constructor(service, options = {}) {
    this.service = service;
    this.state = 'CLOSED';
    this.failureCount = 0;
    this.successCount = 0;
    this.nextAttempt = Date.now();
    
    this.options = {
      failureThreshold: 5,
      successThreshold: 2,
      timeout: 10000,
      resetTimeout: 30000,
      ...options
    };
  }

  async call(request) {
    if (this.state === 'OPEN') {
      if (this.nextAttempt > Date.now()) {
        logger.warn(`Circuit breaker OPEN for ${this.service.name}`);
        throw new Error('Service temporarily unavailable');
      }
      this.state = 'HALF_OPEN';
    }

    try {
      const response = await Promise.race([
        request(),
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Timeout')), this.options.timeout)
        )
      ]);

      this.success();
      return response;
    } catch (error) {
      this.failure(error);
      throw error;
    }
  }

  success() {
    this.failureCount = 0;
    this.successCount++;
    
    if (this.state === 'HALF_OPEN' && this.successCount >= this.options.successThreshold) {
      this.state = 'CLOSED';
      this.successCount = 0;
      logger.info(`Circuit breaker CLOSED for ${this.service.name}`);
    }
  }

  failure(error) {
    this.failureCount++;
    this.successCount = 0;
    
    if (this.failureCount >= this.options.failureThreshold) {
      this.state = 'OPEN';
      this.nextAttempt = Date.now() + this.options.resetTimeout;
      logger.error(`Circuit breaker OPENED for ${this.service.name}: ${error.message}`);
    }
  }
}

// استفاده:
const zarinpalBreaker = new CircuitBreaker({ name: 'Zarinpal' });

const paymentResult = await zarinpalBreaker.call(() => 
  axios.post('https://api.zarinpal.com/pg/v4/payment/request.json', data)
);