// tests/load/load.test.js - تست بار
const loadtest = require('loadtest');
const config = require('../../config/env.config');

describe('Load Testing', () => {
  const baseUrl = `http://localhost:${config.port}`;

  test('باید ۱۰۰ درخواست همزمان را مدیریت کند', async () => {
    const options = {
      url: `${baseUrl}/api/v1/products`,
      maxRequests: 100,
      concurrency: 10,
      method: 'GET',
      contentType: 'application/json',
      statusCallback: (error, result, latency) => {
        if (error) {
          console.error('Request error:', error);
        }
      }
    };

    return new Promise((resolve, reject) => {
      loadtest.loadTest(options, (error, results) => {
        if (error) {
          return reject(error);
        }
        
        console.log('Load test results:', {
          totalRequests: results.totalRequests,
          totalErrors: results.totalErrors,
          meanLatencyMs: results.meanLatencyMs,
          rps: results.rps
        });

        expect(results.totalErrors).toBe(0);
        expect(results.meanLatencyMs).toBeLessThan(500);
        resolve();
      });
    });
  }, 30000);
});