const logger = require('../utils/logger');

const requestLogger = (req, res, next) => {
  req.startTime = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - req.startTime;
    const logData = {
      requestId: req.id,
      method: req.method,
      url: req.url,
      statusCode: res.statusCode,
      duration: `${duration}ms`,
      userAgent: req.get('user-agent'),
      ip: req.ip,
      userId: req.user?.id,
      contentLength: res.get('Content-Length') || 0
    };

    // Filter sensitive URLs
    if (req.url.includes('/auth') || req.url.includes('/payment')) {
      logData.url = req.url.split('?')[0]; // Remove query params
    }

    if (res.statusCode >= 500) {
      logger.error('Request error', logData);
    } else if (res.statusCode >= 400) {
      logger.warn('Request warning', logData);
    } else {
      logger.info('Request completed', logData);
    }
  });

  next();
};

const responseLogger = (req, res, next) => {
  const originalSend = res.send;
  
  res.send = function(data) {
    if (res.statusCode >= 400 && typeof data === 'string') {
      try {
        const parsed = JSON.parse(data);
        logger.debug('Error response', {
          requestId: req.id,
          error: parsed.error,
          code: parsed.code
        });
      } catch (e) {
        // Not JSON
      }
    }
    
    originalSend.call(this, data);
  };
  
  next();
};

module.exports = { requestLogger, responseLogger };