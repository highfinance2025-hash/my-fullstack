// docs/swagger.js
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

const options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'HTLand API',
      version: '1.0.0',
      description: 'API Documentation برای سیستم HTLand',
      contact: {
        name: 'پشتیبانی HTLand',
        email: 'support@htland.ir'
      }
    },
    servers: [
      {
        url: process.env.API_URL || 'http://localhost:3000/api/v1',
        description: 'سرور توسعه'
      }
    ],
    components: {
      securitySchemes: {
        BearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT'
        }
      },
      schemas: {
        Wallet: {
          type: 'object',
          properties: {
            balance: {
              type: 'number',
              description: 'موجودی کیف پول'
            },
            lockedBalance: {
              type: 'number',
              description: 'موجودی قفل شده'
            }
          }
        }
      }
    }
  },
  apis: ['./routes/*.js'] // فایل‌های route
};

const specs = swaggerJsdoc(options);

module.exports = (app) => {
  app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(specs, {
    explorer: true,
    customCss: '.swagger-ui .topbar { display: none }',
    customSiteTitle: 'HTLand API Docs'
  }));
};