const express = require('express');
const router = express.Router();

// ✅ این خط اتصال به فایل auth.routes.js است
const authRoutes = require('./auth.routes');

// تعریف مسیرها
// هر درخواستی که با /api/v1/auth شروع بشه، میره به authRoutes
router.use('/auth', authRoutes);

// مسیر تستی اصلی
router.get('/', (req, res) => {
  res.json({ 
    message: 'HTLand API V1 is Running',
    endpoints: {
      auth: '/api/v1/auth/send-otp',
      health: '/health'
    }
  });
});

module.exports = router;