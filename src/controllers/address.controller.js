/**
 * @file کنترلر مدیریت آدرس‌های کاربران HTLand
 * @description عملیات CRUD برای آدرس‌های تحویل محصولات ارگانیک
 * @since 1403/10/01
 */

const asyncHandler = require('express-async-handler');
const Address = require('../models/Address.model');
const addressService = require('../services/addressService');
const { validateAddressInput } = require('../middlewares/address.middleware');

/**
 * @desc    دریافت لیست آدرس‌های کاربر
 * @route   GET /api/v1/addresses
 * @access  Private
 * @swagger
 * /api/v1/addresses:
 *   get:
 *     summary: دریافت لیست آدرس‌های کاربر
 *     tags: [Addresses]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: لیست آدرس‌های کاربر
 *       401:
 *         description: کاربر لاگین نکرده است
 */
const getAddresses = asyncHandler(async (req, res) => {
  const userId = req.user._id;
  
  const addresses = await addressService.getUserAddresses(userId);
  
  res.status(200).json({
    success: true,
    count: addresses.length,
    data: addresses
  });
});

/**
 * @desc    دریافت یک آدرس خاص
 * @route   GET /api/v1/addresses/:id
 * @access  Private
 * @swagger
 * /api/v1/addresses/{id}:
 *   get:
 *     summary: دریافت یک آدرس خاص
 *     tags: [Addresses]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: شناسه آدرس
 *     responses:
 *       200:
 *         description: اطلاعات آدرس
 *       404:
 *         description: آدرس پیدا نشد
 */
const getAddressById = asyncHandler(async (req, res) => {
  const addressId = req.params.id;
  const userId = req.user._id;
  
  const address = await addressService.getAddressById(addressId, userId);
  
  if (!address) {
    return res.status(404).json({
      success: false,
      error: 'آدرس پیدا نشد'
    });
  }
  
  res.status(200).json({
    success: true,
    data: address
  });
});

/**
 * @desc    ایجاد آدرس جدید
 * @route   POST /api/v1/addresses
 * @access  Private
 * @swagger
 * /api/v1/addresses:
 *   post:
 *     summary: ایجاد آدرس جدید
 *     tags: [Addresses]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - fullName
 *               - phone
 *               - province
 *               - city
 *               - address
 *               - postalCode
 *             properties:
 *               fullName:
 *                 type: string
 *                 example: "علی رضایی"
 *               phone:
 *                 type: string
 *                 example: "09123456789"
 *               province:
 *                 type: string
 *                 example: "مازندران"
 *               city:
 *                 type: string
 *                 example: "ساری"
 *               address:
 *                 type: string
 *                 example: "بلوار طالقانی، برج پاسارگاد، طبقه ۴"
 *               postalCode:
 *                 type: string
 *                 example: "4816653157"
 *               isDefault:
 *                 type: boolean
 *                 default: false
 *               label:
 *                 type: string
 *                 enum: [خانه, کار, فامیل, دیگر]
 *                 default: "خانه"
 *               buildingNumber:
 *                 type: string
 *                 example: "۱۲"
 *               unit:
 *                 type: string
 *                 example: "۴"
 *               floor:
 *                 type: string
 *                 example: "۲"
 *               description:
 *                 type: string
 *                 example: "زنگ بزنید و تحویل بگیرید"
 *     responses:
 *       201:
 *         description: آدرس با موفقیت ایجاد شد
 *       400:
 *         description: داده‌های ورودی معتبر نیست
 *       409:
 *         description: کاربر قبلاً حداکثر آدرس مجاز را دارد
 */
const createAddress = [
  validateAddressInput,
  asyncHandler(async (req, res) => {
    const userId = req.user._id;
    const addressData = req.body;
    
    // بررسی تعداد آدرس‌های کاربر
    const addressCount = await addressService.getUserAddressCount(userId);
    if (addressCount >= 3) {
      return res.status(409).json({
        success: false,
        error: 'هر کاربر می‌تواند حداکثر ۳ آدرس فعال داشته باشد'
      });
    }
    
    const address = await addressService.createAddress(userId, addressData);
    
    res.status(201).json({
      success: true,
      message: 'آدرس جدید با موفقیت ایجاد شد',
      data: address
    });
  })
];

/**
 * @desc    ویرایش آدرس
 * @route   PUT /api/v1/addresses/:id
 * @access  Private
 * @swagger
 * /api/v1/addresses/{id}:
 *   put:
 *     summary: ویرایش آدرس
 *     tags: [Addresses]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: شناسه آدرس
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               fullName:
 *                 type: string
 *               phone:
 *                 type: string
 *               province:
 *                 type: string
 *               city:
 *                 type: string
 *               address:
 *                 type: string
 *               postalCode:
 *                 type: string
 *               isDefault:
 *                 type: boolean
 *               label:
 *                 type: string
 *               buildingNumber:
 *                 type: string
 *               unit:
 *                 type: string
 *               floor:
 *                 type: string
 *               description:
 *                 type: string
 *     responses:
 *       200:
 *         description: آدرس با موفقیت ویرایش شد
 *       404:
 *         description: آدرس پیدا نشد
 *       403:
 *         description: دسترسی غیرمجاز
 */
const updateAddress = [
  validateAddressInput,
  asyncHandler(async (req, res) => {
    const addressId = req.params.id;
    const userId = req.user._id;
    const updateData = req.body;
    
    const address = await addressService.updateAddress(addressId, userId, updateData);
    
    if (!address) {
      return res.status(404).json({
        success: false,
        error: 'آدرس پیدا نشد یا دسترسی غیرمجاز است'
      });
    }
    
    res.status(200).json({
      success: true,
      message: 'آدرس با موفقیت ویرایش شد',
      data: address
    });
  })
];

/**
 * @desc    حذف آدرس
 * @route   DELETE /api/v1/addresses/:id
 * @access  Private
 * @swagger
 * /api/v1/addresses/{id}:
 *   delete:
 *     summary: حذف آدرس
 *     tags: [Addresses]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: شناسه آدرس
 *     responses:
 *       200:
 *         description: آدرس با موفقیت حذف شد
 *       404:
 *         description: آدرس پیدا نشد
 *       403:
 *         description: دسترسی غیرمجاز
 *       400:
 *         description: نمی‌توان آدرس پیش‌فرض را حذف کرد
 */
const deleteAddress = asyncHandler(async (req, res) => {
  const addressId = req.params.id;
  const userId = req.user._id;
  
  const result = await addressService.deleteAddress(addressId, userId);
  
  if (!result) {
    return res.status(404).json({
      success: false,
      error: 'آدرس پیدا نشد یا دسترسی غیرمجاز است'
    });
  }
  
  res.status(200).json({
    success: true,
    message: 'آدرس با موفقیت حذف شد',
    data: { id: addressId }
  });
});

/**
 * @desc    تنظیم آدرس به عنوان پیش‌فرض
 * @route   POST /api/v1/addresses/:id/set-default
 * @access  Private
 * @swagger
 * /api/v1/addresses/{id}/set-default:
 *   post:
 *     summary: تنظیم آدرس به عنوان پیش‌فرض
 *     tags: [Addresses]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: شناسه آدرس
 *     responses:
 *       200:
 *         description: آدرس با موفقیت پیش‌فرض شد
 *       404:
 *         description: آدرس پیدا نشد
 *       403:
 *         description: دسترسی غیرمجاز
 */
const setDefaultAddress = asyncHandler(async (req, res) => {
  const addressId = req.params.id;
  const userId = req.user._id;
  
  const address = await addressService.setDefaultAddress(addressId, userId);
  
  if (!address) {
    return res.status(404).json({
      success: false,
      error: 'آدرس پیدا نشد یا دسترسی غیرمجاز است'
    });
  }
  
  res.status(200).json({
    success: true,
    message: 'آدرس با موفقیت به عنوان پیش‌فرض تنظیم شد',
    data: address
  });
});

/**
 * @desc    دریافت آدرس پیش‌فرض کاربر
 * @route   GET /api/v1/addresses/default
 * @access  Private
 * @swagger
 * /api/v1/addresses/default:
 *   get:
 *     summary: دریافت آدرس پیش‌فرض کاربر
 *     tags: [Addresses]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: آدرس پیش‌فرض کاربر
 *       404:
 *         description: آدرس پیش‌فرضی پیدا نشد
 */
const getDefaultAddress = asyncHandler(async (req, res) => {
  const userId = req.user._id;
  
  const address = await addressService.getDefaultAddress(userId);
  
  if (!address) {
    return res.status(404).json({
      success: false,
      error: 'آدرس پیش‌فرضی پیدا نشد',
      data: null
    });
  }
  
  res.status(200).json({
    success: true,
    data: address
  });
});

/**
 * @desc    بررسی اعتبار آدرس برای سفارش
 * @route   POST /api/v1/addresses/:id/validate-for-order
 * @access  Private
 * @swagger
 * /api/v1/addresses/{id}/validate-for-order:
 *   post:
 *     summary: بررسی اعتبار آدرس برای سفارش
 *     tags: [Addresses]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: شناسه آدرس
 *     responses:
 *       200:
 *         description: آدرس معتبر است
 *       400:
 *         description: آدرس برای سفارش معتبر نیست
 */
const validateForOrder = asyncHandler(async (req, res) => {
  const addressId = req.params.id;
  const userId = req.user._id;
  
  const isValid = await addressService.validateAddressForOrder(addressId, userId);
  
  if (!isValid) {
    return res.status(400).json({
      success: false,
      error: 'آدرس برای سفارش معتبر نیست. لطفاً آدرس دیگری انتخاب کنید',
      data: { valid: false }
    });
  }
  
  res.status(200).json({
    success: true,
    message: 'آدرس برای سفارش معتبر است',
    data: { valid: true }
  });
});

module.exports = {
  getAddresses,
  getAddressById,
  createAddress,
  updateAddress,
  deleteAddress,
  setDefaultAddress,
  getDefaultAddress,
  validateForOrder
};