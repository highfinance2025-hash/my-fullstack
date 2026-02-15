/**
 * @file پیکربندی Cloudinary برای HTLand
 * @description اتصال به سرویس Cloudinary برای آپلود و مدیریت تصاویر
 * @since 1403/10/01
 */

const cloudinary = require('cloudinary').v2;
require('dotenv').config();

// پیکربندی Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME || 'htland',
  api_key: process.env.CLOUDINARY_API_KEY || 'your-api-key',
  api_secret: process.env.CLOUDINARY_API_SECRET || 'your-api-secret',
  secure: true
});

/**
 * آپلود تصویر به Cloudinary
 * @param {string} filePath - مسیر فایل در سرور
 * @param {Object} options - تنظیمات آپلود
 * @returns {Promise<Object>} نتیجه آپلود
 */
const uploadToCloudinary = async (filePath, options = {}) => {
  try {
    const uploadOptions = {
      folder: 'htland/profile-images',
      use_filename: true,
      unique_filename: true,
      overwrite: false,
      transformation: [
        { width: 500, height: 500, crop: 'fill', gravity: 'face' },
        { quality: 'auto:good' }
      ],
      ...options
    };
    
    const result = await cloudinary.uploader.upload(filePath, uploadOptions);
    
    return {
      success: true,
      url: result.secure_url,
      publicId: result.public_id,
      format: result.format,
      width: result.width,
      height: result.height,
      bytes: result.bytes
    };
  } catch (error) {
    console.error('خطا در آپلود به Cloudinary:', error);
    throw new Error('خطا در آپلود تصویر');
  }
};

/**
 * حذف تصویر از Cloudinary
 * @param {string} publicId - شناسه عمومی تصویر
 * @returns {Promise<Object>} نتیجه حذف
 */
const deleteFromCloudinary = async (publicId) => {
  try {
    const result = await cloudinary.uploader.destroy(publicId);
    
    return {
      success: result.result === 'ok',
      result: result.result
    };
  } catch (error) {
    console.error('خطا در حذف از Cloudinary:', error);
    throw new Error('خطا در حذف تصویر');
  }
};

/**
 * تولید URL تصویر با تبدیل‌های مختلف
 * @param {string} publicId - شناسه عمومی تصویر
 * @param {Object} transformations - تبدیل‌های مورد نیاز
 * @returns {string} URL تصویر
 */
const generateImageUrl = (publicId, transformations = {}) => {
  const defaultTransformations = {
    width: 200,
    height: 200,
    crop: 'fill',
    gravity: 'face',
    quality: 'auto:good',
    format: 'webp'
  };
  
  const finalTransformations = { ...defaultTransformations, ...transformations };
  
  return cloudinary.url(publicId, finalTransformations);
};

/**
 * بررسی وجود تصویر در Cloudinary
 * @param {string} publicId - شناسه عمومی تصویر
 * @returns {Promise<boolean>} وجود داشتن تصویر
 */
const checkImageExists = async (publicId) => {
  try {
    const result = await cloudinary.api.resource(publicId);
    return !!result;
  } catch (error) {
    if (error.http_code === 404) {
      return false;
    }
    throw error;
  }
};

/**
 * دریافت اطلاعات تصویر
 * @param {string} publicId - شناسه عمومی تصویر
 * @returns {Promise<Object>} اطلاعات تصویر
 */
const getImageInfo = async (publicId) => {
  try {
    const result = await cloudinary.api.resource(publicId, {
      image_metadata: true,
      colors: true,
      faces: true
    });
    
    return {
      exists: true,
      url: result.secure_url,
      format: result.format,
      width: result.width,
      height: result.height,
      bytes: result.bytes,
      createdAt: result.created_at,
      metadata: result.image_metadata || {}
    };
  } catch (error) {
    if (error.http_code === 404) {
      return { exists: false };
    }
    throw error;
  }
};

module.exports = {
  cloudinary,
  uploadToCloudinary,
  deleteFromCloudinary,
  generateImageUrl,
  checkImageExists,
  getImageInfo
};