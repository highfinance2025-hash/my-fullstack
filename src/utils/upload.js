/**
 * @file ابزارهای آپلود فایل برای HTLand
 * @description پیکربندی multer برای آپلود تصاویر پروفایل
 * @since 1403/10/01
 */

const multer = require('multer');
const path = require('path');
const fs = require('fs');

// ایجاد پوشه uploads اگر وجود ندارد
const uploadDir = 'uploads/profile-images';
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// پیکربندی ذخیره‌سازی فایل
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    // نام فایل: userid-timestamp.extension
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, `user-${req.user._id}-${uniqueSuffix}${ext}`);
  }
});

// فیلتر فایل‌ها
const fileFilter = (req, file, cb) => {
  const allowedTypes = /jpeg|jpg|png|webp/;
  const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = allowedTypes.test(file.mimetype);
  
  if (mimetype && extname) {
    return cb(null, true);
  } else {
    cb(new Error('فقط تصاویر با فرمت‌های JPEG, JPG, PNG, WebP مجاز هستند'));
  }
};

// پیکربندی multer برای آپلود تصویر پروفایل
const uploadProfileImage = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024 // حداکثر 5MB
  },
  fileFilter: fileFilter
});

/**
 * حذف فایل از سیستم
 * @param {string} filePath - مسیر فایل
 */
const deleteFile = (filePath) => {
  if (fs.existsSync(filePath)) {
    fs.unlinkSync(filePath);
  }
};

/**
 * بررسی نوع فایل
 * @param {Object} file - فایل
 * @returns {boolean} آیا فایل تصویر است؟
 */
const isImageFile = (file) => {
  const imageTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp'];
  return imageTypes.includes(file.mimetype);
};

/**
 * بررسی حجم فایل
 * @param {Object} file - فایل
 * @param {number} maxSizeMB - حداکثر حجم به مگابایت
 * @returns {boolean} آیا حجم فایل قابل قبول است؟
 */
const isValidFileSize = (file, maxSizeMB = 5) => {
  const maxSizeBytes = maxSizeMB * 1024 * 1024;
  return file.size <= maxSizeBytes;
};

/**
 * دریافت اطلاعات فایل
 * @param {Object} file - فایل
 * @returns {Object} اطلاعات فایل
 */
const getFileInfo = (file) => {
  const ext = path.extname(file.originalname).toLowerCase();
  const name = path.basename(file.originalname, ext);
  
  return {
    originalName: file.originalname,
    fileName: file.filename,
    filePath: file.path,
    size: file.size,
    mimeType: file.mimetype,
    extension: ext.replace('.', ''),
    dimensions: null // بعداً با sharp می‌توان ابعاد را گرفت
  };
};

module.exports = {
  uploadProfileImage,
  deleteFile,
  isImageFile,
  isValidFileSize,
  getFileInfo
};
// upload.js - جایگزین با نسخه پیشرفته
const FileUpload = require('../utils/fileUpload'); // <-- فایل جدید

// ایجاد instance
const fileUpload = new FileUpload({
  uploadDir: process.env.UPLOAD_PATH || 'uploads',
  maxSize: parseInt(process.env.MAX_FILE_SIZE) || 5 * 1024 * 1024,
  allowedMimes: {
    'image/jpeg': 'jpg',
    'image/jpg': 'jpg',
    'image/png': 'png',
    'image/webp': 'webp',
    'image/gif': 'gif',
    'application/pdf': 'pdf'
  }
});

// Export متدهای موجود برای backward compatibility
module.exports = {
  uploadProfileImage: fileUpload.getProfileImageUpload(),
  deleteFile: fileUpload.deleteFile.bind(fileUpload),
  isImageFile: fileUpload.isImageFile.bind(fileUpload),
  isValidFileSize: fileUpload.isValidFileSize.bind(fileUpload),
  getFileInfo: fileUpload.getFileInfo.bind(fileUpload),
  
  // متدهای جدید
  fileUpload, // instance اصلی
  uploadProductImages: fileUpload.getProductImagesUpload(),
  uploadDocument: fileUpload.getDocumentUpload(),
  validateFile: fileUpload.validateFile.bind(fileUpload),
  processImage: fileUpload.processImage.bind(fileUpload),
  generateSafeFilename: fileUpload.generateSafeFilename.bind(fileUpload)
};
// utils/fileUpload.js - نسخه حرفه‌ای
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const sharp = require('sharp');
const { promisify } = require('util');
const unlinkAsync = promisify(fs.unlink);

class FileUpload {
  constructor(options = {}) {
    this.options = {
      uploadDir: 'uploads',
      maxSize: 5 * 1024 * 1024, // 5MB
      allowedMimes: {
        'image/jpeg': 'jpg',
        'image/jpg': 'jpg',
        'image/png': 'png',
        'image/webp': 'webp',
        'image/gif': 'gif',
        'application/pdf': 'pdf'
      },
      imageResize: {
        width: 1200,
        height: 1200,
        fit: 'inside'
      },
      ...options
    };

    this.ensureUploadDir();
  }

  ensureUploadDir() {
    const dirs = [
      this.options.uploadDir,
      path.join(this.options.uploadDir, 'images'),
      path.join(this.options.uploadDir, 'documents'),
      path.join(this.options.uploadDir, 'temp')
    ];

    dirs.forEach(dir => {
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
    });
  }

  generateSafeFilename(originalName, mimeType) {
    const ext = this.options.allowedMimes[mimeType] || path.extname(originalName).slice(1);
    const uniqueId = crypto.randomBytes(16).toString('hex');
    const timestamp = Date.now();
    
    // حذف کاراکترهای خطرناک
    const safeName = originalName.replace(/[^a-zA-Z0-9\u0600-\u06FF\s\._-]/g, '');
    const baseName = path.basename(safeName, path.extname(safeName));
    
    return `${baseName}-${timestamp}-${uniqueId}.${ext}`;
  }

  // اعتبارسنجی فایل
  validateFile(file) {
    const errors = [];

    // 1. بررسی نوع فایل
    if (!this.options.allowedMimes[file.mimetype]) {
      errors.push(`نوع فایل ${file.mimetype} مجاز نیست`);
    }

    // 2. بررسی حجم فایل
    if (file.size > this.options.maxSize) {
      errors.push(`حجم فایل باید کمتر از ${this.options.maxSize / 1024 / 1024}MB باشد`);
    }

    // 3. بررسی پسوند مخرب
    const maliciousExtensions = ['.php', '.exe', '.js', '.bat', '.sh', '.cmd'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (maliciousExtensions.includes(ext)) {
      errors.push('پسوند فایل غیرمجاز است');
    }

    // 4. بررسی نام فایل برای جلوگیری از Path Traversal
    if (file.originalname.includes('..') || file.originalname.includes('/')) {
      errors.push('نام فایل نامعتبر است');
    }

    return errors;
  }

  // پردازش تصویر
  async processImage(filePath, options = {}) {
    try {
      const processor = sharp(filePath);
      
      // Metadata تصویر
      const metadata = await processor.metadata();
      
      // Resize اگر نیاز باشد
      if (metadata.width > this.options.imageResize.width || 
          metadata.height > this.options.imageResize.height) {
        await processor
          .resize(this.options.imageResize.width, this.options.imageResize.height, {
            fit: this.options.imageResize.fit,
            withoutEnlargement: true
          })
          .toFile(filePath + '.resized');
        
        // جایگزینی فایل اصلی با نسخه resized
        await unlinkAsync(filePath);
        fs.renameSync(filePath + '.resized', filePath);
      }

      // Optimize image quality
      await sharp(filePath)
        .jpeg({ quality: 80, progressive: true })
        .png({ compressionLevel: 8, progressive: true })
        .webp({ quality: 80 })
        .toFile(filePath);

      return {
        success: true,
        metadata,
        processed: true
      };
    } catch (error) {
      throw new Error(`پردازش تصویر ناموفق: ${error.message}`);
    }
  }

  // تنظیمات multer
  getMulterConfig(folder = 'temp') {
    const storage = multer.diskStorage({
      destination: (req, file, cb) => {
        const uploadPath = path.join(this.options.uploadDir, folder);
        if (!fs.existsSync(uploadPath)) {
          fs.mkdirSync(uploadPath, { recursive: true });
        }
        cb(null, uploadPath);
      },
      filename: (req, file, cb) => {
        const safeName = this.generateSafeFilename(file.originalname, file.mimetype);
        cb(null, safeName);
      }
    });

    const fileFilter = (req, file, cb) => {
      const errors = this.validateFile(file);
      
      if (errors.length > 0) {
        return cb(new Error(errors.join(', ')));
      }
      
      cb(null, true);
    };

    return multer({
      storage,
      limits: {
        fileSize: this.options.maxSize,
        files: 5 // حداکثر تعداد فایل‌ها
      },
      fileFilter
    });
  }

  // آپلودرهای آماده
  get profileImageUpload() {
    return this.getMulterConfig('images').single('avatar');
  }

  get productImagesUpload() {
    return this.getMulterConfig('images').array('images', 5);
  }

  get documentUpload() {
    return this.getMulterConfig('documents').single('document');
  }

  // حذف فایل امن
  async deleteFile(filePath) {
    try {
      if (fs.existsSync(filePath)) {
        await unlinkAsync(filePath);
        return true;
      }
      return false;
    } catch (error) {
      throw new Error(`حذف فایل ناموفق: ${error.message}`);
    }
  }

  // بررسی فایل خطرناک
  isFileSafe(filePath) {
    try {
      // خواندن اولیه فایل برای بررسی هدرهای خطرناک
      const buffer = fs.readFileSync(filePath, { length: 100 });
      const header = buffer.toString('hex', 0, 4);
      
      // لیست هدرهای خطرناک
      const dangerousHeaders = [
        '4d5a', // EXE
        '235c21', // PHP
        '3c3f706870', // <?php
        '2f2a', // /*
        '3c21', // <!
        '3c73', // <s
        '3c68', // <h
        '3c62', // <b
      ];
      
      return !dangerousHeaders.some(h => header.startsWith(h));
    } catch (error) {
      return false;
    }
  }
}

module.exports = FileUpload;