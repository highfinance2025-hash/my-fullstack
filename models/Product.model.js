// models/Product.model.js

const mongoose = require('mongoose');
const mongoosePaginate = require('mongoose-paginate-v2');

/**
 * اسکیما و مدل محصول برای فروشگاه HTLand
 * محصولات ارگانیک شمال ایران: برنج، خاویار، ماهی، عسل، مرغ، سوغات
 */
const productSchema = new mongoose.Schema(
  {
    // نام محصول
    name: {
      type: String,
      required: [true, 'نام محصول الزامی است'],
      trim: true,
      maxlength: [200, 'نام محصول نمی‌تواند بیشتر از 200 کاراکتر باشد'],
      index: 'text',
    },
    // slug برای URL
    slug: {
      type: String,
      required: [true, 'Slug الزامی است'],
      unique: true,
      lowercase: true,
      index: true,
    },
    // توضیحات محصول
    description: {
      type: String,
      required: [true, 'توضیحات محصول الزامی است'],
      maxlength: [2000, 'توضیحات محصول نمی‌تواند بیشتر از 2000 کاراکتر باشد'],
    },
    // قیمت اصلی (به تومان)
    price: {
      type: Number,
      required: [true, 'قیمت اصلی محصول الزامی است'],
      min: [0, 'قیمت نمی‌تواند منفی باشد'],
    },
    // قیمت پس از تخفیف (به تومان)
    discountPrice: {
      type: Number,
      min: [0, 'قیمت تخفیف نمی‌تواند منفی باشد'],
      validate: {
        validator: function (value) {
          return value <= this.price;
        },
        message: 'قیمت تخفیف نمی‌تواند بیشتر از قیمت اصلی باشد',
      },
    },
    // دسته‌بندی محصول
    category: {
      type: String,
      required: [true, 'دسته‌بندی محصول الزامی است'],
      enum: {
        values: ['rice', 'caviar', 'fish', 'honey', 'chicken', 'souvenir'],
        message: 'دسته‌بندی معتبر نیست',
      },
      index: true,
    },
    // نام دسته‌بندی فارسی (برای نمایش)
    categoryFa: {
      type: String,
      required: [true, 'نام دسته‌بندی فارسی الزامی است'],
      enum: {
        values: ['برنج شمال', 'خاویار ایرانی', 'ماهی تازه', 'عسل طبیعی', 'مرغ محلی', 'سوغات شمال'],
        message: 'نام دسته‌بندی فارسی معتبر نیست',
      },
    },
    // آدرس تصویر اصلی محصول (ذخیره شده در CDN)
    image: {
      type: String,
      required: [true, 'تصویر محصول الزامی است'],
      validate: {
        validator: function (value) {
          return /^(https?|ftp):\/\/[^\s/$.?#].[^\s]*$/.test(value);
        },
        message: 'آدرس تصویر معتبر نیست',
      },
    },
    // گالری تصاویر (آرایه‌ای از آدرس‌ها)
    gallery: [
      {
        type: String,
        validate: {
          validator: function (value) {
            return /^(https?|ftp):\/\/[^\s/$.?#].[^\s]*$/.test(value);
          },
          message: 'آدرس تصویر معتبر نیست',
        },
      },
    ],
    // موجودی کالا
    stock: {
      type: Number,
      required: [true, 'موجودی محصول الزامی است'],
      min: [0, 'موجودی نمی‌تواند منفی باشد'],
      default: 0,
    },
    // وضعیت موجود بودن (محاسبه شده از stock)
    inStock: {
      type: Boolean,
      default: true,
      index: true,
    },
    // آیا محصول ویژه است (برای نمایش در بخش ویژه‌ها)
    featured: {
      type: Boolean,
      default: false,
      index: true,
    },
    // وضعیت فعال/غیرفعال
    active: {
      type: Boolean,
      default: true,
      index: true,
    },
    // تگ‌ها برای جستجو و فیلتر بهتر
    tags: [
      {
        type: String,
        trim: true,
        lowercase: true,
      },
    ],
    // اطلاعات اضافی (وزن، ابعاد، تاریخ تولید، ...)
    metadata: {
      weight: {
        type: Number,
        min: 0,
      },
      unit: {
        type: String,
        enum: ['گرم', 'کیلوگرم', 'عدد', 'بسته'],
        default: 'کیلوگرم',
      },
      origin: {
        type: String,
        default: 'شمال ایران',
      },
      productionDate: Date,
      expiryDate: Date,
      // هر فیلد سفارشی دیگر
    },
    // امتیاز محصول (میانگین نظرات)
    rating: {
      type: Number,
      min: 0,
      max: 5,
      default: 0,
    },
    // تعداد نظرات
    reviewsCount: {
      type: Number,
      default: 0,
    },
    // ایجاد شده توسط
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },
    // به‌روزرسانی شده توسط
    updatedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
    },
  },
  {
    timestamps: true, // ایجاد فیلدهای createdAt و updatedAt
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// ایندکس برای جستجوی متنی و فیلترهای پرکاربرد
productSchema.index({ name: 'text', description: 'text', tags: 'text' });
productSchema.index({ category: 1, active: 1, inStock: 1 });
productSchema.index({ price: 1 });
productSchema.index({ discountPrice: 1 });
productSchema.index({ createdAt: -1 });

// متد instance برای بررسی موجودی
productSchema.methods.checkStock = function (quantity) {
  return this.stock >= quantity;
};

// متد instance برای کاهش موجودی
productSchema.methods.decreaseStock = async function (quantity) {
  if (this.stock < quantity) {
    throw new Error('موجودی کافی نیست');
  }
  this.stock -= quantity;
  this.inStock = this.stock > 0;
  await this.save();
};

// متد instance برای افزایش موجودی
productSchema.methods.increaseStock = async function (quantity) {
  this.stock += quantity;
  this.inStock = true;
  await this.save();
};

// middleware برای محاسبه خودکار inStock قبل از ذخیره
productSchema.pre('save', function (next) {
  this.inStock = this.stock > 0;
  next();
});

// plugin برای صفحه‌بندی
productSchema.plugin(mongoosePaginate);

// متد استاتیک برای جستجوی پیشرفته
productSchema.statics.search = async function (text, options = {}) {
  const query = this.find(
    {
      $text: { $search: text },
      active: true,
      inStock: true,
    },
    { score: { $meta: 'textScore' } }
  )
    .sort({ score: { $meta: 'textScore' } })
    .select('-__v');

  // اعمال فیلترهای اضافی اگر وجود داشته باشند
  if (options.category) {
    query.where('category').equals(options.category);
  }
  if (options.minPrice) {
    query.where('price').gte(options.minPrice);
  }
  if (options.maxPrice) {
    query.where('price').lte(options.maxPrice);
  }

  return query;
};

const Product = mongoose.model('Product', productSchema);

module.exports = Product;