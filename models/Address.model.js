/**
 * @file مدل آدرس‌های کاربران HTLand
 * @description مدیریت آدرس‌های کاربر برای تحویل محصولات ارگانیک شمال
 * @since 1403/10/01
 */

const mongoose = require('mongoose');
const validator = require('validator');

const addressSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'آدرس باید متعلق به یک کاربر باشد'],
    index: true
  },
  
  fullName: {
    type: String,
    required: [true, 'نام کامل گیرنده الزامی است'],
    trim: true,
    minlength: [3, 'نام کامل باید حداقل ۳ کاراکتر باشد'],
    maxlength: [100, 'نام کامل نباید بیش از ۱۰۰ کاراکتر باشد'],
    validate: {
      validator: function(v) {
        return /^[\u0600-\u06FF\s]+$/.test(v); // فقط حروف فارسی و فاصله
      },
      message: 'نام کامل باید فارسی باشد'
    }
  },
  
  phone: {
    type: String,
    required: [true, 'شماره تلفن الزامی است'],
    validate: {
      validator: function(v) {
        return /^09[0-9]{9}$/.test(v);
      },
      message: 'شماره تلفن معتبر نیست (فرمت: 09123456789)'
    }
  },
  
  province: {
    type: String,
    required: [true, 'استان الزامی است'],
    enum: [
      'مازندران', 'گیلان', 'گلستان', 'آذربایجان شرقی', 'آذربایجان غربی',
      'تهران', 'البرز', 'قم', 'مرکزی', 'همدان', 'زنجان', 'اردبیل',
      'قزوین', 'کردستان', 'کرمانشاه', 'لرستان', 'ایلام', 'خوزستان',
      'فارس', 'بوشهر', 'هرمزگان', 'کرمان', 'سیستان و بلوچستان',
      'خراسان رضوی', 'خراسان شمالی', 'خراسان جنوبی', 'یزد', 'اصفهان',
      'سمنان', 'چهارمحال و بختیاری', 'کهگیلویه و بویراحمد'
    ]
  },
  
  city: {
    type: String,
    required: [true, 'شهر الزامی است'],
    trim: true,
    minlength: [2, 'نام شهر باید حداقل ۲ کاراکتر باشد'],
    maxlength: [50, 'نام شهر نباید بیش از ۵۰ کاراکتر باشد']
  },
  
  address: {
    type: String,
    required: [true, 'آدرس کامل الزامی است'],
    trim: true,
    minlength: [10, 'آدرس باید حداقل ۱۰ کاراکتر باشد'],
    maxlength: [500, 'آدرس نباید بیش از ۵۰۰ کاراکتر باشد']
  },
  
  postalCode: {
    type: String,
    required: [true, 'کد پستی الزامی است'],
    validate: {
      validator: function(v) {
        return /^\d{10}$/.test(v);
      },
      message: 'کد پستی باید ۱۰ رقم باشد'
    }
  },
  
  isDefault: {
    type: Boolean,
    default: false
  },
  
  label: {
    type: String,
    enum: ['خانه', 'کار', 'فامیل', 'دیگر'],
    default: 'خانه'
  },
  
  location: {
    type: {
      type: String,
      enum: ['Point'],
      default: 'Point'
    },
    coordinates: {
      type: [Number], // [longitude, latitude]
      default: [0, 0]
    }
  },
  
  buildingNumber: {
    type: String,
    maxlength: [20, 'شماره پلاک نباید بیش از ۲۰ کاراکتر باشد']
  },
  
  unit: {
    type: String,
    maxlength: [10, 'واحد نباید بیش از ۱۰ کاراکتر باشد']
  },
  
  floor: {
    type: String,
    maxlength: [10, 'طبقه نباید بیش از ۱۰ کاراکتر باشد']
  },
  
  description: {
    type: String,
    maxlength: [200, 'توضیحات نباید بیش از ۲۰۰ کاراکتر باشد']
  },
  
  isActive: {
    type: Boolean,
    default: true
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// ایندکس برای جستجوی بهتر
addressSchema.index({ user: 1, isDefault: 1 });
addressSchema.index({ location: '2dsphere' });

// متد ایستا: بررسی تعداد آدرس‌های کاربر
addressSchema.statics.getUserAddressCount = async function(userId) {
  return await this.countDocuments({ user: userId, isActive: true });
};

// متد ایستا: پیدا کردن آدرس پیش‌فرض کاربر
addressSchema.statics.findDefaultAddress = async function(userId) {
  return await this.findOne({ user: userId, isDefault: true, isActive: true });
};

// متد نمونه: فرمت آدرس برای نمایش
addressSchema.methods.formatAddress = function() {
  return `${this.address}، ${this.city}، ${this.province}، کدپستی: ${this.postalCode}`;
};

// متد نمونه: فرمت مختصر آدرس
addressSchema.methods.getShortAddress = function() {
  return `${this.city}، ${this.address.substring(0, 50)}...`;
};

// میدلور: قبل از ذخیره، اعتبارسنجی اضافی
addressSchema.pre('save', async function(next) {
  // اگر این آدرس پیش‌فرض است، بقیه آدرس‌های کاربر را غیرپیش‌فرض کن
  if (this.isDefault && this.isModified('isDefault')) {
    try {
      await this.constructor.updateMany(
        { user: this.user, _id: { $ne: this._id } },
        { $set: { isDefault: false } }
      );
    } catch (error) {
      return next(error);
    }
  }
  
  // محدودیت تعداد آدرس‌ها (حداکثر ۳ آدرس فعال)
  if (this.isNew && !this.isModified('isActive')) {
    const addressCount = await this.constructor.getUserAddressCount(this.user);
    if (addressCount >= 3) {
      return next(new Error('هر کاربر می‌تواند حداکثر ۳ آدرس فعال داشته باشد'));
    }
  }
  
  next();
});

// میدلور: قبل از حذف، بررسی آدرس پیش‌فرض
addressSchema.pre('remove', async function(next) {
  if (this.isDefault) {
    return next(new Error('نمی‌توان آدرس پیش‌فرض را حذف کرد. ابتدا آدرس دیگری را پیش‌فرض کنید'));
  }
  next();
});

const Address = mongoose.model('Address', addressSchema);

module.exports = Address;