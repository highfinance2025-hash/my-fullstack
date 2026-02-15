/**
 * @file سرویس مدیریت آدرس‌های کاربران HTLand
 * @description منطق کسب‌وکار و عملیات‌های مربوط به آدرس‌ها
 * @since 1403/10/01
 */

const Address = require('../models/Address.model');
const User = require('../models/User.model');
const logger = require('../utils/logger');

/**
 * دریافت لیست آدرس‌های کاربر
 * @param {string} userId - شناسه کاربر
 * @returns {Promise<Array>} لیست آدرس‌های کاربر
 */
const getUserAddresses = async (userId) => {
  try {
    const addresses = await Address.find({ user: userId, isActive: true })
      .sort({ isDefault: -1, createdAt: -1 })
      .lean();
    
    // افزودن فرمت نمایشی به هر آدرس
    return addresses.map(address => ({
      ...address,
      formattedAddress: formatAddressForDisplay(address)
    }));
  } catch (error) {
    logger.error(`خطا در دریافت آدرس‌های کاربر ${userId}:`, error);
    throw new Error('خطا در دریافت آدرس‌ها');
  }
};

/**
 * دریافت یک آدرس خاص
 * @param {string} addressId - شناسه آدرس
 * @param {string} userId - شناسه کاربر
 * @returns {Promise<Object>} اطلاعات آدرس
 */
const getAddressById = async (addressId, userId) => {
  try {
    const address = await Address.findOne({
      _id: addressId,
      user: userId,
      isActive: true
    }).lean();
    
    if (!address) return null;
    
    return {
      ...address,
      formattedAddress: formatAddressForDisplay(address)
    };
  } catch (error) {
    logger.error(`خطا در دریافت آدرس ${addressId}:`, error);
    throw new Error('خطا در دریافت آدرس');
  }
};

/**
 * ایجاد آدرس جدید
 * @param {string} userId - شناسه کاربر
 * @param {Object} addressData - اطلاعات آدرس جدید
 * @returns {Promise<Object>} آدرس ایجاد شده
 */
const createAddress = async (userId, addressData) => {
  try {
    // اعتبارسنجی داده‌های ورودی
    validateAddressData(addressData);
    
    // بررسی تکراری نبودن آدرس
    const isDuplicate = await checkDuplicateAddress(userId, addressData);
    if (isDuplicate) {
      throw new Error('این آدرس قبلاً ثبت شده است');
    }
    
    // اگر اولین آدرس کاربر است، آن را پیش‌فرض کن
    const addressCount = await Address.countDocuments({ user: userId, isActive: true });
    if (addressCount === 0) {
      addressData.isDefault = true;
    }
    
    // ایجاد آدرس جدید
    const address = new Address({
      user: userId,
      ...addressData
    });
    
    await address.save();
    
    // آپدیت لیست آدرس‌های کاربر در مدل User
    await User.findByIdAndUpdate(userId, {
      $push: { addresses: address._id }
    });
    
    logger.info(`آدرس جدید برای کاربر ${userId} ایجاد شد: ${address._id}`);
    
    return {
      ...address.toObject(),
      formattedAddress: formatAddressForDisplay(address)
    };
  } catch (error) {
    logger.error(`خطا در ایجاد آدرس برای کاربر ${userId}:`, error);
    throw error;
  }
};

/**
 * ویرایش آدرس موجود
 * @param {string} addressId - شناسه آدرس
 * @param {string} userId - شناسه کاربر
 * @param {Object} updateData - اطلاعات جدید آدرس
 * @returns {Promise<Object>} آدرس ویرایش شده
 */
const updateAddress = async (addressId, userId, updateData) => {
  try {
    // اعتبارسنجی داده‌های ورودی
    if (Object.keys(updateData).length > 0) {
      validateAddressData(updateData);
    }
    
    // یافتن آدرس و بررسی مالکیت
    const address = await Address.findOne({
      _id: addressId,
      user: userId,
      isActive: true
    });
    
    if (!address) {
      return null;
    }
    
    // بررسی تکراری نبودن آدرس (به جز خود آدرس فعلی)
    if (Object.keys(updateData).some(key => 
      ['province', 'city', 'address', 'postalCode'].includes(key)
    )) {
      const duplicateCheckData = {
        province: updateData.province || address.province,
        city: updateData.city || address.city,
        address: updateData.address || address.address,
        postalCode: updateData.postalCode || address.postalCode
      };
      
      const isDuplicate = await checkDuplicateAddress(
        userId, 
        duplicateCheckData, 
        addressId
      );
      
      if (isDuplicate) {
        throw new Error('این آدرس قبلاً ثبت شده است');
      }
    }
    
    // اعمال تغییرات
    Object.keys(updateData).forEach(key => {
      if (updateData[key] !== undefined) {
        address[key] = updateData[key];
      }
    });
    
    await address.save();
    
    logger.info(`آدرس ${addressId} برای کاربر ${userId} ویرایش شد`);
    
    return {
      ...address.toObject(),
      formattedAddress: formatAddressForDisplay(address)
    };
  } catch (error) {
    logger.error(`خطا در ویرایش آدرس ${addressId}:`, error);
    throw error;
  }
};

/**
 * حذف آدرس
 * @param {string} addressId - شناسه آدرس
 * @param {string} userId - شناسه کاربر
 * @returns {Promise<boolean>} موفقیت عملیات
 */
const deleteAddress = async (addressId, userId) => {
  const session = await Address.startSession();
  session.startTransaction();
  
  try {
    // یافتن آدرس و بررسی مالکیت
    const address = await Address.findOne({
      _id: addressId,
      user: userId,
      isActive: true
    }).session(session);
    
    if (!address) {
      await session.abortTransaction();
      session.endSession();
      return false;
    }
    
    // بررسی آدرس پیش‌فرض
    if (address.isDefault) {
      throw new Error('نمی‌توان آدرس پیش‌فرض را حذف کرد');
    }
    
    // غیرفعال کردن آدرس (Soft Delete)
    address.isActive = false;
    await address.save({ session });
    
    // حذف آدرس از لیست آدرس‌های کاربر
    await User.findByIdAndUpdate(
      userId,
      { $pull: { addresses: addressId } },
      { session }
    );
    
    await session.commitTransaction();
    session.endSession();
    
    logger.info(`آدرس ${addressId} برای کاربر ${userId} حذف شد`);
    
    return true;
  } catch (error) {
    await session.abortTransaction();
    session.endSession();
    
    logger.error(`خطا در حذف آدرس ${addressId}:`, error);
    throw error;
  }
};

/**
 * تنظیم آدرس به عنوان پیش‌فرض
 * @param {string} addressId - شناسه آدرس
 * @param {string} userId - شناسه کاربر
 * @returns {Promise<Object>} آدرس پیش‌فرض شده
 */
const setDefaultAddress = async (addressId, userId) => {
  const session = await Address.startSession();
  session.startTransaction();
  
  try {
    // یافتن آدرس و بررسی مالکیت
    const address = await Address.findOne({
      _id: addressId,
      user: userId,
      isActive: true
    }).session(session);
    
    if (!address) {
      await session.abortTransaction();
      session.endSession();
      return null;
    }
    
    // اگر قبلاً پیش‌فرض است، تغییر نده
    if (address.isDefault) {
      await session.abortTransaction();
      session.endSession();
      return address;
    }
    
    // غیرپیش‌فرض کردن بقیه آدرس‌های کاربر
    await Address.updateMany(
      { user: userId, _id: { $ne: addressId }, isActive: true },
      { $set: { isDefault: false } },
      { session }
    );
    
    // پیش‌فرض کردن آدرس انتخاب شده
    address.isDefault = true;
    await address.save({ session });
    
    await session.commitTransaction();
    session.endSession();
    
    logger.info(`آدرس ${addressId} برای کاربر ${userId} پیش‌فرض شد`);
    
    return {
      ...address.toObject(),
      formattedAddress: formatAddressForDisplay(address)
    };
  } catch (error) {
    await session.abortTransaction();
    session.endSession();
    
    logger.error(`خطا در پیش‌فرض کردن آدرس ${addressId}:`, error);
    throw error;
  }
};

/**
 * دریافت آدرس پیش‌فرض کاربر
 * @param {string} userId - شناسه کاربر
 * @returns {Promise<Object>} آدرس پیش‌فرض
 */
const getDefaultAddress = async (userId) => {
  try {
    const address = await Address.findOne({
      user: userId,
      isDefault: true,
      isActive: true
    }).lean();
    
    if (!address) {
      // اگر آدرس پیش‌فرضی نداشت، اولین آدرس فعال را برگردان
      const firstAddress = await Address.findOne({
        user: userId,
        isActive: true
      }).sort({ createdAt: 1 }).lean();
      
      if (!firstAddress) return null;
      
      // این آدرس را پیش‌فرض کن
      await setDefaultAddress(firstAddress._id, userId);
      
      return {
        ...firstAddress,
        formattedAddress: formatAddressForDisplay(firstAddress)
      };
    }
    
    return {
      ...address,
      formattedAddress: formatAddressForDisplay(address)
    };
  } catch (error) {
    logger.error(`خطا در دریافت آدرس پیش‌فرض کاربر ${userId}:`, error);
    throw new Error('خطا در دریافت آدرس پیش‌فرض');
  }
};

/**
 * بررسی اعتبار آدرس برای سفارش
 * @param {string} addressId - شناسه آدرس
 * @param {string} userId - شناسه کاربر
 * @returns {Promise<boolean>} معتبر بودن آدرس
 */
const validateAddressForOrder = async (addressId, userId) => {
  try {
    const address = await Address.findOne({
      _id: addressId,
      user: userId,
      isActive: true
    });
    
    if (!address) return false;
    
    // بررسی کامل بودن اطلاعات آدرس
    const requiredFields = ['fullName', 'phone', 'province', 'city', 'address', 'postalCode'];
    const isValid = requiredFields.every(field => 
      address[field] && address[field].toString().trim().length > 0
    );
    
    // بررسی استان‌های قابل ارسال (شمال ایران اولویت دارد)
    const northernProvinces = ['مازندران', 'گیلان', 'گلستان', 'تهران', 'البرز'];
    const hasFastShipping = northernProvinces.includes(address.province);
    
    return {
      valid: isValid,
      hasFastShipping,
      estimatedDelivery: hasFastShipping ? '۱-۲ روز کاری' : '۳-۵ روز کاری'
    };
  } catch (error) {
    logger.error(`خطا در بررسی اعتبار آدرس ${addressId}:`, error);
    return false;
  }
};

/**
 * دریافت تعداد آدرس‌های کاربر
 * @param {string} userId - شناسه کاربر
 * @returns {Promise<number>} تعداد آدرس‌ها
 */
const getUserAddressCount = async (userId) => {
  try {
    return await Address.countDocuments({ user: userId, isActive: true });
  } catch (error) {
    logger.error(`خطا در شمارش آدرس‌های کاربر ${userId}:`, error);
    throw new Error('خطا در شمارش آدرس‌ها');
  }
};

/**
 * بررسی تکراری نبودن آدرس
 * @param {string} userId - شناسه کاربر
 * @param {Object} addressData - اطلاعات آدرس
 * @param {string} excludeId - شناسه آدرسی که از بررسی مستثنی است
 * @returns {Promise<boolean>} تکراری بودن
 */
const checkDuplicateAddress = async (userId, addressData, excludeId = null) => {
  try {
    const query = {
      user: userId,
      province: addressData.province,
      city: addressData.city,
      address: addressData.address,
      postalCode: addressData.postalCode,
      isActive: true
    };
    
    if (excludeId) {
      query._id = { $ne: excludeId };
    }
    
    const existingAddress = await Address.findOne(query);
    return !!existingAddress;
  } catch (error) {
    logger.error('خطا در بررسی تکراری بودن آدرس:', error);
    throw error;
  }
};

/**
 * اعتبارسنجی داده‌های آدرس
 * @param {Object} addressData - اطلاعات آدرس
 * @throws {Error} اگر داده‌ها معتبر نباشند
 */
const validateAddressData = (addressData) => {
  const errors = [];
  
  if (addressData.fullName && addressData.fullName.length < 3) {
    errors.push('نام کامل باید حداقل ۳ کاراکتر باشد');
  }
  
  if (addressData.phone && !/^09[0-9]{9}$/.test(addressData.phone)) {
    errors.push('شماره تلفن معتبر نیست');
  }
  
  if (addressData.postalCode && !/^\d{10}$/.test(addressData.postalCode)) {
    errors.push('کد پستی باید ۱۰ رقم باشد');
  }
  
  if (addressData.address && addressData.address.length < 10) {
    errors.push('آدرس باید حداقل ۱۰ کاراکتر باشد');
  }
  
  if (errors.length > 0) {
    throw new Error(errors.join(', '));
  }
};

/**
 * فرمت نمایش آدرس
 * @param {Object} address - اطلاعات آدرس
 * @returns {string} آدرس فرمت شده
 */
const formatAddressForDisplay = (address) => {
  const parts = [];
  
  if (address.buildingNumber) parts.push(`پلاک ${address.buildingNumber}`);
  if (address.unit) parts.push(`واحد ${address.unit}`);
  if (address.floor) parts.push(`طبقه ${address.floor}`);
  
  let formatted = address.address;
  if (parts.length > 0) {
    formatted += `، ${parts.join('، ')}`;
  }
  
  formatted += `، ${address.city}، ${address.province}`;
  formatted += `، کد پستی: ${address.postalCode}`;
  
  if (address.description) {
    formatted += ` (${address.description})`;
  }
  
  return formatted;
};

/**
 * جستجوی آدرس بر اساس موقعیت جغرافیایی
 * @param {string} userId - شناسه کاربر
 * @param {Object} coordinates - مختصات جغرافیایی [longitude, latitude]
 * @param {number} radius - شعاع جستجو به کیلومتر
 * @returns {Promise<Array>} آدرس‌های نزدیک
 */
const findAddressesByLocation = async (userId, coordinates, radius = 10) => {
  try {
    const addresses = await Address.find({
      user: userId,
      isActive: true,
      location: {
        $near: {
          $geometry: {
            type: 'Point',
            coordinates: coordinates
          },
          $maxDistance: radius * 1000 // تبدیل به متر
        }
      }
    }).lean();
    
    return addresses.map(address => ({
      ...address,
      formattedAddress: formatAddressForDisplay(address),
      distance: calculateDistance(
        coordinates,
        address.location.coordinates
      )
    }));
  } catch (error) {
    logger.error(`خطا در جستجوی آدرس بر اساس موقعیت:`, error);
    throw new Error('خطا در جستجوی آدرس');
  }
};

/**
 * محاسبه فاصله بین دو نقطه جغرافیایی
 * @param {Array} coords1 - مختصات نقطه اول [lon, lat]
 * @param {Array} coords2 - مختصات نقطه دوم [lon, lat]
 * @returns {number} فاصله به کیلومتر
 */
const calculateDistance = (coords1, coords2) => {
  const [lon1, lat1] = coords1;
  const [lon2, lat2] = coords2;
  
  const R = 6371; // شعاع زمین به کیلومتر
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a = 
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * 
    Math.sin(dLon / 2) * Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
};

const toRad = (value) => value * Math.PI / 180;

module.exports = {
  getUserAddresses,
  getAddressById,
  createAddress,
  updateAddress,
  deleteAddress,
  setDefaultAddress,
  getDefaultAddress,
  validateAddressForOrder,
  getUserAddressCount,
  checkDuplicateAddress,
  validateAddressData,
  formatAddressForDisplay,
  findAddressesByLocation,
  calculateDistance
};