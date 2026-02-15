/**
 * اعتبارسنجی پیشرفته محصولات
 */
const Joi = require('joi');

const productSchema = Joi.object({
  name: Joi.string().min(3).max(200).required().messages({
    'string.empty': 'نام محصول الزامی است',
    'string.min': 'نام محصول باید حداقل ۳ کاراکتر باشد',
    'string.max': 'نام محصول نمی‌تواند بیشتر از ۲۰۰ کاراکتر باشد'
  }),
  
  description: Joi.string().min(10).max(2000).required().messages({
    'string.empty': 'توضیحات محصول الزامی است',
    'string.min': 'توضیحات باید حداقل ۱۰ کاراکتر باشد',
    'string.max': 'توضیحات نمی‌تواند بیشتر از ۲۰۰۰ کاراکتر باشد'
  }),
  
  price: Joi.number().min(1000).required().messages({
    'number.base': 'قیمت باید عدد باشد',
    'number.min': 'قیمت نمی‌تواند کمتر از ۱۰۰۰ تومان باشد',
    'any.required': 'قیمت الزامی است'
  }),
  
  discountPrice: Joi.number().min(0).less(Joi.ref('price')).messages({
    'number.less': 'قیمت تخفیف باید کمتر از قیمت اصلی باشد',
    'number.min': 'قیمت تخفیف نمی‌تواند منفی باشد'
  }),
  
  category: Joi.string().valid(
    'rice', 'caviar', 'fish', 'honey', 'chicken', 'souvenir'
  ).required(),
  
  categoryFa: Joi.string().valid(
    'برنج شمال', 'خاویار ایرانی', 'ماهی تازه', 'عسل طبیعی', 'مرغ محلی', 'سوغات شمال'
  ).required(),
  
  stock: Joi.number().integer().min(0).default(0),
  
  featured: Joi.boolean().default(false),
  
  tags: Joi.array().items(Joi.string()).default([]),
  
  specifications: Joi.object({
    weight: Joi.object({
      value: Joi.number().min(0),
      unit: Joi.string().valid('گرم', 'کیلوگرم', 'لیتر', 'عدد', 'بسته')
    }),
    origin: Joi.string().default('شمال ایران'),
    shelfLife: Joi.string(),
    storageCondition: Joi.string(),
    certifications: Joi.array().items(Joi.string())
  }).default({})
});

module.exports = {
  validateProduct: (data) => productSchema.validate(data, { abortEarly: false })
};
// src/validators/product.validator.js - Production Grade
const Joi = require('joi');
const { ErrorBuilder } = require('../utils/error-builder');

class ProductValidator {
  static schemas = {
    create: Joi.object({
      name: Joi.string()
        .min(3).max(200)
        .required()
        .messages({
          'string.empty': 'نام محصول الزامی است',
          'string.min': 'نام محصول باید حداقل ۳ کاراکتر باشد',
          'string.max': 'نام محصول نمی‌تواند بیشتر از ۲۰۰ کاراکتر باشد',
          'any.required': 'نام محصول الزامی است'
        }),
      
      description: Joi.string()
        .min(10).max(5000)
        .required()
        .messages({
          'string.empty': 'توضیحات محصول الزامی است',
          'string.min': 'توضیحات باید حداقل ۱۰ کاراکتر باشد',
          'string.max': 'توضیحات نمی‌تواند بیشتر از ۵۰۰۰ کاراکتر باشد',
          'any.required': 'توضیحات محصول الزامی است'
        }),
      
      price: Joi.number()
        .min(1000).max(1000000000)
        .required()
        .messages({
          'number.base': 'قیمت باید عدد باشد',
          'number.min': 'قیمت نمی‌تواند کمتر از ۱۰۰۰ تومان باشد',
          'number.max': 'قیمت نمی‌تواند بیشتر از ۱,۰۰۰,۰۰۰,۰۰۰ تومان باشد',
          'any.required': 'قیمت الزامی است'
        }),
      
      discountPrice: Joi.number()
        .min(0)
        .less(Joi.ref('price'))
        .default(0)
        .messages({
          'number.less': 'قیمت تخفیف باید کمتر از قیمت اصلی باشد',
          'number.min': 'قیمت تخفیف نمی‌تواند منفی باشد'
        }),
      
      category: Joi.string()
        .valid('rice', 'caviar', 'fish', 'honey', 'chicken', 'souvenir', 'other')
        .required()
        .messages({
          'any.only': 'دسته‌بندی نامعتبر است',
          'any.required': 'دسته‌بندی الزامی است'
        }),
      
      stock: Joi.number()
        .integer()
        .min(0)
        .default(0)
        .messages({
          'number.base': 'موجودی باید عدد باشد',
          'number.min': 'موجودی نمی‌تواند منفی باشد'
        }),
      
      sku: Joi.string()
        .pattern(/^[A-Z0-9-]{6,20}$/)
        .required()
        .messages({
          'string.pattern.base': 'کد SKU باید شامل حروف بزرگ و اعداد باشد (6-20 کاراکتر)',
          'any.required': 'کد SKU الزامی است'
        }),
      
      weight: Joi.object({
        value: Joi.number().min(0).required(),
        unit: Joi.string().valid('گرم', 'کیلوگرم', 'لیتر', 'عدد', 'بسته').required()
      }).optional(),
      
      images: Joi.array()
        .items(Joi.string().uri())
        .max(10)
        .default([])
        .messages({
          'array.max': 'حداکثر ۱۰ تصویر مجاز است',
          'string.uri': 'آدرس تصویر نامعتبر است'
        }),
      
      tags: Joi.array()
        .items(Joi.string().min(2).max(50))
        .max(20)
        .default([])
        .messages({
          'array.max': 'حداکثر ۲۰ تگ مجاز است',
          'string.min': 'تگ باید حداقل ۲ کاراکتر باشد',
          'string.max': 'تگ نمی‌تواند بیشتر از ۵۰ کاراکتر باشد'
        }),
      
      isActive: Joi.boolean().default(true),
      isFeatured: Joi.boolean().default(false),
      
      specifications: Joi.object({
        origin: Joi.string().max(100),
        shelfLife: Joi.string().max(50),
        storageCondition: Joi.string().max(200),
        certifications: Joi.array().items(Joi.string()),
        ingredients: Joi.string().max(1000)
      }).default({}),
      
      taxRate: Joi.number()
        .min(0).max(100)
        .default(9)
        .messages({
          'number.min': 'نرخ مالیات نمی‌تواند منفی باشد',
          'number.max': 'نرخ مالیات نمی‌تواند بیشتر از ۱۰۰٪ باشد'
        })
    }),
    
    update: Joi.object({
      name: Joi.string().min(3).max(200),
      description: Joi.string().min(10).max(5000),
      price: Joi.number().min(1000).max(1000000000),
      discountPrice: Joi.number().min(0),
      category: Joi.string().valid('rice', 'caviar', 'fish', 'honey', 'chicken', 'souvenir', 'other'),
      stock: Joi.number().integer().min(0),
      sku: Joi.string().pattern(/^[A-Z0-9-]{6,20}$/),
      weight: Joi.object({
        value: Joi.number().min(0),
        unit: Joi.string().valid('گرم', 'کیلوگرم', 'لیتر', 'عدد', 'بسته')
      }),
      images: Joi.array().items(Joi.string().uri()).max(10),
      tags: Joi.array().items(Joi.string().min(2).max(50)).max(20),
      isActive: Joi.boolean(),
      isFeatured: Joi.boolean(),
      specifications: Joi.object(),
      taxRate: Joi.number().min(0).max(100)
    }).min(1), // حداقل یک فیلد باید آپدیت شود
    
    query: Joi.object({
      page: Joi.number().integer().min(1).default(1),
      limit: Joi.number().integer().min(1).max(100).default(20),
      sort: Joi.string().valid('price', '-price', 'createdAt', '-createdAt', 'name', '-name'),
      category: Joi.string().valid('rice', 'caviar', 'fish', 'honey', 'chicken', 'souvenir', 'other', 'all'),
      minPrice: Joi.number().min(0),
      maxPrice: Joi.number().min(0),
      search: Joi.string().min(1).max(100),
      featured: Joi.boolean(),
      inStock: Joi.boolean()
    })
  };

  static validate(schema) {
    return (req, res, next) => {
      const { error, value } = schema.validate(req.body || req.query, {
        abortEarly: false,
        stripUnknown: true,
        convert: true
      });

      if (error) {
        const validationErrors = error.details.map(detail => ({
          field: detail.path.join('.'),
          message: detail.message,
          type: detail.type
        }));

        throw ErrorBuilder.validationError(validationErrors);
      }

      // Replace with validated data
      if (req.body) req.body = value;
      if (req.query) req.query = value;
      
      next();
    };
  }

  static create() {
    return this.validate(this.schemas.create);
  }

  static update() {
    return this.validate(this.schemas.update);
  }

  static query() {
    return this.validate(this.schemas.query);
  }

  // 🏷️ Bulk validation for imports
  static bulkCreate() {
    return (req, res, next) => {
      if (!Array.isArray(req.body)) {
        throw ErrorBuilder.validationError([{
          field: 'body',
          message: 'بدنه درخواست باید آرایه‌ای از محصولات باشد',
          type: 'array.base'
        }]);
      }

      const errors = [];
      const validatedProducts = [];

      req.body.forEach((product, index) => {
        const { error, value } = this.schemas.create.validate(product, {
          abortEarly: false,
          stripUnknown: true
        });

        if (error) {
          errors.push({
            index,
            errors: error.details.map(detail => ({
              field: detail.path.join('.'),
              message: detail.message,
              type: detail.type
            }))
          });
        } else {
          validatedProducts.push(value);
        }
      });

      if (errors.length > 0) {
        throw ErrorBuilder.bulkValidationError(errors);
      }

      req.body = validatedProducts;
      next();
    };
  }
}

module.exports = ProductValidator;