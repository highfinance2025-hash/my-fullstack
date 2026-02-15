// src/utils/api-response.js - Consistent API Responses
class ApiResponse {
  static middleware(req, res, next) {
    // ✅ Success response method
    res.api = {
      success: (data, message = '', statusCode = 200) => {
        const response = {
          success: true,
          data,
          message,
          timestamp: new Date().toISOString(),
          requestId: req.id
        };

        // 🔍 Add pagination metadata if present
        if (data && data.data && data.pagination) {
          response.data = data.data;
          response.pagination = data.pagination;
        }

        return res.status(statusCode).json(response);
      },

      // 📄 Paginated response
      paginated: (data, pagination, message = '') => {
        return res.status(200).json({
          success: true,
          data,
          pagination,
          message,
          timestamp: new Date().toISOString(),
          requestId: req.id
        });
      },

      // 🚫 Error response (should be handled by error middleware)
      error: (error) => {
        // This should not be called directly
        // Use next(error) instead
        return next(error);
      },

      // 📤 Created response (201)
      created: (data, message = 'با موفقیت ایجاد شد') => {
        return res.status(201).json({
          success: true,
          data,
          message,
          timestamp: new Date().toISOString(),
          requestId: req.id
        });
      },

      // ✅ No content (204)
      noContent: (message = 'با موفقیت حذف شد') => {
        return res.status(204).json({
          success: true,
          message,
          timestamp: new Date().toISOString(),
          requestId: req.id
        });
      },

      // 🔄 Accepted (202 - async operations)
      accepted: (data, message = 'درخواست شما پذیرفته شد') => {
        return res.status(202).json({
          success: true,
          data,
          message,
          timestamp: new Date().toISOString(),
          requestId: req.id,
          status: 'processing'
        });
      }
    };

    next();
  }
}

module.exports = {
  apiResponse: ApiResponse.middleware,
  ApiResponse
};