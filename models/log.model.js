import mongoose from 'mongoose';



/**
 * Determine CRUD operation type based on HTTP method or WebSocket operation
 * @param {string} method - HTTP method (GET, POST, PUT, DELETE, etc.) or WEBSOCKET
 * @returns {string} - CRUD operation type (CREATE, READ, UPDATE, DELETE, WEBSOCKET, OTHER)
 */
function determineOperationType(method) {
    if (!method) return 'OTHER';

    // Convert to uppercase for consistent matching
    const methodUpper = method.toUpperCase();

    switch (methodUpper) {
        case 'GET':
            return 'READ';
        case 'POST':
            return 'CREATE';
        case 'PUT':
        case 'PATCH':
            return 'UPDATE';
        case 'DELETE':
            return 'DELETE';
        case 'WEBSOCKET':
            return 'WEBSOCKET';
        default:
            return 'OTHER';
    }
}

/**
 * Log Schema for MongoDB storage
 * Stores all application logs with structured data
 */
const logSchema = new mongoose.Schema({
    // Core log fields
    timestamp: {
        type: Date, default: Date.now
    }, // HTTP-specific fields
    method: {
        type: String, sparse: true, index: true
    }, url: {
        type: String, sparse: true
    }, statusCode: {
        type: Number, sparse: true, index: true
    }, responseTime: {
        type: Number, sparse: true
    }, ip: {
        type: String, sparse: true
    }, userAgent: {
        type: String, sparse: true
    }, userId: {
        type: mongoose.Schema.Types.ObjectId, ref: 'User', sparse: true
    }, // Request/Response body capture fields with size limits
    requestBody: {
        type: mongoose.Schema.Types.Mixed, sparse: true, validate: {
            validator: function (v) {
                return !v || JSON.stringify(v).length <= 16384; // 16KB limit
            }, message: 'Request body exceeds maximum allowed size of 16KB'
        }
    }, responseBody: {
        type: mongoose.Schema.Types.Mixed, sparse: true, validate: {
            validator: function (v) {
                return !v || JSON.stringify(v).length <= 16384; // 16KB limit
            }, message: 'Response body exceeds maximum allowed size of 16KB'
        }
    }, requestHeaders: {
        type: mongoose.Schema.Types.Mixed, sparse: true, validate: {
            validator: function (v) {
                return !v || JSON.stringify(v).length <= 4096; // 4KB limit
            }, message: 'Request headers exceed maximum allowed size of 4KB'
        }
    }, responseHeaders: {
        type: mongoose.Schema.Types.Mixed, sparse: true, validate: {
            validator: function (v) {
                return !v || JSON.stringify(v).length <= 4096; // 4KB limit
            }, message: 'Response headers exceed maximum allowed size of 4KB'
        }
    }, contentType: {
        type: String, sparse: true
    }, contentLength: {
        type: Number, sparse: true
    },

    // Error-specific fields
    stack: {
        type: String, sparse: true
    }, errorCode: {
        type: String, sparse: true
    },

    // Additional metadata
    environment: {
        type: String, default: process.env.NODE_ENV
    }, service: {
        type: String, default: 'app-base-server'
    }, meta: {
        type: mongoose.Schema.Types.Mixed, default: {}
    }
}, {
    timestamps: false // We use our own timestamp field
});

// Pre-save middleware to add real-time data
logSchema.pre('save', function (next) {
    // Ensure operation type is inferred from method
    if (this.method && !this.operationType) {
        this.operationType = determineOperationType(this.method);
    }

    next();
});

// Post-save middleware for cache invalidation and real-time updates
logSchema.post('save', async function (doc) {
    try {
        // Import cache utility (delayed to avoid circular dependencies)
        const {cache} = await import('../middleware/cache.middleware.js');

        // Invalidate log-related caches
        await cache.invalidateAllRelatedCaches('log', doc._id.toString());
    } catch (error) {
        // Don't fail the save operation if cache invalidation fails
        console.error('Log post-save middleware error:', error.message);
    }
});

// Indexes for performance
logSchema.index({timestamp: -1});
logSchema.index({method: 1, statusCode: 1}, {sparse: true});
logSchema.index({userId: 1, timestamp: -1}, {sparse: true});
logSchema.index({url: 1, method: 1}, {sparse: true});
logSchema.index({ip: 1, timestamp: -1}, {sparse: true});

// TTL index - automatically delete logs older than 30 days
logSchema.index({timestamp: 1}, {expireAfterSeconds: 30 * 24 * 60 * 60});

/**
 * Static method to create a log entry
 * @param {Object} logData - Log data to store
 * @returns {Promise<Object>} Created log document
 */
logSchema.statics.createLog = async function (logData) {
    try {
        // Import sanitizeObject from the utility module
        const {sanitizeObject, truncateObject} = await import('../utils/sanitize.js');

        // Make a copy of logData to avoid modifying the original
        const sanitizedLogData = {...logData};

        // Sanitize and truncate request and response bodies
        if (sanitizedLogData.requestBody && typeof sanitizedLogData.requestBody === 'object') {
            try {
                // First sanitize sensitive data
                const sanitizedRequestBody = sanitizeObject(sanitizedLogData.requestBody);
                // Then truncate if needed
                sanitizedLogData.requestBody = truncateObject(sanitizedRequestBody, 16384);
            } catch (error) {
                sanitizedLogData.requestBody = {
                    _error: `Failed to process request body: ${error.message}`,
                    _type: typeof sanitizedLogData.requestBody
                };
            }
        }

        if (sanitizedLogData.responseBody && typeof sanitizedLogData.responseBody === 'object') {
            try {
                // First sanitize sensitive data
                const sanitizedResponseBody = sanitizeObject(sanitizedLogData.responseBody);
                // Then truncate if needed
                sanitizedLogData.responseBody = truncateObject(sanitizedResponseBody, 16384);
            } catch (error) {
                sanitizedLogData.responseBody = {
                    _error: `Failed to process response body: ${error.message}`,
                    _type: typeof sanitizedLogData.responseBody
                };
            }
        }

        // Truncate headers if needed
        if (sanitizedLogData.requestHeaders) {
            sanitizedLogData.requestHeaders = truncateObject(sanitizedLogData.requestHeaders, 4096);
        }

        if (sanitizedLogData.responseHeaders) {
            sanitizedLogData.responseHeaders = truncateObject(sanitizedLogData.responseHeaders, 4096);
        }

        // Perform a final validation check before saving
        const requestBodySize = sanitizedLogData.requestBody ? JSON.stringify(sanitizedLogData.requestBody).length : 0;

        const responseBodySize = sanitizedLogData.responseBody ? JSON.stringify(sanitizedLogData.responseBody).length : 0;

        // If sizes still exceed limits after truncation, force truncate again
        if (requestBodySize > 16384) {
            sanitizedLogData.requestBody = {
                _forceTruncated: true,
                _originalSize: requestBodySize,
                _message: "Request body exceeded size limit even after truncation"
            };
        }

        if (responseBodySize > 16384) {
            sanitizedLogData.responseBody = {
                _forceTruncated: true,
                _originalSize: responseBodySize,
                _message: "Response body exceeded size limit even after truncation"
            };
        }

        // Create and save the log with sanitized and truncated data
        const log = new this(sanitizedLogData);
        return await log.save();
    } catch (error) {
        // Fallback to console if database logging fails
        console.error('Failed to save log to database:', error.message || error);
        return null;
    }
};

/**
 * Static method to get logs with pagination and filtering
 * @param {Object} filters - Query filters
 * @param {Object} options - Pagination and sorting options
 * @returns {Promise<Object>} Paginated logs result
 */
logSchema.statics.getLogs = async function (filters = {}, options = {}) {
    const {
        page = 1, limit = 50, sortBy = 'timestamp', sortOrder = 'desc'
    } = options;

    // Special case: if limit is -1 or 'all', return all logs
    const getAllLogs = limit === -1 || limit === 'all';

    const skip = getAllLogs ? 0 : (page - 1) * limit;
    const sort = {[sortBy]: sortOrder === 'desc' ? -1 : 1};

    try {
        let logsQuery = this.find(filters).sort(sort);

        // Only apply pagination if not getting all logs
        if (!getAllLogs) {
            logsQuery = logsQuery.skip(skip).limit(limit);
        }

        const [logs, total] = await Promise.all([logsQuery.lean(), this.countDocuments(filters)]);

        return {
            logs, pagination: {
                current: getAllLogs ? 1 : page,
                pages: getAllLogs ? 1 : Math.ceil(total / limit),
                total,
                limit: getAllLogs ? total : limit
            }
        };
    } catch (error) {
        throw new Error(`Failed to retrieve logs: ${error.message}`);
    }
};

// Export model with added utility functions
// Check if model exists to prevent recompilation errors in tests
const Log = mongoose.models.Log || mongoose.model('Log', logSchema);

// Attach utility functions to the model
Log.determineOperationType = determineOperationType;

export default Log;