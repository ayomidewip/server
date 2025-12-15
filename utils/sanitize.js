import sanitizeHtml from 'sanitize-html';
import logger from '../utils/app.logger.js';

/**
 * Sanitize HTML input to prevent XSS attacks
 * @param {string} input - String to sanitize
 * @returns {string} - Sanitized string with HTML tags removed/escaped
 */
export const sanitizeHtmlInput = (input) => {
    if (typeof input !== 'string') {
        return input;
    }

    // Remove all HTML tags and potentially dangerous content
    return sanitizeHtml(input, {
        allowedTags: [], // No HTML tags allowed
        allowedAttributes: {}, // No attributes allowed
        disallowedTagsMode: 'discard' // Remove disallowed tags entirely
    });
};

/**
 * Recursively sanitize HTML content in an object
 * @param {any} obj - Object to sanitize
 * @returns {any} - Object with HTML content sanitized
 */
export const sanitizeHtmlInObject = (obj) => {
    if (!obj || typeof obj !== 'object') {
        return typeof obj === 'string' ? sanitizeHtmlInput(obj) : obj;
    }

    // Handle arrays
    if (Array.isArray(obj)) {
        return obj.map(item => sanitizeHtmlInObject(item));
    }

    // Create a sanitized copy
    const sanitized = {};

    for (const [key, value] of Object.entries(obj)) {
        if (typeof value === 'string') {
            sanitized[key] = sanitizeHtmlInput(value);
        } else if (typeof value === 'object' && value !== null) {
            sanitized[key] = sanitizeHtmlInObject(value);
        } else {
            sanitized[key] = value;
        }
    }

    return sanitized;
};

/**
 * Recursively sanitize sensitive data from objects
 * Creates a deep copy to avoid modifying the original object
 * @param {any} obj - Object to sanitize
 * @returns {any} - Sanitized copy of the object
 */
export const sanitizeObject = (obj) => {
    if (!obj || typeof obj !== 'object') {
        return obj;
    }

    // Handle arrays
    if (Array.isArray(obj)) {
        return obj.map(item => sanitizeObject(item));
    }

    // Create a deep clone to avoid modifying the original object
    let sanitized = {};

    // Define sensitive fields that should be redacted
    const sensitiveFields = [
        'password',
        'newPassword',
        'confirmPassword',
        'currentPassword',
        'oldPassword',
        'token',
        'secret',
        'key',
        'accessToken',
        'refreshToken'
    ];

    for (const [key, value] of Object.entries(obj)) {
        const lowerKey = key.toLowerCase();

        // Check if the key is sensitive
        const isSensitive = sensitiveFields.some(field =>
            lowerKey === field.toLowerCase() || // Exact match
            lowerKey.includes(field.toLowerCase()) || // Contains sensitive word
            lowerKey.endsWith('password') ||
            lowerKey.endsWith('token') ||
            lowerKey.endsWith('secret') ||
            lowerKey.endsWith('key')
        );

        if (isSensitive) {
            // Replace sensitive data with [REDACTED] in the copy only
            sanitized[key] = '[REDACTED]';

            // Add debugging for sensitive fields in development
            if (process.env.NODE_ENV === 'development') {
                logger.debug(`Sanitized sensitive field: ${key}`);
            }
        } else if (typeof value === 'object' && value !== null) {
            // Recursively sanitize nested objects
            sanitized[key] = sanitizeObject(value);
        } else {
            // Copy the value as-is for non-sensitive fields
            sanitized[key] = value;
        }
    }

    return sanitized;
};

/**
 * Safely truncate an object to ensure it doesn't exceed a maximum size
 * @param {any} obj - Object to truncate
 * @param {number} maxSize - Maximum size in bytes
 * @returns {any} - Truncated object
 */
export const truncateObject = (obj, maxSize) => {
    if (!obj || typeof obj !== 'object') return obj;

    try {
        // Use safe stringification to handle circular references
        const str = JSON.stringify(obj, function (key, value) {
            if (typeof value === 'object' && value !== null) {
                if (this[key] === value) {
                    return '[Circular]';
                }
            }
            return value;
        });

        if (str.length <= maxSize) return obj;

        // If object is too large, create a truncated version
        return {
            _truncated: true,
            _originalSize: str.length,
            _truncatedAt: maxSize,
            summary: str.substring(0, maxSize) + '...'
        };
    } catch (error) {
        // Handle any errors in stringification
        return {
            _error: true,
            _errorMessage: error.message || 'Error truncating object',
            _truncated: true,
            _type: Array.isArray(obj) ? 'array' : typeof obj,
            _keys: typeof obj === 'object' && obj !== null ? Object.keys(obj).slice(0, 10) : []
        };
    }
};
