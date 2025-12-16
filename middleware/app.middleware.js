import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import hpp from 'hpp';
import cors from 'cors';
import express from 'express';
import cookieParser from 'cookie-parser';
import logger from '../utils/app.logger.js';
import redis from 'redis';
import {sanitizeObject} from '../utils/sanitize.js';

// Lazy-load Log model to prevent recompilation errors in Vitest
let Log = null;
async function getLogModel() {
    if (!Log) {
        const module = await import('../models/log.model.js');
        Log = module.default;
    }
    return Log;
}

// Wrapper for async route handlers
const asyncHandler = (fn) => (req, res, next) => {
    return Promise.resolve(fn(req, res, next)).catch((err) => {
        if (!err.statusCode) {
            // Use logger.error for unhandled errors in async routes
            logger.error('Async Handler Error:', {
                message: err.message,
                stack: err.stack,
                error: err
            });
        }
        next(err);
    });
};

// Create Redis client with default settings
let redisClient;

redisClient = redis.createClient({
    url: process.env.REDIS_URL,
    socket: {
        reconnectStrategy: (retries) => Math.min(retries * 50, 500)
    },
    disableClientInfo: true
});

// Redis event handlers
redisClient.on('connect', () => {
    // Keep emojis for startup logs as per requirements
    logger.info(`📡 Redis Client connected to Redis (default: localhost:6379)`);
});

redisClient.on('error', (err) => {
    logger.error(`${logger.safeColor(logger.colors.red)}[Redis Client]${logger.safeColor(logger.colors.reset)} Redis connection error:`, err);
});

// Auto-connect Redis (gracefully handle failures)
(async () => {
    try {
        await redisClient.connect();
        // Keep emojis for startup logs as per requirements
        logger.info(`🚀 Redis client connected in ${process.env.NODE_ENV} mode`);
    } catch (err) {
        // Keep emojis for startup logs as per requirements
        logger.warn(`⚠️ Redis not available - caching features will be disabled: ${err.message}`);
    }
})();

// Store all registered routes
const validRoutes = new Set();

// Define ANSI color codes for HTTP logging
const httpColors = {
    green: '\x1b[32m',
    cyan: '\x1b[36m',
    yellow: '\x1b[33m',
    red: '\x1b[31m',
    magenta: '\x1b[35m',
    gray: '\x1b[90m',
    reset: '\x1b[0m',
    bold: '\x1b[1m',
    dim: '\x1b[2m'
};

// Add icons for HTTP methods
const methodIcons = {
    GET: '\u{1F50D}',      // 🔍
    POST: '\u{1F4E4}',     // 📤
    PUT: '\u{1F4DD}',      // 📝
    DELETE: '\u{1F5D1}',   // 🗑️
    PATCH: '\u{1F527}',    // 🔧
    OPTIONS: '\u{1F4AC}',  // 💬
    WEBSOCKET: '\u{1F4F6}', // 📶
};

// Add icons for status codes
const statusIcons = (status) => {
    if (status >= 500) return '\u{1F525}'; // 🔥
    if (status >= 400) return '\u{26A0}\uFE0F'; // ⚠️
    if (status >= 300) return '\u{1F4A1}'; // 💡
    if (status >= 200) return '\u{2705}'; // ✅
    return '\u{1F535}'; // 🔵
};

/**
 * Format response time with color based on duration
 */
const formatResponseTime = (time) => {
    let color = httpColors.green; // Fast response (< 300ms)
    if (time > 1000) {
        color = httpColors.red; // Slow response (> 1000ms)
    } else if (time > 300) {
        color = httpColors.yellow; // Medium response (300-1000ms)
    }

    return `${color}${time.toFixed(2)}ms${httpColors.reset}`;
};

/**
 * Format URL with highlighting for API paths
 */
const formatUrl = (url) => {
    const parts = url.split('/');

    // Highlight API version and resource
    if (parts.length >= 3 && parts[1] === 'api') {
        // Format: /api/v1/resource/id
        const basePath = `/${parts[1]}/${parts[2]}`;
        const resource = parts[3] ? `/${httpColors.bold}${parts[3]}${httpColors.reset}` : '';
        const rest = parts.slice(4).join('/');
        const restPath = rest ? `/${httpColors.dim}${rest}${httpColors.reset}` : '';

        return `${httpColors.cyan}${basePath}${httpColors.reset}${resource}${restPath}`;
    }

    return `${httpColors.cyan}${url}${httpColors.reset}`;
};

/**
 * Format status code with color
 */
const formatStatus = (status) => {
    if (status >= 500) {
        return `${httpColors.red}${status}${httpColors.reset}`;
    } else if (status >= 400) {
        return `${httpColors.yellow}${status}${httpColors.reset}`;
    } else if (status >= 300) {
        return `${httpColors.cyan}${status}${httpColors.reset}`;
    } else if (status >= 200) {
        return `${httpColors.green}${status}${httpColors.reset}`;
    } else {
        return `${httpColors.gray}${status}${httpColors.reset}`;
    }
};

/**
 * Format HTTP method with color and icon
 */
const formatMethod = (method) => {
    const upperMethod = method.toUpperCase();
    const icon = methodIcons[upperMethod] || '';
    let color = httpColors.green;
    if (upperMethod === 'POST') color = httpColors.yellow;
    if (upperMethod === 'PUT') color = httpColors.cyan;
    if (upperMethod === 'DELETE') color = httpColors.red;
    if (upperMethod === 'PATCH') color = httpColors.magenta;
    if (upperMethod === 'WEBSOCKET') color = httpColors.magenta;
    return `${color}${icon} ${upperMethod}${httpColors.reset}`;
};

/**
 * Custom HTTP request logging middleware - simplified
 */
const createHttpLogger = () => {
    return async (req, res, next) => {
        const startHrTime = process.hrtime();

        // Capture request body for logging
        let requestBody = null;
        if (req.body && Object.keys(req.body).length > 0) {
            requestBody = sanitizeObject(req.body);
        }

        // Capture important request headers
        const requestHeaders = {};
        const allowedHeaders = ['content-type', 'accept', 'user-agent', 'origin', 'referer', 'x-requested-with'];
        allowedHeaders.forEach(header => {
            if (req.headers[header]) {
                requestHeaders[header] = req.headers[header];
            }
        });
        // Use lazy-loaded Log model to determine operation type
        const LogModel = await getLogModel();
        requestHeaders['x-operation-type'] = LogModel.determineOperationType(req.method);

        // Override res.json to capture response data
        const originalJson = res.json;
        let responseBody = null;
        res.json = function (data) {
            responseBody = data;
            // Summarize large responses
            const responseStr = JSON.stringify(data);
            if (responseStr.length > 10000) {
                responseBody = {
                    _summary: 'Response too large to log fully',
                    _size: responseStr.length,
                    _type: Array.isArray(data) ? 'array' : typeof data,
                    _firstItems: Array.isArray(data) ? data.slice(0, 3) : undefined,
                    _keys: typeof data === 'object' && data !== null ? Object.keys(data).slice(0, 10) : undefined
                };
            }
            return originalJson.call(this, data);
        };

        // Override res.end to capture final response
        const originalEnd = res.end;
        res.end = function (...args) {
            const elapsedHrTime = process.hrtime(startHrTime);
            const elapsedTimeInMs = elapsedHrTime[0] * 1000 + elapsedHrTime[1] / 1000000;

            const url = req.originalUrl || req.url;
            const method = formatMethod(req.method);
            const status = formatStatus(res.statusCode);
            const statusIcon = statusIcons(res.statusCode);
            const responseTime = formatResponseTime(elapsedTimeInMs);
            const formattedUrl = formatUrl(url);

            // Create beautiful console message
            const consoleLogMessage = `${method} ${formattedUrl} ${status} ${statusIcon} ${responseTime}`;

            // Capture response headers
            const responseHeaders = {};
            const allowedResponseHeaders = ['content-type', 'content-length', 'cache-control', 'x-cache', 'x-cache-status'];
            allowedResponseHeaders.forEach(header => {
                if (res.getHeader(header)) {
                    responseHeaders[header] = res.getHeader(header);
                }
            });

            // Prepare metadata for database logging
            const logData = {
                method: req.method,
                url: url,
                statusCode: res.statusCode,
                responseTime: elapsedTimeInMs,
                ip: req.ip || req.connection.remoteAddress,
                userAgent: req.get('User-Agent'),
                userId: req.user ? req.user.id : null,
                requestBody: requestBody,
                responseBody: responseBody,
                requestHeaders: Object.keys(requestHeaders).length > 0 ? requestHeaders : undefined,
                responseHeaders: Object.keys(responseHeaders).length > 0 ? responseHeaders : undefined,
                contentType: res.getHeader('content-type'),
                contentLength: res.getHeader('content-length') ? parseInt(res.getHeader('content-length')) : undefined
            };

            // Log the beautiful HTTP message with database ObjectId
            logger.http(consoleLogMessage, logData);

            // Verbose logging is now handled directly in appLogger.http() method
            // No need for separate logger.data() calls here anymore

            // Handle cache invalidation
            try {
                if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) && res.statusCode >= 200 && res.statusCode < 300) {
                    let entityType = 'unknown';
                    let entityId = null;

                    if (url.includes('/api/v1/users/')) {
                        entityType = 'user';
                        const userMatch = url.match(/\/api\/v1\/users\/([^\/]+)/);
                        entityId = userMatch ? userMatch[1] : null;
                    } else if (url.includes('/api/v1/files/')) {
                        entityType = 'file';
                        const fileMatch = url.match(/\/api\/v1\/files\/([^\/]+)/);
                        entityId = fileMatch ? fileMatch[1] : null;
                    } else if (url.includes('/api/v1/auth/')) {
                        entityType = 'auth';
                        entityId = req.user ? req.user.id : null;
                    }

                    if (entityType !== 'unknown') {
                        import('./cache.middleware.js')
                            .then(({invalidateEntityCache}) => {
                                if (invalidateEntityCache) {
                                    invalidateEntityCache(entityType, entityId, req.user ? req.user.id : null);
                                }
                            })
                            .catch(() => {});
                    }
                }
            } catch (error) {
                // Swallow cache invalidation errors to avoid affecting response lifecycle
            }

            originalEnd.apply(this, args);
        };

        next();
    };
};

/**
 * Register routes for validation
 * @param {Array<string>} routes - Array of route paths
 */
const registerRoutes = (routes) => {    // Add starting message with emoji for startup
    logger.info(`⚙️ Registering API routes...`);

    routes.forEach(route => validRoutes.add(route));

    // Add completion message with emoji for startup
    logger.info(`✅  API routes registered.`);
};

/**
 * Helper function to check if a path matches a route pattern
 * @param {string} path - The requested path
 * @param {string} pattern - The route pattern (may contain :param)
 * @returns {boolean} - True if path matches pattern
 */
const matchRoute = (path, pattern) => {
    // Convert pattern to regex by replacing :param with [^/]+
    const regexPattern = pattern.replace(/:[^/]+/g, '[^/]+');
    const regex = new RegExp(`^${regexPattern}(?:/.*)?$`);
    return regex.test(path);
};

/**
 * Middleware to validate routes
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Next middleware function
 */
const validateRoute = (req, res, next) => {
    const path = req.originalUrl;

    // Skip validation for health checks and root paths
    if (path === '/health' || path === '/api/v1/health' || path === '/') {
        return next();
    }

    // Check if the route or a parent route is valid
    let isValid = false;
    let matchedRoute = null;

    for (const route of validRoutes) {
        // Check if path starts with a registered route (for simple routes)
        // or matches the pattern (for parameterized routes)
        if (path.startsWith(route) || matchRoute(path, route)) {
            isValid = true;
            matchedRoute = route;
            break;
        }
    }

    if (isValid) {
        // Route is valid - continue to next middleware
        return next();
    }

    // Invalid route - send immediate 404 response to prevent hanging
    logger.warn(`${logger.safeColor(logger.colors.yellow)}[Route Validation]${logger.safeColor(logger.colors.reset)} Invalid route requested: ${path}`, {
        ip: req.ip || req.connection.remoteAddress,
        method: req.method,
        url: req.originalUrl,
        userAgent: req.get('User-Agent')
    });

    // Send proper JSON response immediately
    return res.status(404).json({
        success: false,
        message: `Can't find ${req.originalUrl} on this server!`
    });
};

/**
 * Setup logging for development/test environments
 */
const setupLogging = (app) => {
    // Apply our custom HTTP request logging middleware
    app.use(createHttpLogger());
};

/**
 * Setup security middleware for all environments
 */
const setupSecurity = (app) => {

    // Set security HTTP headers (always enabled)
    app.use(helmet({}));

    // Prevent parameter pollution (always enabled)
    app.use(hpp());
    // Get rate limiting configuration from environment variables
    const rateLimitWindowMs = parseInt(process.env.RATE_LIMIT_WINDOW_MS);
    const rateLimitMaxRequests = parseInt(process.env.RATE_LIMIT_MAX_REQUESTS);
    const rateLimitAuthWindowMs = parseInt(process.env.RATE_LIMIT_AUTH_WINDOW_MS);
    const rateLimitAuthMaxRequests = parseInt(process.env.RATE_LIMIT_AUTH_MAX_REQUESTS);

    // General rate limiting using environment configuration
    const limiter = rateLimit({
        windowMs: rateLimitWindowMs,
        max: rateLimitMaxRequests,
        message: {
            success: false,
            message: 'Too many requests from this IP, please try again later'
        },
        standardHeaders: true,
        legacyHeaders: false,
        handler: (req, res) => {
            logger.warn(`${logger.safeColor(logger.colors.yellow)}[Rate Limit]${logger.safeColor(logger.colors.reset)} Rate limit exceeded for IP: ${req.ip}`, {
                ip: req.ip,
                method: req.method,
                url: req.originalUrl,
                windowMs: rateLimitWindowMs,
                maxRequests: rateLimitMaxRequests
            });

            res.status(429).json({
                success: false,
                message: 'Too many requests from this IP, please try again later'
            });
        }
    });
    app.use('/api', limiter);

    // Auth rate limiting using environment configuration
    const authLimiter = rateLimit({
        windowMs: rateLimitAuthWindowMs,
        max: rateLimitAuthMaxRequests,
        message: {
            success: false,
            message: 'Too many auth attempts from this IP, please try again later'
        },
        standardHeaders: true,
        legacyHeaders: false,
        handler: (req, res) => {
            logger.warn(`${logger.safeColor(logger.colors.yellow)}[Auth Rate Limit]${logger.safeColor(logger.colors.reset)} Auth rate limit exceeded for IP: ${req.ip}`, {
                ip: req.ip,
                method: req.method,
                url: req.originalUrl,
                windowMs: rateLimitAuthWindowMs,
                maxRequests: rateLimitAuthMaxRequests
            });

            res.status(429).json({
                success: false,
                message: 'Too many auth attempts from this IP, please try again later'
            });
        }
    });
    app.use('/api/v1/auth/', authLimiter);

    const envType = process.env.NODE_ENV;
    logger.info(`🛡️ ${envType} mode: Security middleware enabled with configurable rate limits (General: ${rateLimitMaxRequests}/${rateLimitWindowMs}ms, Auth: ${rateLimitAuthMaxRequests}/${rateLimitAuthWindowMs}ms)`);
};

/**
 * Setup CORS configuration
 */
const setupCors = (app) => {
    // Validate that ALLOWED_ORIGINS is properly configured
    if (!process.env.ALLOWED_ORIGINS) {
        logger.error('FATAL: ALLOWED_ORIGINS environment variable is not set. Server cannot start without explicit CORS configuration.');
        process.exit(1);
    }

    const getAllowedOrigins = () => {
        const envOrigins = process.env.ALLOWED_ORIGINS;
        if (!envOrigins || envOrigins.trim() === '') {
            logger.error('FATAL: ALLOWED_ORIGINS is empty. Server requires explicit origin configuration.');
            process.exit(1);
        }
        return envOrigins.split(',').map(origin => origin.trim()).filter(origin => origin.length > 0);
    };

    const allowedOrigins = getAllowedOrigins();
    const corsOptions = {
        origin: (origin, callback) => {
            // Allow requests with no origin (like health checks from Render)
            if (!origin) {
                return callback(null, true);
            }
            
            // Allow explicitly configured origins
            if (allowedOrigins.includes(origin)) {
                return callback(null, true);
            }

            // Reject unauthorized origins with proper logging
            logger.warn(`CORS: Rejecting request from unauthorized origin: ${origin}`);
            return callback(null, false);
        },
        credentials: true,
        methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
        allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'X-CSRF-Token', 'x-csrf-token', 'Accept', 'Origin'],
        exposedHeaders: ['Set-Cookie'],
        optionsSuccessStatus: 200, // For legacy browser support
        preflightContinue: false, // Pass control to next handler after preflight
        maxAge: 86400 // Cache preflight for 24 hours
    };    // Enable CORS before any routes
    app.use(cors(corsOptions));

    // Keep emojis for startup logs as per requirements
    logger.info(`🌐 CORS configured for ${process.env.NODE_ENV} environment with ${allowedOrigins.length} allowed origins`);
    logger.info(`📱 Mobile app requests (no-origin) are allowed`);
};

/**
 * Parse string size format to bytes
 * @param {string} sizeStr - Size string (e.g., '1mb', '500kb')
 * @returns {number} Size in bytes
 */
function parseSize(sizeStr) {
    const units = {
        b: 1,
        kb: 1024,
        mb: 1024 * 1024,
        gb: 1024 * 1024 * 1024
    };

    const match = sizeStr.toLowerCase().match(/^(\d+(?:\.\d+)?)\s*([a-z]+)$/);

    if (!match) {
        return parseInt(sizeStr) || 1048576; // Default to 1MB if parsing fails
    }

    const size = parseFloat(match[1]);
    const unit = match[2];

    return Math.floor(size * (units[unit] || units.mb));
}

/**
 * Create middleware that limits request body size
 * @param {string|number} maxSize - Maximum size in bytes or string (e.g., '1mb')
 * @returns {Function} Express middleware
 */
const limitPayloadSize = (maxSize = '1mb') => {
    // Convert string size to bytes
    const bytes = typeof maxSize === 'string'
        ? parseSize(maxSize)
        : maxSize;

    return (req, res, next) => {
        // Get content length from headers
        const contentLength = req.headers['content-length'];

        if (contentLength && parseInt(contentLength) > bytes) {
            // Log the rejection
            logger.warn(`${logger.safeColor(logger.colors.yellow)}[App Middleware]${logger.safeColor(logger.colors.reset)} Request payload too large: ${contentLength} bytes (limit: ${bytes} bytes)`, {
                ip: req.ip,
                method: req.method,
                url: req.originalUrl,
                contentLength,
                maxSize: bytes
            });

            // Return 413 Payload Too Large immediately
            return res.status(413).json({
                success: false,
                message: `Request payload size (${contentLength} bytes) exceeds the limit (${bytes} bytes)`
            });
        }

        next();
    };
};

/**
 * Create middleware that sets request timeout to prevent hanging
 * @param {number} timeoutMs - Timeout in milliseconds (default: 30 seconds)
 * @returns {Function} Express middleware
 */
const requestTimeout = (timeoutMs = 30000) => {
    return (req, res, next) => {
        // Set response timeout
        res.setTimeout(timeoutMs, () => {
            if (!res.headersSent) {
                logger.warn(`${logger.safeColor(logger.colors.red)}[Request Timeout]${logger.safeColor(logger.colors.reset)} Request timed out after ${timeoutMs}ms`, {
                    ip: req.ip,
                    method: req.method,
                    url: req.originalUrl,
                    timeout: timeoutMs
                });

                res.status(408).json({
                    success: false,
                    message: 'Request timeout - the server took too long to respond'
                });
            }
        });

        next();
    };
};

/**
 * Setup all middleware for the application
 * @param {Object} app - Express application
 * @returns {Promise<void>}
 */
const setupMiddleware = async (app) => {
    // Setup request timeout first to prevent hanging requests
    app.use(requestTimeout(30000)); // 30 second timeout

    // Setup CORS next
    setupCors(app);

    const maxRequestSize = process.env.MAX_REQUEST_SIZE;

    // Apply explicit payload size limiting middleware
    app.use(limitPayloadSize(maxRequestSize));

    // Body parsers with size limits for security - skip multipart for file uploads
    app.use((req, res, next) => {
        // Skip JSON parsing for multipart/form-data requests (file uploads)
        const contentType = req.get('content-type') || '';
        
        if (contentType.startsWith('multipart/form-data')) {
            return next();
        }
        return express.json({limit: maxRequestSize})(req, res, next);
    });
    app.use(express.urlencoded({extended: true, limit: maxRequestSize})); // Parses URL-encoded data with size limit

    // Cookie parser for authentication token cookies
    app.use(cookieParser());

    // Setup security features
    setupSecurity(app);
    
    // Setup request logging
    setupLogging(app);

};

/**
 * Handle 404 errors for undefined routes - final catch-all
 */
const handleUndefinedRoutes = (app) => {
    app.use((req, res, next) => {
        // Check if response has already been sent to prevent multiple responses
        if (res.headersSent) {
            return next();
        }

        // Log the undefined route access attempt
        logger.warn(`${logger.safeColor(logger.colors.yellow)}[Undefined Route]${logger.safeColor(logger.colors.reset)} 404 - Route not found: ${req.originalUrl}`, {
            ip: req.ip || req.connection.remoteAddress,
            method: req.method,
            url: req.originalUrl,
            userAgent: req.get('User-Agent')
        });

        // Ensure proper headers and send immediate JSON response
        res.status(404)
            .set('Content-Type', 'application/json')
            .json({
                success: false,
                message: `Can't find ${req.originalUrl} on this server!`
            });
    });
};

export {
    setupMiddleware,
    registerRoutes,
    validateRoute,
    handleUndefinedRoutes,
    setupSecurity,
    setupLogging,
    setupCors,
    redisClient,
    limitPayloadSize,
    requestTimeout,
    sanitizeObject,
    asyncHandler
};
