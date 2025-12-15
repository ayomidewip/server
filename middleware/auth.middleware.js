import jwt from 'jsonwebtoken';
import {hasRight, hasRole, ROLES, RIGHTS} from '../config/rights.js';
import {normalizeRoles} from './user.middleware.js';
import {cache} from './cache.middleware.js';
import logger from '../utils/app.logger.js'; // Added logger
import User from '../models/user.model.js'; // Added User model for active status check
import cookie from 'cookie';
import cookieParserLib from 'cookie-parser';
import {parse as parseUrl} from 'node:url';

/**
 * Helper function to normalize user roles
 * @param {String|Array} roles - User roles
 * @returns {Array} - Normalized roles array
 */
/**
 * Middleware to verify JWT tokens
 * @param {string} tokenType - Type of token (access or refresh)
 * @returns {Function} - Express middleware
 */
const verifyToken = (tokenType = 'access') => (req, res, next) => {
    try {
        // Get token from cookies only - no backwards compatibility with headers
        const cookieName = tokenType === 'refresh' ? 'refreshToken' : 'accessToken';
        const token = req.cookies?.[cookieName];
        
        if (!token) {
            logger.warn(`${logger.safeColor(logger.colors.yellow)}[Auth Middleware]${logger.safeColor(logger.colors.reset)} Unauthorized: Token cookie missing`, {
                ip: req.ip,
                originalUrl: req.originalUrl,
                cookieName,
                tokenType,
                hasCookies: !!req.cookies
            });
            return res.status(401).json({
                success: false,
                message: 'Unauthorized: Authentication required'
            });
        }

        const secret = tokenType === 'refresh'
            ? process.env.REFRESH_TOKEN_SECRET
            : process.env.ACCESS_TOKEN_SECRET;
            
        jwt.verify(token, secret, async (err, decoded) => {
            if (err) {
                logger.warn(`${logger.safeColor(logger.colors.yellow)}[Auth Middleware]${logger.safeColor(logger.colors.reset)} Invalid or expired token`, {
                    error: err.message,
                    tokenType,
                    ip: req.ip
                });
                return res.status(403).json({
                    success: false,
                    message: 'Invalid or expired token'
                });
            }

            // Check if decoded token has required structure
            if (!decoded.id || !decoded.username || !decoded.email) {
                logger.error(`${logger.safeColor(logger.colors.red)}[Auth Middleware]${logger.safeColor(logger.colors.reset)} Malformed token payload - missing required fields`, {
                    decoded,
                    tokenType,
                    ip: req.ip
                });
                return res.status(500).json({
                    success: false,
                    message: 'Server error during authentication'
                });
            }
            // Check if token is blacklisted (logged out)
            try {
                const isBlacklisted = await cache.get(`auth:blacklist:${token}`);
                if (isBlacklisted) {
                    logger.warn(`${logger.safeColor(logger.colors.yellow)}[Auth Middleware]${logger.safeColor(logger.colors.reset)} Token is blacklisted (logged out)`, {
                        userId: decoded.id,
                        tokenType,
                        ip: req.ip
                    });
                    return res.status(401).json({
                        success: false,
                        message: 'Token has been revoked'
                    });
                }
            } catch (cacheError) {
                logger.error(`${logger.safeColor(logger.colors.red)}[Auth Middleware]${logger.safeColor(logger.colors.reset)} Cache error during blacklist check:`, {
                    message: cacheError.message,
                    error: cacheError
                });
                // Continue with authentication even if cache fails (fail-open for availability)
                // In production, you might want to fail-closed for maximum security
            }

            // Check if user is still active in the database
            try {
                const user = await User.findById(decoded.id).select('+active');
                if (!user) {
                    logger.warn(`${logger.safeColor(logger.colors.yellow)}[Auth Middleware]${logger.safeColor(logger.colors.reset)} User not found`, {
                        userId: decoded.id,
                        tokenType,
                        ip: req.ip
                    });
                    return res.status(401).json({
                        success: false,
                        message: 'User not found'
                    });
                }

                if (user.active === false) {
                    logger.warn(`${logger.safeColor(logger.colors.yellow)}[Auth Middleware]${logger.safeColor(logger.colors.reset)} Account is deactivated`, {
                        userId: decoded.id,
                        tokenType,
                        ip: req.ip
                    });
                    return res.status(401).json({
                        success: false,
                        message: 'Account is deactivated'
                    });
                }

                // Check if password was changed after token was issued
                if (user.changedPasswordAfter && user.changedPasswordAfter(decoded.iat)) {
                    logger.warn(`${logger.safeColor(logger.colors.yellow)}[Auth Middleware]${logger.safeColor(logger.colors.reset)} Password changed after token issued`, {
                        userId: decoded.id,
                        tokenType,
                        ip: req.ip
                    });
                    return res.status(401).json({
                        success: false,
                        message: 'Password changed. Please log in again.'
                    });
                }
            } catch (dbError) {
                logger.error(`${logger.safeColor(logger.colors.red)}[Auth Middleware]${logger.safeColor(logger.colors.reset)} Database error during user active check:`, {
                    message: dbError.message,
                    error: dbError
                });
                return res.status(500).json({
                    success: false,
                    message: 'Server error during authentication'
                });
            }

            // Store decoded user data in request object with normalized roles
            req.user = {
                ...decoded,
                roles: normalizeRoles(decoded.roles)
            };
            next();
        });
    } catch (error) {
        logger.error(`${logger.safeColor(logger.colors.red)}[Auth Middleware]${logger.safeColor(logger.colors.reset)} Auth middleware error:`, {
            message: error.message,
            stack: error.stack,
            error
        });
        res.status(500).json({
            success: false,
            message: 'Server error during authentication'
        });
    }
};

/**
 * Middleware to check if user has required permission
 * @param {string} permission - Permission required to access the resource
 * @returns {Function} - Express middleware
 */
const checkPermission = (permission) => (req, res, next) => {
    try {
        // Check if user object and roles exist
        if (!req.user || !req.user.roles) {
            logger.warn(`${logger.safeColor(logger.colors.yellow)}[Auth Middleware]${logger.safeColor(logger.colors.reset)} Forbidden: Authentication required for permission check`, {
                permission,
                ip: req.ip,
                originalUrl: req.originalUrl
            });
            return res.status(403).json({
                success: false,
                message: 'Forbidden: Authentication required'
            });
        }

        // Check if user has the required permission
        if (!hasRight(req.user.roles, permission)) {
            logger.warn(`${logger.safeColor(logger.colors.yellow)}[Auth Middleware]${logger.safeColor(logger.colors.reset)} Forbidden: Insufficient permissions`, {
                userId: req.user.id,
                roles: req.user.roles,
                requiredPermission: permission,
                ip: req.ip,
                originalUrl: req.originalUrl
            });
            return res.status(403).json({
                success: false,
                message: 'Forbidden: Insufficient permissions'
            });
        }

        next();
    } catch (error) {
        logger.error(`${logger.safeColor(logger.colors.red)}[Auth Middleware]${logger.safeColor(logger.colors.reset)} Permission check error:`, {
            message: error.message,
            stack: error.stack,
            error,
            permission
        });
        res.status(500).json({
            success: false,
            message: 'Server error during permission check'
        });
    }
};

/**
 * Middleware to check user role or higher in hierarchy
 * @param {string} requiredRole - Minimum role required to access the resource
 * @returns {Function} - Express middleware
 */
const checkRole = (requiredRole) => (req, res, next) => {
    try {
        // Check if user object and roles exist
        if (!req.user || !req.user.roles) {
            logger.warn(`${logger.safeColor(logger.colors.yellow)}[Auth Middleware]${logger.safeColor(logger.colors.reset)} Forbidden: Authentication required for role check`, {
                requiredRole,
                ip: req.ip,
                originalUrl: req.originalUrl
            });
            return res.status(403).json({success: false, message: 'Forbidden: Authentication required'});
        }

        // Check if user has the required role or higher
        if (!hasRole(req.user.roles, requiredRole)) {
            logger.warn(`${logger.safeColor(logger.colors.yellow)}[Auth Middleware]${logger.safeColor(logger.colors.reset)} Forbidden: Insufficient role`, {
                userId: req.user.id,
                roles: req.user.roles,
                requiredRole,
                ip: req.ip,
                originalUrl: req.originalUrl
            });
            return res.status(403).json({
                success: false,
                message: `Forbidden: Requires ${requiredRole} role or higher`
            });
        }

        next();
    } catch (error) {
        logger.error(`${logger.safeColor(logger.colors.red)}[Auth Middleware]${logger.safeColor(logger.colors.reset)} Role check error:`, {
            message: error.message,
            stack: error.stack,
            error,
            requiredRole
        });
        res.status(500).json({success: false, message: 'Server error during permission check'});
    }
};

/**
 * Optional authentication middleware - extracts user if token is provided,
 * but doesn't fail if no token is present
 * @param {Object} options - Optional configuration
 */
const optionalAuth = (options = {}) => {
    return async (req, res, next) => {
        try {
            // Check for token in cookies only - no header fallback
            const token = req.cookies?.accessToken;

            // If no token provided, continue without user
            if (!token) {
                req.user = null;
                return next();
            }

            try {
                // Verify token
                const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

                // Check if token is blacklisted
                const isBlacklisted = await cache.get(`auth:blacklist:${token}`);
                if (isBlacklisted) {
                    req.user = null;
                    return next();
                }

                // Find user and check status
                const user = await User.findById(decoded.id).select('+active');
                if (!user || !user.active) {
                    req.user = null;
                    return next();
                }

                // Check password change
                if (user.changedPasswordAfter && user.changedPasswordAfter(decoded.iat)) {
                    req.user = null;
                    return next();
                }

                // Set user info
                req.user = {
                    id: user._id,
                    username: user.username,
                    email: user.email,
                    roles: user.roles,
                    firstName: user.firstName,
                    lastName: user.lastName
                };

                next();
            } catch (jwtError) {
                // Invalid token - continue without user
                req.user = null;
                next();
            }
        } catch (error) {
            logger.error('[Auth Middleware] Error in optional auth:', error);
            req.user = null;
            next();
        }
    };
};

/**
 * WebSocket Authentication helper - leverages existing HTTP auth middleware
 * @param {WebSocket} ws - WebSocket connection
 * @param {Object} req - WebSocket request object
 * @returns {Promise<Object>} - Authenticated user object
 */
const authenticateWebSocket = async (ws, req) => {
    try {
        // Parse cookies and attach to fake req object to reuse existing middleware
        if (req.headers.cookie) {
            const rawCookies = cookie.parse(req.headers.cookie);
            const jsonCookies = cookieParserLib.JSONCookies(rawCookies);
            req.cookies = { ...rawCookies, ...jsonCookies };
        } else {
            req.cookies = {};
        }
        
        // TEMPORARY: Support URL token for existing connections (will be removed)
        // Parse URL parameters as fallback for backwards compatibility
        const parsedUrl = parseUrl(req.url, true);
        const urlToken = parsedUrl.query.token;
        
        // If no cookies but URL token exists, temporarily set it as cookie for validation
        if (!req.cookies.accessToken && !req.cookies.refreshToken && urlToken) {
            logger.warn('WebSocket: Using URL token (DEPRECATED - will be removed)', { tokenLength: urlToken.length });
            // Temporarily set as cookie for existing middleware to process
            req.cookies.accessToken = urlToken;
        }

        // Create promise to capture the middleware result
        return new Promise((resolve, reject) => {
            // Mock res object for middleware
            const mockRes = {
                status: () => mockRes,
                json: (data) => {
                    const error = new Error(data.message || 'Authentication failed');
                    error.statusCode = 401;
                    reject(error);
                }
            };

            // Try access token first
            const accessMiddleware = verifyToken('access');
            accessMiddleware(req, mockRes, (err) => {
                if (err || !req.user) {
                    // Access token failed, try refresh token
                    const refreshMiddleware = verifyToken('refresh');
                    refreshMiddleware(req, mockRes, (refreshErr) => {
                        if (refreshErr || !req.user) {
                            const closeReason = 'Token expired';
                            logger.warn('WebSocket: Authentication failed - no valid tokens', {
                                url: req.url,
                                origin: req.headers.origin,
                                hasCookies: !!req.headers.cookie,
                                hasUrlToken: !!urlToken,
                                userAgent: req.headers['user-agent']
                            });
                            ws.close(1008, closeReason);
                            reject(new Error(closeReason));
                        } else {
                            // Success with refresh token
                            ws.user = req.user;
                            logger.info(`🔌 Authenticated WebSocket connection for user ${req.user.username} (${req.user.id})`);
                            resolve(req.user);
                        }
                    });
                } else {
                    // Success with access token
                    ws.user = req.user;
                    logger.info(`🔌 Authenticated WebSocket connection for user ${req.user.username} (${req.user.id})`);
                    resolve(req.user);
                }
            });
        });
    } catch (error) {
        logger.error('WebSocket authentication error:', error);
        ws.close(1008, 'Authentication failed');
        throw error;
    }
};

export {
    verifyToken,
    checkRole,
    checkPermission,
    optionalAuth,
    authenticateWebSocket,
    ROLES,
    RIGHTS
};