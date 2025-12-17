import jwt from 'jsonwebtoken';
import crypto from 'node:crypto';
import {hasRight, hasRole, ROLES, RIGHTS} from '../config/rights.js';
import {normalizeRoles} from './user.middleware.js';
import {cache} from './cache.middleware.js';
import logger from '../utils/app.logger.js';
import User from '../models/user.model.js';
import cookie from 'cookie';
import cookieParserLib from 'cookie-parser';
import {parse as parseUrl} from 'node:url';

// =============================================================================
// CSRF PROTECTION CONFIGURATION
// =============================================================================

const CSRF_TOKEN_LENGTH = 32;
const CSRF_COOKIE_NAME = 'csrfToken';
const CSRF_HEADER_NAME = 'x-csrf-token';
const CSRF_TOKEN_EXPIRY = 24 * 60 * 60 * 1000; // 24 hours

// Methods that require CSRF protection (state-changing operations)
const CSRF_PROTECTED_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'];

// Routes exempt from CSRF protection (public endpoints)
// These should match the full request path (req.originalUrl)
const CSRF_EXEMPT_ROUTES = [
    '/api/v1/auth/login',
    '/api/v1/auth/signup',
    '/api/v1/auth/forgot-password',
    '/api/v1/auth/reset-password', // Has its own token-based security
    '/api/v1/auth/refresh-token',
    '/api/v1/auth/verify-email',
    '/api/v1/contact',
    '/health',
    '/api/v1/health'
];

// =============================================================================
// REFRESH TOKEN ROTATION & CHAIN TRACKING CONFIGURATION
// =============================================================================

// Token family tracking for detecting token reuse attacks
// When a refresh token is used, we create a new "family" chain
// If an old token from the same family is reused, it indicates a potential attack
const REFRESH_TOKEN_FAMILY_PREFIX = 'auth:token_family:';
const REFRESH_TOKEN_USED_PREFIX = 'auth:refresh_used:';

/**
 * Generate a unique token family ID for refresh token chains
 * @returns {string} Unique family ID
 */
const generateTokenFamilyId = () => {
    return crypto.randomBytes(16).toString('hex');
};

/**
 * Store token family information for chain tracking
 * @param {string} familyId - Token family ID
 * @param {string} userId - User ID
 * @param {number} expirySeconds - Expiry time in seconds
 */
const storeTokenFamily = async (familyId, userId, expirySeconds = 172800) => {
    try {
        await cache.set(`${REFRESH_TOKEN_FAMILY_PREFIX}${familyId}`, {
            userId,
            createdAt: Date.now(),
            isValid: true
        }, expirySeconds);
    } catch (error) {
        logger.error('[Auth Middleware] Error storing token family:', error);
    }
};

/**
 * Mark a refresh token as used (for rotation tracking)
 * @param {string} tokenHash - Hash of the refresh token
 * @param {string} familyId - Token family ID
 * @param {number} expirySeconds - Expiry time in seconds
 */
const markRefreshTokenUsed = async (tokenHash, familyId, expirySeconds = 172800) => {
    try {
        await cache.set(`${REFRESH_TOKEN_USED_PREFIX}${tokenHash}`, {
            familyId,
            usedAt: Date.now()
        }, expirySeconds);
    } catch (error) {
        logger.error('[Auth Middleware] Error marking refresh token as used:', error);
    }
};

/**
 * Check if a refresh token has been used before (potential reuse attack)
 * @param {string} tokenHash - Hash of the refresh token
 * @returns {Promise<Object|null>} Token usage info if used, null if fresh
 */
const checkRefreshTokenReuse = async (tokenHash) => {
    try {
        return await cache.get(`${REFRESH_TOKEN_USED_PREFIX}${tokenHash}`);
    } catch (error) {
        logger.error('[Auth Middleware] Error checking refresh token reuse:', error);
        return null;
    }
};

/**
 * Invalidate an entire token family (used when reuse is detected)
 * This forces all tokens in the family to be invalid
 * @param {string} familyId - Token family ID
 */
const invalidateTokenFamily = async (familyId) => {
    try {
        const familyKey = `${REFRESH_TOKEN_FAMILY_PREFIX}${familyId}`;
        const familyData = await cache.get(familyKey);
        
        if (familyData) {
            // Mark family as invalid
            await cache.set(familyKey, {
                ...familyData,
                isValid: false,
                invalidatedAt: Date.now()
            }, 172800); // Keep for 2 days for audit
            
            logger.warn('[Auth Middleware] Token family invalidated due to potential reuse attack', {
                familyId,
                userId: familyData.userId
            });
        }
    } catch (error) {
        logger.error('[Auth Middleware] Error invalidating token family:', error);
    }
};

/**
 * Check if a token family is still valid
 * @param {string} familyId - Token family ID
 * @returns {Promise<boolean>} True if family is valid
 */
const isTokenFamilyValid = async (familyId) => {
    try {
        const familyData = await cache.get(`${REFRESH_TOKEN_FAMILY_PREFIX}${familyId}`);
        return familyData?.isValid === true;
    } catch (error) {
        logger.error('[Auth Middleware] Error checking token family validity:', error);
        return true; // Fail-open for availability
    }
};

/**
 * Hash a token for storage (don't store raw tokens)
 * @param {string} token - Raw token
 * @returns {string} Hashed token
 */
const hashToken = (token) => {
    return crypto.createHash('sha256').update(token).digest('hex');
};

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
    // CSRF Protection exports
    csrfProtection,
    attachCsrfToken,
    validateCsrfToken,
    getCsrfToken,
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    // Refresh Token Rotation exports
    generateTokenFamilyId,
    storeTokenFamily,
    markRefreshTokenUsed,
    checkRefreshTokenReuse,
    invalidateTokenFamily,
    isTokenFamilyValid,
    hashToken,
    ROLES,
    RIGHTS
};

// =============================================================================
// CSRF PROTECTION MIDDLEWARE
// =============================================================================

/**
 * Generate a cryptographically secure CSRF token
 * @returns {string} Random hex string
 */
const generateCsrfToken = () => {
    return crypto.randomBytes(CSRF_TOKEN_LENGTH).toString('hex');
};

/**
 * Set CSRF token cookie
 * @param {Object} res - Express response object
 * @param {string} token - CSRF token
 */
const setCsrfCookie = (res, token) => {
    // For cross-origin requests (web on different port than server),
    // we need sameSite: 'none' with secure: true.
    // Chrome 80+ requires secure: true for sameSite: 'none' even on localhost.
    res.cookie(CSRF_COOKIE_NAME, token, {
        httpOnly: false, // Must be readable by JavaScript to include in header
        secure: true, // Required for sameSite: 'none' in all modern browsers
        sameSite: 'none', // Required for cross-origin requests
        maxAge: CSRF_TOKEN_EXPIRY,
        path: '/'
    });
};

/**
 * Middleware to generate and attach CSRF token to response
 */
const attachCsrfToken = (req, res, next) => {
    const existingToken = req.cookies?.[CSRF_COOKIE_NAME];
    
    if (!existingToken) {
        const newToken = generateCsrfToken();
        setCsrfCookie(res, newToken);
        req.csrfToken = newToken;
        
        logger.verbose('[CSRF] New CSRF token generated', {
            ip: req.ip,
            path: req.path
        });
    } else {
        req.csrfToken = existingToken;
    }
    
    next();
};

/**
 * Timing-safe string comparison to prevent timing attacks
 * @param {string} a - First string
 * @param {string} b - Second string
 * @returns {boolean} True if strings are equal
 */
const timingSafeEqual = (a, b) => {
    if (typeof a !== 'string' || typeof b !== 'string') {
        return false;
    }
    
    if (a.length !== b.length) {
        return false;
    }
    
    try {
        const bufferA = Buffer.from(a, 'utf8');
        const bufferB = Buffer.from(b, 'utf8');
        return crypto.timingSafeEqual(bufferA, bufferB);
    } catch {
        return false;
    }
};

/**
 * Middleware to validate CSRF token on state-changing requests
 */
const validateCsrfToken = (req, res, next) => {
    // Skip for non-protected methods
    if (!CSRF_PROTECTED_METHODS.includes(req.method)) {
        return next();
    }
    
    // Skip for exempt routes - use originalUrl to get the full path including mount prefix
    const path = req.originalUrl || req.path;
    if (CSRF_EXEMPT_ROUTES.some(exemptRoute => path.startsWith(exemptRoute))) {
        return next();
    }
    
    const cookieToken = req.cookies?.[CSRF_COOKIE_NAME];
    const headerToken = req.get(CSRF_HEADER_NAME);
    
    // If no auth cookie exists, skip CSRF validation - let auth middleware handle it
    // CSRF is only relevant for authenticated requests
    const authCookie = req.cookies?.accessToken;
    if (!authCookie) {
        return next();
    }
    
    if (!cookieToken) {
        logger.warn('[CSRF] Missing CSRF cookie token', {
            ip: req.ip,
            path: req.path,
            method: req.method
        });
        return res.status(403).json({
            success: false,
            message: 'CSRF token missing. Please refresh the page and try again.'
        });
    }
    
    if (!headerToken) {
        logger.warn('[CSRF] Missing CSRF header token', {
            ip: req.ip,
            path: req.path,
            method: req.method
        });
        return res.status(403).json({
            success: false,
            message: 'CSRF token header missing. Please include X-CSRF-Token header.'
        });
    }
    
    if (!timingSafeEqual(cookieToken, headerToken)) {
        logger.warn('[CSRF] CSRF token mismatch', {
            ip: req.ip,
            path: req.path,
            method: req.method
        });
        return res.status(403).json({
            success: false,
            message: 'CSRF token validation failed. Please refresh the page and try again.'
        });
    }
    
    logger.verbose('[CSRF] CSRF token validated successfully', {
        ip: req.ip,
        path: req.path,
        method: req.method
    });
    
    next();
};

/**
 * Combined CSRF middleware - attaches and validates in one step
 */
const csrfProtection = (req, res, next) => {
    attachCsrfToken(req, res, () => {
        validateCsrfToken(req, res, next);
    });
};

/**
 * Endpoint handler to get a fresh CSRF token
 */
const getCsrfToken = (req, res) => {
    const token = generateCsrfToken();
    setCsrfCookie(res, token);
    
    res.status(200).json({
        success: true,
        message: 'CSRF token generated',
        csrfToken: token
    });
};