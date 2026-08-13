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
 * Parse a JWT expiry string (e.g. '20m', '1h', '7d') to seconds.
 * Exported so auth.controller.js can reuse it for cookie maxAge calculations
 * rather than maintaining a duplicate inline implementation.
 * @param {string} str - Expiry string
 * @returns {number} Expiry in seconds
 */
const parseExpiryToSeconds = (str = '') => {
    const unit = str.slice(-1);
    const value = parseInt(str.slice(0, -1), 10);
    if (isNaN(value)) return 0;
    switch (unit) {
        case 'm': return value * 60;
        case 'h': return value * 60 * 60;
        case 'd': return value * 24 * 60 * 60;
        default:  return value;
    }
};

const parseExpiryToMs = (str) => parseExpiryToSeconds(str) * 1000;

/**
 * Shared cookie options for all httpOnly auth token cookies.
 * base.eccco.space and api.eccco.space share the same eTLD+1 (eccco.space),
 * making them same-site. sameSite:'lax' is therefore correct in production
 * and more secure than 'none', which is only needed for cross-site contexts
 * (different eTLD+1, e.g. app.foo.com → api.bar.com).
 */
const TOKEN_COOKIE_OPTIONS = {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/'
};

// Token lifetimes from env – single source of truth for TTL defaults below.
const REFRESH_TOKEN_EXPIRY_S = parseExpiryToSeconds(process.env.REFRESH_TOKEN_EXPIRY);

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
const storeTokenFamily = async (familyId, userId, expirySeconds = REFRESH_TOKEN_EXPIRY_S) => {
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
const markRefreshTokenUsed = async (tokenHash, familyId, expirySeconds = REFRESH_TOKEN_EXPIRY_S) => {
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
        // null means the key is missing (never stored or TTL expired) – not explicitly revoked.
        // Only a record with isValid: false (written by invalidateTokenFamily) should deny.
        if (familyData === null) return true;
        return familyData.isValid !== false;
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
 * Validate a JWT token string and return the authenticated user.
 * Pure async function — no Express req/res dependency.
 * Used by both the Express middleware and WebSocket authentication.
 *
 * @param {string} token - Raw JWT string
 * @param {string} tokenType - 'access' or 'refresh'
 * @returns {Promise<object>} Decoded user with normalized roles
 * @throws {{ status: number, message: string }} on any auth failure
 */
const validateToken = async (token, tokenType = 'access') => {
    if (!token) {
        throw { status: 401, message: 'Unauthorized: Authentication required' };
    }

    const secret = tokenType === 'refresh'
        ? process.env.REFRESH_TOKEN_SECRET
        : process.env.ACCESS_TOKEN_SECRET;

    // Promisify jwt.verify
    const decoded = await new Promise((resolve, reject) => {
        jwt.verify(token, secret, (err, payload) => {
            if (err) reject(err);
            else resolve(payload);
        });
    }).catch(err => {
        throw { status: 403, message: 'Invalid or expired token', cause: err };
    });

    // Check required structure
    if (!decoded.id || !decoded.username || !decoded.email) {
        throw { status: 500, message: 'Server error during authentication' };
    }

    // Check blacklist (fail-open if cache is unavailable)
    try {
        const isBlacklisted = await cache.get(`auth:blacklist:${token}`);
        if (isBlacklisted) {
            throw { status: 401, message: 'Token has been revoked' };
        }
    } catch (err) {
        if (err.status) throw err; // re-throw our own errors
        logger.error(`${logger.safeColor(logger.colors.red)}[Auth]${logger.safeColor(logger.colors.reset)} Cache error during blacklist check:`, {
            message: err.message, error: err
        });
    }

    // Check user is still active
    const user = await User.findById(decoded.id).select('+active');
    if (!user) {
        throw { status: 401, message: 'User not found' };
    }
    if (user.active === false) {
        throw { status: 401, message: 'Account is deactivated' };
    }
    if (user.changedPasswordAfter && user.changedPasswordAfter(decoded.iat)) {
        throw { status: 401, message: 'Password changed. Please log in again.' };
    }

    return { ...decoded, roles: normalizeRoles(decoded.roles) };
};

/**
 * Express middleware to verify JWT tokens from cookies.
 * Wraps validateToken with req/res/next handling.
 * @param {string} tokenType - Type of token (access or refresh)
 * @returns {Function} - Express middleware
 */
const verifyToken = (tokenType = 'access') => async (req, res, next) => {
    const cookieName = tokenType === 'refresh' ? 'refreshToken' : 'accessToken';
    const token = req.cookies?.[cookieName];

    try {
        req.user = await validateToken(token, tokenType);
        next();
    } catch (err) {
        const status = err.status || 500;
        const message = err.message || 'Server error during authentication';

        if (status >= 500) {
            logger.error(`${logger.safeColor(logger.colors.red)}[Auth Middleware]${logger.safeColor(logger.colors.reset)} ${message}`, {
                tokenType, ip: req.ip, originalUrl: req.originalUrl, error: err.cause || err
            });
        } else {
            logger.warn(`${logger.safeColor(logger.colors.yellow)}[Auth Middleware]${logger.safeColor(logger.colors.reset)} ${message}`, {
                tokenType, ip: req.ip, originalUrl: req.originalUrl
            });
        }

        res.status(status).json({ success: false, message });
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
 * Authenticate a WebSocket upgrade request.
 * Extracts tokens from cookies or URL query params and validates directly
 * via validateToken — no Express middleware adapter needed.
 *
 * @param {WebSocket} ws - WebSocket connection
 * @param {Object} req - HTTP upgrade request
 * @returns {Promise<Object>} Authenticated user object
 */
const authenticateWebSocket = async (ws, req) => {
    try {
        // Parse cookies from the upgrade request
        const cookies = req.headers.cookie
            ? { ...cookie.parse(req.headers.cookie), ...cookieParserLib.JSONCookies(cookie.parse(req.headers.cookie)) }
            : {};

        // URL token fallback (for y-websocket params)
        const parsedUrl = parseUrl(req.url, true);
        const urlToken = parsedUrl.query.token;

        // Collect candidate tokens in priority order
        const candidates = [
            { token: cookies.accessToken, type: 'access', source: 'cookie' },
            { token: urlToken,            type: 'access', source: 'url' },
            { token: cookies.refreshToken, type: 'refresh', source: 'cookie' },
        ].filter(c => c.token);

        let lastError;
        for (const { token, type, source } of candidates) {
            try {
                const user = await validateToken(token, type);
                ws.user = user;
                logger.info(`🔌 Authenticated WebSocket connection for user ${user.username} (${user.id}) via ${source} ${type} token`);
                return user;
            } catch (err) {
                lastError = err;
            }
        }

        // All candidates exhausted
        const reason = lastError?.message || 'Authentication failed';
        logger.warn('WebSocket: Authentication failed - no valid tokens', {
            url: req.url,
            origin: req.headers.origin,
            hasCookies: !!req.headers.cookie,
            hasUrlToken: !!urlToken,
            userAgent: req.headers['user-agent']
        });
        ws.close(1008, reason);
        throw new Error(reason);
    } catch (error) {
        if (ws.readyState === ws.OPEN) {
            ws.close(1008, 'Authentication failed');
        }
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
    // Token config utilities – import these instead of re-implementing
    parseExpiryToMs,
    TOKEN_COOKIE_OPTIONS,
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
    res.cookie(CSRF_COOKIE_NAME, token, {
        ...TOKEN_COOKIE_OPTIONS,
        httpOnly: false, // Must be readable by JavaScript to include in header
        maxAge: CSRF_TOKEN_EXPIRY
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