const jwt = require('jsonwebtoken');
const User = require('../models/user.model');
const userMiddleware = require('../middleware/user.middleware');
const {asyncHandler} = require('../middleware/app.middleware');
const {AppError} = require('../middleware/error.middleware');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const {requiresOwnerApproval} = require('../config/rights');
const logger = require('../utils/app.logger');
const {cache} = require('../middleware/cache.middleware');
const {sanitizeObject} = require('../utils/sanitize');
const {sendEmail, getEmailTransporter} = require('./app.controller');

/**
 * Helper function to normalize user roles
 * @param {String|Array} roles - User roles
 * @returns {Array} - Normalized roles array
 */
const normalizeRoles = userMiddleware.normalizeRoles;

/**
 * Generate access and refresh tokens for a user
 * @param {Object} user - User object
 * @returns {Object} - Access and refresh tokens
 */
const generateTokens = (user) => {
    // Create a unique nonce to ensure tokens are always different
    const nonce = crypto.randomBytes(8).toString('hex');

    // Create a user data object with all necessary properties
    const userData = {
        id: user.id,
        username: user.username,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        roles: normalizeRoles(user.roles),
        nonce: nonce // Add nonce for uniqueness
    };

    const accessToken = jwt.sign(userData, process.env.ACCESS_TOKEN_SECRET, {expiresIn: process.env.ACCESS_TOKEN_EXPIRY});

    const refreshToken = jwt.sign({id: user.id, nonce: nonce}, // Add nonce to refresh token too
        process.env.REFRESH_TOKEN_SECRET, {expiresIn: process.env.REFRESH_TOKEN_EXPIRY});
    return {accessToken, refreshToken};
};

/**
 * Cache session token for tracking active sessions
 * @param {string} userId - User ID
 * @param {string} token - Access token
 * @param {number} expiry - Token expiry time in seconds
 */
const cacheUserSession = async (userId, token, expiry = 900) => {
    try {
        const sessionKey = `auth:session:${userId}:${token}`;
        await cache.set(sessionKey, {userId, createdAt: Date.now()}, expiry);
    } catch (error) {
        logger.error('Error caching user session:', error);
    }
};

/**
 * Cache user profile for quick access
 * @param {Object} user - User object
 * @param {number} duration - Cache duration in seconds
 */
const cacheUserProfile = async (user, duration = 3600) => {
    try {
        const profileKey = `user:profile:${user.id}`;
        await cache.set(profileKey, formatUserResponse(user), duration);
    } catch (error) {
        logger.error('Error caching user profile:', error);
    }
};

/**
 * Format user response without sensitive data
 * @param {Object} user - User object
 * @returns {Object} - Formatted user data
 */
const formatUserResponse = (user) => {
    // Handle active field - if it doesn't exist, default to true
    const active = user.active !== undefined ? user.active : true;

    return {
        id: user.id,
        firstName: user.firstName,
        lastName: user.lastName,
        username: user.username,
        email: user.email,
        roles: normalizeRoles(user.roles),
        createdAt: user.createdAt,
        emailVerified: user.emailVerified,
        twoFactorEnabled: user.twoFactorEnabled,
        profilePhoto: user.profilePhoto,
        active: active
    };
};

/**
 * Send password reset email
 * @param {Object} user - User object
 * @param {string} resetToken - Password reset token
 * @param {string} resetUrl - Password reset URL
 * @param {Object} [transporter] - Email transporter (passed from server)
 */
const sendPasswordResetEmail = async (user, resetToken, resetUrl, transporter = null) => {
    const expirationMinutes = 10; // Should match your token expiration

    return sendEmail({
        to: user.email, subject: 'Password Reset Request', template: 'password-reset', data: {
            firstName: user.firstName || user.name || 'User', resetUrl, expirationMinutes, email: user.email
        }
    }, transporter);
};

/**
 * Send welcome email to new users
 * @param {Object} user - User object
 * @param {Object} [transporter] - Email transporter (passed from server)
 */
const sendWelcomeEmail = async (user, transporter = null) => {
    return sendEmail({
        to: user.email, subject: 'Welcome to App Base!', template: 'welcome', data: {
            firstName: user.firstName || user.name || 'User',
            email: user.email,
            loginUrl: `${process.env.APP_URL || 'http://localhost:8080'}/auth/login`
        }
    }, transporter);
};

/**
 * Send password changed confirmation email
 * @param {Object} user - User object
 * @param {Object} [transporter] - Email transporter (passed from server)
 */
const sendPasswordChangedEmail = async (user, transporter = null) => {
    return sendEmail({
        to: user.email, subject: 'Password Changed Successfully', template: 'password-changed', data: {
            firstName: user.firstName || user.name || 'User', email: user.email, changeTime: new Date().toLocaleString()
        }
    }, transporter);
};

/**
 * Send security alert email
 * @param {Object} user - User object
 * @param {Object} alertData - Security alert data
 * @param {Object} [transporter] - Email transporter (passed from server)
 */
const sendSecurityAlertEmail = async (user, alertData, transporter = null) => {
    return sendEmail({
        to: user.email, subject: 'Security Alert - New Login Detected', template: 'security-alert', data: {
            firstName: user.firstName || user.name || 'User', email: user.email, ...alertData
        }
    }, transporter);
};

/**
 * Auth Controller
 * Handles authentication-related operations with Redis caching
 */
module.exports = {
    signup: asyncHandler(async (req, res, next) => {
        logger.info(`${logger.safeColor(logger.colors.cyan)}[Auth Controller]${logger.safeColor(logger.colors.reset)} Signup request received...`, {ip: req.ip});
        logger.verbose('[Auth Controller - Signup] Request headers:', {headers: req.headers});
        logger.verbose('[Auth Controller - Signup] Request body structure:', {bodyKeys: Object.keys(req.body || {})});

        // Early validation before the try block to catch invalid requests
        if (!req.body || typeof req.body !== 'object' || Object.keys(req.body).length === 0 || Object.values(req.body).every(x => x === null || x === undefined)) {
            logger.error(`${logger.safeColor(logger.colors.red)}[Auth Controller]${logger.safeColor(logger.colors.reset)} Signup error: Request body is missing or malformed`);
            logger.verbose('[Auth Controller - Signup] Invalid request body:', {body: req.body});
            return res.status(400).json({success: false, message: 'Request body is missing or malformed.'});
        }
        try {
            // Extract data directly from request body for user creation
            // Note: We don't sanitize here as we need actual password for hashing
            const {firstName, lastName, username, email, password, roles} = req.body;

            // Log sanitized version for security (without actual sensitive data)
            const sanitizedData = sanitizeObject(req.body);
            logger.info(`${logger.safeColor(logger.colors.cyan)}[Auth Controller]${logger.safeColor(logger.colors.reset)} Signup attempt`, {
                sanitizedData, ip: req.ip
            });
            logger.verbose('[Auth Controller - Signup] Processing signup for:', {
                email,
                username,
                firstName,
                lastName,
                roles
            });

            // Ensure all required fields are provided
            if (!firstName || !lastName || !username || !email || !password) {
                logger.warn(`${logger.safeColor(logger.colors.yellow)}[Auth Controller]${logger.safeColor(logger.colors.reset)} Signup: Missing required fields`);
                return res.status(400).json({success: false, message: 'All fields are required.'});
            }

            // Check if email already exists (better error handling)
            const existingEmail = await User.findOne({email});
            if (existingEmail) {
                logger.warn(`${logger.safeColor(logger.colors.yellow)}[Auth Controller]${logger.safeColor(logger.colors.reset)} Signup: Email already exists`, {email});
                return res.status(400).json({
                    success: false, message: 'Email already exists. Please use a different email address.'
                });
            }            // Check if username already exists
            const existingUsername = await User.findOne({username});
            if (existingUsername) {
                logger.warn(`${logger.safeColor(logger.colors.yellow)}[Auth Controller]${logger.safeColor(logger.colors.reset)} Signup: Username already exists`, {username});
                return res.status(400).json({
                    success: false, message: 'Username already exists. Please choose a different username.'
                });
            }

            // Hash the password (password validation already done by middleware)
            const hashedPassword = await bcrypt.hash(password, 12);

            // Process roles with approval logic
            const roleProcessing = userMiddleware.processRolesWithApproval(
                roles,
                req.user, // Current user if authenticated (for admin creation)
                null // Target user (will be the new user)
            );

            // Create a new user with processed roles
            const userData = {
                firstName,
                lastName,
                username,
                email,
                password: hashedPassword,
                roles: roleProcessing.assignedRoles,
                pendingRoles: roleProcessing.pendingRoles,
                roleApprovalStatus: roleProcessing.roleApprovalStatus
            };

            // Add role approval request if there is one
            if (roleProcessing.roleApprovalRequest) {
                userData.roleApprovalRequest = roleProcessing.roleApprovalRequest;
            }

            const user = new User(userData);

            // Update the approval request with the actual user ID after creation
            if (roleProcessing.roleApprovalStatus === 'PENDING' && !req.user) {
                user.roleApprovalRequest.requestedBy = user._id.toString();
            }            // Save the user to the database
            await user.save();

            // Clear users:list:all cache after creating new user
            await cache.del('users:list:all');

            // Clear pending requests cache if we just created a user with pending roles
            if (user.roleApprovalStatus === 'PENDING') {
                await cache.del('roles:pending');
            }

            logger.info(`${logger.safeColor(logger.colors.cyan)}[Auth Controller]${logger.safeColor(logger.colors.reset)} Signup: User created successfully`, {
                userId: user.id, username: user.username
            });            // Generate device fingerprint and add the initial device
            const deviceInfo = userMiddleware.generateDeviceFingerprint(req);
            try {
                await userMiddleware.addOrUpdateDevice(user, deviceInfo);
                logger.info(`[Auth Controller] Initial device registered for new user:`, {
                    userId: user.id,
                    deviceId: deviceInfo.deviceId,
                    browser: deviceInfo.browser,
                    os: deviceInfo.os,
                    platform: deviceInfo.platform
                });
            } catch (deviceError) {
                logger.warn('[Auth Controller] Failed to register initial device for new user:', {
                    message: deviceError.message, userId: user.id
                });
            }

            // Generate tokens for the newly created user
            const tokens = generateTokens(user);
            await cacheUserSession(user.id, tokens.accessToken); // Cache the user session
            await cacheUserProfile(user); // Cache the user profile

            // Send welcome email
            try {
                await sendWelcomeEmail(user, getEmailTransporter());
                logger.info(`[Auth Controller] Welcome email sent to new user: ${user.email}`);
            } catch (emailError) {
                logger.warn('[Auth Controller] Failed to send welcome email:', {
                    message: emailError.message, email: user.email, userId: user.id
                });
                // Continue with signup even if email fails
            }

            // Create response message based on role approval status
            let responseMessage = 'User created successfully';
            let additionalInfo = {};

            if (user.roleApprovalStatus === 'PENDING') {
                responseMessage = 'Your account has been created with USER role. Requested elevated roles are pending approval from an owner.';
                additionalInfo.roleApprovalStatus = 'PENDING';
                additionalInfo.pendingRoles = user.pendingRoles;
            } else if (user.roleApprovalStatus === 'APPROVED') {
                responseMessage = 'Account created with approved roles by owner.';
                additionalInfo.roleApprovalStatus = 'APPROVED';
            }

            res.status(201).json({
                success: true,
                message: responseMessage,
                authentication: {
                    accessToken: tokens.accessToken,
                    refreshToken: tokens.refreshToken
                },
                user: formatUserResponse(user),
                meta: {
                    deviceInfo: {
                        isNewDevice: true, 
                        deviceId: deviceInfo.deviceId
                    },
                    ...additionalInfo,
                    timestamp: new Date().toISOString()
                }
            });
        } catch (error) {
            if (error.code === 11000) {
                const field = Object.keys(error.keyPattern)[0];
                logger.warn(`[Auth Controller] Signup: Duplicate key error for field: ${field}`, {field, error});
                return res.status(400).json({
                    success: false, message: `${field} already exists. Please use a different ${field}.`
                });
            }
            if (error.name === 'ValidationError') {
                const errors = Object.values(error.errors).map(err => err.message);
                logger.warn('[Auth Controller] Signup: Validation error', {errors, error});
                return res.status(400).json({
                    success: false, message: `Validation error: ${errors.join(', ')}`
                });
            }
            logger.error(`${logger.safeColor(logger.colors.red)}[Auth Controller]${logger.safeColor(logger.colors.reset)} Signup error:`, {
                message: error.message, stack: error.stack, error
            });
            return next(error);
        }
    }),
    login: asyncHandler(async (req, res, next) => {
        logger.info(`${logger.safeColor(logger.colors.cyan)}[Auth Controller]${logger.safeColor(logger.colors.reset)} Login request received...`, {ip: req.ip});

        // Early validation before the try block to catch invalid requests
        if (!req.body || typeof req.body !== 'object' || Object.keys(req.body).length === 0 || Object.values(req.body).every(x => x === null || x === undefined)) {
            logger.error(`${logger.safeColor(logger.colors.red)}[Auth Controller]${logger.safeColor(logger.colors.reset)} Login error: Request body is missing or malformed`);
            return res.status(400).json({
                success: false, message: 'Request body is missing or malformed.'
            });
        }

        try {
            // Extract credentials directly from request body for authentication
            // Note: We don't sanitize here as we need the actual password for verification
            const {identifier, password, twoFactorToken} = req.body;

            // Log sanitized version for security (without actual sensitive data)
            const sanitizedData = sanitizeObject(req.body);
            logger.info(`${logger.safeColor(logger.colors.cyan)}[Auth Controller]${logger.safeColor(logger.colors.reset)} Login attempt`, {
                sanitizedData, ip: req.ip
            });

            // Find user by either email or username
            const user = await User.findOne({
                $or: [{email: identifier.toLowerCase()}, {username: identifier}]
            }).select('+password +active +twoFactorEnabled +twoFactorSecret +twoFactorBackupCodes');

            if (!user) {
                logger.warn(`${logger.safeColor(logger.colors.yellow)}[Auth Controller]${logger.safeColor(logger.colors.reset)} Login: User not found`, {identifier});
                return res.status(401).json({
                    success: false, message: 'Invalid credentials'
                });
            }

            // Check if the password is correct
            const isPasswordCorrect = await bcrypt.compare(password, user.password);
            if (!isPasswordCorrect) {
                logger.warn(`${logger.safeColor(logger.colors.yellow)}[Auth Controller]${logger.safeColor(logger.colors.reset)} Login: Invalid password`, {identifier});
                return res.status(401).json({
                    success: false, message: 'Invalid credentials'
                });
            }

            // Check if user is active
            if (user.active === false) {
                logger.warn(`${logger.safeColor(logger.colors.yellow)}[Auth Controller]${logger.safeColor(logger.colors.reset)} Login: Account deactivated`, {
                    userId: user.id, identifier
                });
                return res.status(401).json({
                    success: false, message: 'Account is deactivated'
                });
            }

            // Check 2FA if enabled
            if (user.twoFactorEnabled) {
                if (!twoFactorToken) {
                    logger.info('2FA required for login', {userId: user.id});
                    return res.status(200).json({
                        success: true,
                        requiresTwoFactor: true,
                        message: 'Two-factor authentication code required',
                        tempToken: jwt.sign(
                            {userId: user.id, step: '2fa_pending'},
                            process.env.ACCESS_TOKEN_SECRET,
                            {expiresIn: '5m'}
                        )
                    });
                }

                // Verify 2FA token
                const is2FAValid = await verify2FAToken(user.id, twoFactorToken);
                if (!is2FAValid) {
                    logger.warn('Invalid 2FA token provided', {userId: user.id});
                    return res.status(401).json({
                        success: false,
                        message: 'Invalid two-factor authentication code'
                    });
                }

                logger.info('2FA verification successful', {userId: user.id});
            }

            // Generate tokens
            const tokens = generateTokens(user);

            await cacheUserSession(user.id, tokens.accessToken); // Cache the user session
            await cacheUserProfile(user); // Cache the user profile

            // Track user device for login and send security alert for new devices
            try {
                const deviceInfo = userMiddleware.generateDeviceFingerprint(req);
                logger.verbose('[Auth Controller - Login] Generated device fingerprint:', {deviceInfo});

                // Check if this is a new device before adding it
                const isNewDevice = !user.knownDevices || !user.knownDevices.some(device =>
                    device.deviceFingerprint === deviceInfo.deviceFingerprint
                );

                logger.verbose('[Auth Controller - Login] Device analysis:', {
                    userId: user.id,
                    deviceId: deviceInfo.deviceId,
                    isNewDevice,
                    existingDevicesCount: user.knownDevices ? user.knownDevices.length : 0
                });

                // Send security alert email if this is a new device (but not during signup)
                if (isNewDevice) {
                    try {
                        await sendSecurityAlertEmail(user, {
                            deviceInfo: {
                                browser: deviceInfo.browser,
                                os: deviceInfo.os,
                                platform: deviceInfo.platform,
                                ipAddress: deviceInfo.ipAddress,
                                timestamp: new Date().toISOString()
                            },
                            loginTime: new Date().toISOString(),
                            ipAddress: deviceInfo.ipAddress
                        });
                        logger.verbose('[Auth Controller - Login] Security alert email sent for new device:', {
                            userId: user.id, deviceId: deviceInfo.deviceId, email: user.email
                        });
                    } catch (emailError) {
                        logger.warn('[Auth Controller - Login] Failed to send security alert email:', {
                            message: emailError.message, userId: user.id, email: user.email
                        });
                        // Don't fail login if email fails
                    }
                }

                await userMiddleware.addOrUpdateDevice(user, deviceInfo);
                logger.verbose('[Auth Controller - Login] Device tracking updated for user:', {
                    userId: user.id,
                    deviceId: deviceInfo.deviceId,
                    browser: deviceInfo.browser,
                    os: deviceInfo.os,
                    platform: deviceInfo.platform
                });
            } catch (deviceError) {
                logger.warn('[Auth Controller - Login] Failed to track device for user:', {
                    message: deviceError.message, userId: user.id
                });
                // Don't fail login if device tracking fails
            }

            logger.info(`${logger.safeColor(logger.colors.green)}[Auth Controller]${logger.safeColor(logger.colors.reset)} User logged in successfully`, {
                userId: user.id, username: user.username, twoFactorUsed: user.twoFactorEnabled
            });
            logger.verbose('[Auth Controller - Login] Login response being sent:', {
                success: true,
                message: 'Login successful',
                userId: user.id,
                hasAccessToken: !!tokens.accessToken,
                hasRefreshToken: !!tokens.refreshToken
            });

            res.status(200).json({
                success: true,
                message: 'Login successful',
                authentication: {
                    accessToken: tokens.accessToken,
                    refreshToken: tokens.refreshToken
                },
                user: formatUserResponse(user),
                meta: {
                    timestamp: new Date().toISOString()
                }
            });
        } catch (error) {
            logger.error(`${logger.safeColor(logger.colors.red)}[Auth Controller]${logger.safeColor(logger.colors.reset)} Login error:`, {
                message: error.message, stack: error.stack, error
            });
            return next(error);
        }
    }),

    refreshToken: asyncHandler(async (req, res, next) => {
        logger.info(`${logger.safeColor(logger.colors.cyan)}[Auth Controller]${logger.safeColor(logger.colors.reset)} Refresh token request received...`, {ip: req.ip});
        logger.verbose('[Auth Controller - Refresh Token] Request details:', {
            body: req.body ? Object.keys(req.body) : 'no body',
            ip: req.ip,
            userAgent: req.get('User-Agent')
        });

        try {
            const {token: refreshToken} = req.body;
            if (!refreshToken) {
                logger.warn(`${logger.safeColor(logger.colors.yellow)}[Auth Controller]${logger.safeColor(logger.colors.reset)} Refresh token: Token is required`);
                return res.status(401).json({
                    success: false, message: 'Refresh token is required'
                });
            }

            logger.verbose('[Auth Controller - Refresh Token] Verifying token:', {tokenLength: refreshToken?.length});

            // Verify the refresh token
            let decoded;
            try {
                decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
                logger.verbose('[Auth Controller - Refresh Token] Token decoded successfully:', {
                    userId: decoded.id,
                    nonce: decoded.nonce
                });
            } catch (err) {
                logger.warn(`${logger.safeColor(logger.colors.yellow)}[Auth Controller]${logger.safeColor(logger.colors.reset)} Invalid refresh token:`, {
                    message: err.message, error: err
                });
                if (err.name === 'TokenExpiredError') {
                    return res.status(403).json({
                        success: false, message: 'Refresh token expired'
                    });
                }
                return res.status(403).json({
                    success: false, message: 'Invalid refresh token'
                });
            }

            // Get updated user data for the new token
            const user = await User.findById(decoded.id).select('+active')
            if (!user) {
                logger.warn('[Auth Controller] Refresh token: User not found', {userId: decoded.id});
                return res.status(404).json({
                    success: false, message: 'User not found'
                });
            }

            logger.verbose('[Auth Controller - Refresh Token] User found:', {userId: user.id, active: user.active});

            // Check if user is still active
            if (user.active === false) {
                logger.warn('[Auth Controller] Refresh token: Account deactivated', {userId: user.id});
                return res.status(401).json({
                    success: false, message: 'Account is deactivated'
                });
            }

            // Generate new tokens with current user data
            const tokens = generateTokens(user);
            await cacheUserSession(user.id, tokens.accessToken); // Cache the new session

            // Track user device for token refresh
            try {
                const deviceInfo = userMiddleware.generateDeviceFingerprint(req);
                logger.verbose('[Auth Controller - Refresh Token] Generated device fingerprint:', {deviceInfo});
                await userMiddleware.addOrUpdateDevice(user, deviceInfo);
                logger.verbose('[Auth Controller - Refresh Token] Device tracking updated for user:', {
                    userId: user.id,
                    deviceId: deviceInfo.deviceId,
                    browser: deviceInfo.browser,
                    os: deviceInfo.os,
                    platform: deviceInfo.platform
                });
            } catch (deviceError) {
                logger.warn('[Auth Controller - Refresh Token] Failed to track device for user:', {
                    message: deviceError.message, userId: user.id
                });
                // Don't fail token refresh if device tracking fails
            }
            await cacheUserProfile(user); // Cache the user profile

            logger.info(`${logger.safeColor(logger.colors.green)}[Auth Controller]${logger.safeColor(logger.colors.reset)} Token refreshed successfully`, {userId: user.id});
            logger.verbose('[Auth Controller - Refresh Token] Success response being sent:', {
                success: true,
                message: 'Token refreshed successfully',
                userId: user.id,
                hasAccessToken: !!tokens.accessToken,
                hasRefreshToken: !!tokens.refreshToken
            });

            res.status(200).json({
                success: true,
                message: 'Token refreshed successfully',
                authentication: {
                    accessToken: tokens.accessToken,
                    refreshToken: tokens.refreshToken
                },
                user: formatUserResponse(user),
                meta: {
                    timestamp: new Date().toISOString()
                }
            });
        } catch (error) {
            logger.error(`${logger.safeColor(logger.colors.red)}[Auth Controller]${logger.safeColor(logger.colors.reset)} Refresh token error:`, {
                message: error.message, stack: error.stack, error
            });
            return next(error);
        }
    }),

    // Request password reset - sends reset token
    forgotPassword: asyncHandler(async (req, res, next) => {
        logger.info(`${logger.safeColor(logger.colors.cyan)}[Auth Controller]${logger.safeColor(logger.colors.reset)} Forgot password request received...`, {ip: req.ip});
        try {
            // Sanitize request data
            const sanitizedData = sanitizeObject(req.body);
            const {email} = sanitizedData;

            if (!email) {
                logger.warn(`${logger.safeColor(logger.colors.yellow)}[Auth Controller]${logger.safeColor(logger.colors.reset)} Forgot password: Email is required`);
                return res.status(400).json({success: false, message: 'Email is required'});
            }

            // Find user by email
            const user = await User.findOne({email});

            // Don't reveal if user exists or not for security
            if (!user) {
                logger.info(`[Auth Controller] Password reset requested for non-existent email: ${email}`);
                return res.status(200).json({
                    message: 'If a user with that email exists, a password reset link will be sent'
                });
            }

            // Generate a reset token and set expiry
            const resetToken = crypto.randomBytes(32).toString('hex');
            user.passwordResetToken = crypto
                .createHash('sha256')
                .update(resetToken)
                .digest('hex');

            // Token expires in 10 minutes
            user.passwordResetExpires = Date.now() + 10 * 60 * 1000;

            await user.save({validateBeforeSave: false});

            // Clear user profile cache after password reset token update
            await cache.invalidateUserCaches(user.id);

            const resetUrl = `${req.protocol}://${req.get('host')}/auth/reset-password/${resetToken}`;
            logger.info(`[Auth Controller] Password reset token generated for ${email}`, {userId: user.id, resetUrl});
            // Send password reset email
            try {
                await sendPasswordResetEmail(user, resetToken, resetUrl, getEmailTransporter());
                logger.info(`[Auth Controller] Password reset email sent successfully to ${email}`);
            } catch (emailError) {
                logger.error('[Auth Controller] Failed to send password reset email:', {
                    message: emailError.message, email, userId: user.id
                });
                // Continue with response even if email fails
            }

            res.status(200).json({
                success: true, 
                message: 'Password reset email sent',
                meta: {
                    timestamp: new Date().toISOString()
                }
            });
        } catch (error) {
            logger.error('[Auth Controller] Error in forgot password:', {
                message: error.message, stack: error.stack, error
            });
            return next(error);
        }
    }),

    // Reset password with token
    resetPassword: asyncHandler(async (req, res, next) => {
        logger.info(`${logger.safeColor(logger.colors.cyan)}[Auth Controller]${logger.safeColor(logger.colors.reset)} Reset password request received...`, {ip: req.ip});
        try {
            const {token} = req.params;
            // Extract password directly from request body for reset operation
            // Note: We don't sanitize here as we need the actual password for hashing
            const {password} = req.body;

            // Log sanitized version for security (without actual sensitive data)
            const sanitizedData = sanitizeObject(req.body);
            logger.info(`${logger.safeColor(logger.colors.cyan)}[Auth Controller]${logger.safeColor(logger.colors.reset)} Reset password attempt`, {
                sanitizedData, ip: req.ip
            });

            if (!token || !password) {
                logger.warn(`${logger.safeColor(logger.colors.yellow)}[Auth Controller]${logger.safeColor(logger.colors.reset)} Reset password: Token and new password are required`);
                return res.status(400).json({success: false, message: 'Token and new password are required'});
            }

            // Hash the token for comparison (same way it was stored)
            const hashedToken = crypto
                .createHash('sha256')
                .update(token)
                .digest('hex');

            // Find user with valid reset token and not expired
            const user = await User.findOne({
                passwordResetToken: hashedToken, passwordResetExpires: {$gt: Date.now()}
            });
            if (!user) {
                logger.error(`${logger.safeColor(logger.colors.red)}[Auth Controller]${logger.safeColor(logger.colors.reset)} Invalid or expired reset token`);
                return res.status(400).json({
                    success: false, message: 'Password reset token is invalid or has expired'
                });
            }

            // Set new password and clear reset token fields
            user.password = await bcrypt.hash(password, 12);
            user.passwordResetToken = undefined;
            user.passwordResetExpires = undefined;
            user.passwordChangedAt = Date.now();
            await user.save();

            // Clear user profile cache after password reset
            await cache.invalidateUserCaches(user.id);

            // Generate new tokens after password reset (optional)
            const tokens = generateTokens(user);
            await cacheUserSession(user.id, tokens.accessToken); // Cache new session
            await cacheUserProfile(user); // Cache updated profile
            // Send password changed confirmation email
            try {
                await sendPasswordChangedEmail(user, getEmailTransporter());
                logger.info(`[Auth Controller] Password changed confirmation email sent to ${user.email}`);
            } catch (emailError) {
                logger.error('[Auth Controller] Failed to send password changed confirmation email:', {
                    message: emailError.message, email: user.email, userId: user.id
                });
                // Continue with response even if email fails
            }

            logger.info(`${logger.safeColor(logger.colors.green)}[Auth Controller]${logger.safeColor(logger.colors.reset)} Password reset successful for ${user.email}`);
            res.status(200).json({
                success: true,
                message: 'Password has been reset successfully',
                authentication: {
                    accessToken: tokens.accessToken,
                    refreshToken: tokens.refreshToken
                },
                user: formatUserResponse(user),
                meta: {
                    timestamp: new Date().toISOString()
                }
            });
        } catch (error) {
            logger.error(`${logger.safeColor(logger.colors.red)}[Auth Controller]${logger.safeColor(logger.colors.reset)} Error in reset password:`, {
                message: error.message, stack: error.stack, error
            });
            return next(error);
        }
    }),

    // Logout user - blacklist token
    logout: asyncHandler(async (req, res, next) => {
        logger.info(`${logger.safeColor(logger.colors.cyan)}[Auth Controller]${logger.safeColor(logger.colors.reset)} Logout request received...`, {
            userId: req.user?.id, ip: req.ip
        });
        try {
            const authHeader = req.headers.authorization;
            if (authHeader && authHeader.startsWith('Bearer ')) {
                const token = authHeader.substring(7);

                // Add token to blacklist with remaining TTL
                const decoded = jwt.decode(token);
                if (decoded && decoded.exp) {
                    const remainingTtl = decoded.exp - Math.floor(Date.now() / 1000);
                    if (remainingTtl > 0) {
                        await cache.set(`auth:blacklist:${token}`, true, remainingTtl);
                        logger.info(`Token blacklisted for user ${req.user.id}`);
                    }
                }

                // Clear user session cache
                const sessionPattern = `auth:session:${req.user.id}:*`;
                await cache.delPattern(sessionPattern);

                // Clear user profile cache
                await cache.del(`user:profile:${req.user.id}`);
            }

            logger.info(`${logger.safeColor(logger.colors.green)}[Auth Controller]${logger.safeColor(logger.colors.reset)} User logged out successfully`, {userId: req.user?.id});
            res.status(200).json({
                success: true,
                message: 'Logged out successfully',
                meta: {
                    timestamp: new Date().toISOString()
                }
            });
        } catch (error) {
            logger.error(`${logger.safeColor(logger.colors.red)}[Auth Controller]${logger.safeColor(logger.colors.reset)} Logout error:`, {
                message: error.message, stack: error.stack, error
            });
            return next(error);
        }
    }),

    // Get user devices
    getUserDevices: asyncHandler(async (req, res, next) => {
        logger.info(`${logger.safeColor(logger.colors.cyan)}[Auth Controller]${logger.safeColor(logger.colors.reset)} Get user devices request received...`, {userId: req.user.id});
        try {
            // Find user and get their devices
            const user = await User.findById(req.user.id);
            if (!user) {
                logger.warn('[Auth Controller] User not found for devices request', {userId: req.user.id});
                return res.status(404).json({
                    success: false, message: 'User not found'
                });
            }            // Get device summary using user middleware
            const devices = userMiddleware.getDeviceSummary(user);

            logger.info(`[Auth Controller] Retrieved ${devices.length} devices for user`, {userId: req.user.id});
            res.status(200).json({
                success: true,
                message: 'User devices retrieved successfully',
                devices: devices,
                totalDevices: devices.length
            });
        } catch (error) {
            logger.error(`${logger.safeColor(logger.colors.red)}[Auth Controller]${logger.safeColor(logger.colors.reset)} Get user devices error:`, {
                message: error.message, stack: error.stack, error, userId: req.user.id
            });
            return next(error);
        }
    }),

    // =============================================================================
    // 2FA CONTROLLER FUNCTIONS
    // =============================================================================

    setup2FA: asyncHandler(async (req, res) => {
        const userId = req.user.id;

        logger.info('2FA setup initiated', {userId});

        const user = await User.findById(userId);
        if (!user) {
            throw new AppError('User not found', 404);
        }

        if (user.twoFactorEnabled) {
            throw new AppError('Two-factor authentication is already enabled', 400);
        }

        // Generate a secret for the user
        const secret = speakeasy.generateSecret({
            name: `${process.env.APP_NAME || 'App Base'} (${user.email})`,
            issuer: process.env.APP_NAME || 'App Base',
            length: 32
        });

        // Store the temporary secret in cache (not in database until verified)
        await cache.set(`auth:2fa:temp_secret:${userId}`, secret.base32, 600); // 10 minutes

        // Generate QR code
        const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

        logger.info('2FA setup QR code generated', {userId});

        res.status(200).json({
            success: true,
            message: '2FA setup initiated. Please scan the QR code with your authenticator app.',
            qrCode: qrCodeUrl,
            manualEntryKey: secret.base32,
            backupCodes: null, // Will be provided after verification
            meta: {
                timestamp: new Date().toISOString()
            }
        });
    }),

    verify2FASetup: asyncHandler(async (req, res) => {
        const {token} = req.body;
        const userId = req.user.id;

        if (!token) {
            throw new AppError('TOTP token is required', 400);
        }

        logger.info('2FA setup verification attempted', {userId});

        const user = await User.findById(userId);
        if (!user) {
            throw new AppError('User not found', 404);
        }

        if (user.twoFactorEnabled) {
            throw new AppError('Two-factor authentication is already enabled', 400);
        }

        // Get the temporary secret from cache
        const tempSecret = await cache.get(`auth:2fa:temp_secret:${userId}`);
        if (!tempSecret) {
            throw new AppError('2FA setup session expired. Please start setup again.', 400);
        }

        // Verify the token
        const verified = speakeasy.totp.verify({
            secret: tempSecret,
            encoding: 'base32',
            token: token,
            window: 2 // Allow some time drift
        });

        if (!verified) {
            throw new AppError('Invalid TOTP token', 400);
        }

        // Generate backup codes
        const backupCodes = generateBackupCodes();
        const hashedBackupCodes = backupCodes.map(code =>
            crypto.createHash('sha256').update(code).digest('hex')
        );

        // Save to database
        user.twoFactorEnabled = true;
        user.twoFactorSecret = tempSecret;
        user.twoFactorBackupCodes = hashedBackupCodes;
        await user.save();

        // Clean up temporary secret
        await cache.del(`auth:2fa:temp_secret:${userId}`);

        // Clear user profile cache
        await cache.del(`user:profile:${userId}`);

        logger.info('2FA setup completed successfully', {userId});

        res.status(200).json({
            success: true,
            message: '2FA has been successfully enabled for your account.',
            backupCodes: backupCodes,
            meta: {
                timestamp: new Date().toISOString()
            }
        });
    }),

    disable2FA: asyncHandler(async (req, res) => {
        const {password, token} = req.body;
        const userId = req.user.id;

        if (!password) {
            throw new AppError('Password is required to disable 2FA', 400);
        }

        if (!token) {
            throw new AppError('2FA token is required to disable 2FA', 400);
        }

        logger.info('2FA disable attempted', {userId});

        const user = await User.findById(userId).select('+password +twoFactorSecret +twoFactorBackupCodes');
        if (!user) {
            throw new AppError('User not found', 404);
        }

        if (!user.twoFactorEnabled) {
            throw new AppError('Two-factor authentication is not enabled', 400);
        }

        // Verify password
        const isPasswordCorrect = await user.correctPassword(password, user.password);
        if (!isPasswordCorrect) {
            throw new AppError('Incorrect password', 401);
        }

        // Verify 2FA token
        const is2FAValid = await verify2FAToken(userId, token);
        if (!is2FAValid) {
            throw new AppError('Invalid 2FA token', 401);
        }

        // Disable 2FA
        user.twoFactorEnabled = false;
        user.twoFactorSecret = undefined;
        user.twoFactorBackupCodes = undefined;
        await user.save();

        // Clear user profile cache
        await cache.del(`user:profile:${userId}`);

        logger.info('2FA disabled successfully', {userId});

        res.status(200).json({
            success: true,
            message: 'Two-factor authentication has been disabled for your account.',
            meta: {
                timestamp: new Date().toISOString()
            }
        });
    }),

    get2FAStatus: asyncHandler(async (req, res) => {
        const userId = req.user.id;

        const user = await User.findById(userId).select('+twoFactorBackupCodes');
        if (!user) {
            throw new AppError('User not found', 404);
        }

        res.status(200).json({
            success: true,
            message: '2FA status retrieved successfully',
            twoFactorEnabled: user.twoFactorEnabled || false,
            backupCodesRemaining: user.twoFactorBackupCodes ? user.twoFactorBackupCodes.length : 0,
            meta: {
                timestamp: new Date().toISOString()
            }
        });
    }),

    generateNewBackupCodes: asyncHandler(async (req, res) => {
        const {password, token} = req.body;
        const userId = req.user.id;

        if (!password || !token) {
            throw new AppError('Password and 2FA token are required', 400);
        }

        logger.info('New backup codes generation attempted', {userId});

        const user = await User.findById(userId).select('+password +twoFactorSecret +twoFactorBackupCodes');
        if (!user) {
            throw new AppError('User not found', 404);
        }

        if (!user.twoFactorEnabled) {
            throw new AppError('Two-factor authentication is not enabled', 400);
        }

        // Verify password
        const isPasswordCorrect = await user.correctPassword(password, user.password);
        if (!isPasswordCorrect) {
            throw new AppError('Incorrect password', 401);
        }

        // Verify 2FA token
        const is2FAValid = await verify2FAToken(userId, token);
        if (!is2FAValid) {
            throw new AppError('Invalid 2FA token', 401);
        }

        // Generate new backup codes
        const backupCodes = generateBackupCodes();
        const hashedBackupCodes = backupCodes.map(code =>
            crypto.createHash('sha256').update(code).digest('hex')
        );

        user.twoFactorBackupCodes = hashedBackupCodes;
        await user.save();

        logger.info('New backup codes generated successfully', {userId});

        res.status(200).json({
            success: true,
            message: 'New backup codes have been generated. Please store them securely.',
            backupCodes: backupCodes,
            meta: {
                timestamp: new Date().toISOString()
            }
        });
    }),

    // =============================================================================
    // EMAIL VERIFICATION FUNCTIONS
    // =============================================================================

    sendVerificationEmail: asyncHandler(async (req, res) => {
        const userId = req.user.id;
        const {email} = req.body;

        logger.info('Email verification requested', {userId, email});
        logger.verbose('[Auth Controller - Email Verification] Request details:', {
            userId,
            email,
            requestBody: req.body,
            ip: req.ip
        });

        const user = await User.findById(userId);
        if (!user) {
            logger.error('[Auth Controller - Email Verification] User not found:', {userId});
            throw new AppError('User not found', 404);
        }

        // Check rate limiting - only allow one email per 5 minutes
        const rateLimitKey = `auth:rate_limit:email_verify:${userId}`;
        const lastSent = await cache.get(rateLimitKey);
        logger.verbose('[Auth Controller - Email Verification] Rate limit check:', {
            rateLimitKey,
            lastSent,
            hasRateLimit: !!lastSent
        });

        if (lastSent) {
            logger.warn('[Auth Controller - Email Verification] Rate limit exceeded:', {userId, lastSent});
            throw new AppError('Please wait before requesting another verification email', 429);
        }

        // Set rate limit first to prevent race conditions
        await cache.set(rateLimitKey, Date.now(), 300); // 5 minutes
        logger.verbose('[Auth Controller - Email Verification] Rate limit set for user:', {userId, rateLimitKey});

        // If email is provided and different from current, validate it first
        let targetEmail = user.email;
        if (email && email !== user.email) {
            // Check if new email is already in use
            const existingUser = await User.findOne({email: email.toLowerCase()});
            if (existingUser) {
                throw new AppError('Email address is already in use', 400);
            }
            targetEmail = email.toLowerCase();
        }

        // Check if user is already verified for their current email
        if (!email && user.emailVerified) {
            return res.status(200).json({
                success: true,
                message: 'Email is already verified',
                meta: {
                    timestamp: new Date().toISOString()
                }
            });
        }

        // Set rate limit
        await cache.set(rateLimitKey, Date.now(), 300); // 5 minutes

        // Generate verification token
        const verificationToken = user.createEmailVerificationToken();

        // If changing email, store the new email temporarily
        if (email && email !== user.email) {
            user.pendingEmail = targetEmail;
        }

        await user.save({validateBeforeSave: false});

        // Create verification URL
        const verificationUrl = `${process.env.APP_URL || 'http://localhost:8080'}/verify-email/${verificationToken}`;

        try {
            // Send verification email
            await sendEmail({
                to: targetEmail,
                subject: `Verify your email address - ${process.env.APP_NAME || 'App Base'}`,
                template: 'email-verification',
                data: {
                    userName: user.firstName || user.username,
                    verificationUrl: verificationUrl,
                    appName: process.env.APP_NAME || 'App Base',
                    supportEmail: process.env.EMAIL_FROM || 'support@example.com'
                }
            }, getEmailTransporter());

            logger.info('Verification email sent successfully', {userId, email: targetEmail});

            res.status(200).json({
                success: true,
                message: `Verification email sent to ${targetEmail}. Please check your inbox and click the verification link.`,
                meta: {
                    timestamp: new Date().toISOString()
                }
            });
        } catch (emailError) {
            // Reset the verification token if email failed
            user.emailVerificationToken = undefined;
            user.emailVerificationExpires = undefined;
            user.pendingEmail = undefined;
            await user.save({validateBeforeSave: false});

            logger.error('Failed to send verification email:', {userId, error: emailError.message});
            throw new AppError('Failed to send verification email. Please try again later.', 500);
        }
    }),

    verifyEmail: asyncHandler(async (req, res) => {
        const {token} = req.params;

        if (!token) {
            throw new AppError('Verification token is required', 400);
        }

        logger.info('Email verification attempted', {token: token});

        // Hash the token to compare with stored hash
        const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

        // Find user with this token that hasn't expired
        const user = await User.findOne({
            emailVerificationToken: hashedToken,
            emailVerificationExpires: {$gt: Date.now()}
        });

        if (!user) {
            throw new AppError('Invalid or expired verification token', 400);
        }

        // Check if user is changing email
        if (user.pendingEmail) {
            // Update to new email
            user.email = user.pendingEmail;
            user.pendingEmail = undefined;
        }

        // Mark email as verified and clear token
        user.emailVerified = true;
        user.emailVerificationToken = undefined;
        user.emailVerificationExpires = undefined;
        await user.save();

        // Clear user profile cache
        await cache.del(`user:profile:${user.id}`);

        logger.info('Email verification successful', {userId: user.id, email: user.email});

        res.status(200).json({
            success: true,
            message: 'Email verified successfully! You can now access all features of your account.',
            meta: {
                timestamp: new Date().toISOString()
            }
        });
    }),

    // =============================================================================
    // ROLE MANAGEMENT FUNCTIONS
    // =============================================================================

    approveRoleRequest: asyncHandler(async (req, res) => {
        const {userId} = req.params;
        const {reason} = req.body;
        const approverUserId = req.user.id;

        logger.info('Role approval request received', {userId, approverUserId, reason});
        logger.verbose('[Auth Controller - Role Approval] Request details:', {
            userId,
            approverUserId,
            reason,
            ip: req.ip
        });

        // Find the user whose role needs approval
        const user = await User.findById(userId);
        if (!user) {
            logger.error('[Auth Controller - Role Approval] User not found:', {userId});
            throw new AppError('User not found', 404);
        }

        // Check if user has pending role request
        if (user.roleApprovalStatus !== 'PENDING') {
            logger.warn('[Auth Controller - Role Approval] No pending role request:', {
                userId,
                currentStatus: user.roleApprovalStatus
            });
            throw new AppError('No pending role request found for this user', 400);
        }

        // Approve the roles
        if (user.pendingRoles && user.pendingRoles.length > 0) {
            // Merge pending roles with existing roles (remove duplicates)
            const currentRoles = normalizeRoles(user.roles);
            const pendingRoles = normalizeRoles(user.pendingRoles);
            const mergedRoles = [...new Set([...currentRoles, ...pendingRoles])];

            user.roles = mergedRoles;
            user.pendingRoles = [];
        }

        // Update approval status
        user.roleApprovalStatus = 'APPROVED';
        user.roleApprovalRequest = {
            ...user.roleApprovalRequest,
            approvedBy: approverUserId.toString(),
            approvedAt: new Date(),
            reason: reason || 'Role request approved by owner'
        };

        await user.save();

        // Clear user caches
        await cache.del(`user:profile:${userId}`);
        await cache.del('users:list:all');
        // Clear pending requests cache since we just approved/removed a request
        await cache.del('roles:pending');

        logger.info('[Auth Controller - Role Approval] Role request approved successfully:', {
            userId,
            approvedBy: approverUserId,
            approvedRoles: user.roles,
            reason
        });

        res.status(200).json({
            success: true,
            message: 'Role request approved successfully',
            user: formatUserResponse(user)
        });
    }),

    rejectRoleRequest: asyncHandler(async (req, res) => {
        const {userId} = req.params;
        const {reason} = req.body;
        const rejecterUserId = req.user.id;

        logger.info('Role rejection request received', {userId, rejecterUserId, reason});
        logger.verbose('[Auth Controller - Role Rejection] Request details:', {
            userId,
            rejecterUserId,
            reason,
            ip: req.ip
        });

        // Find the user whose role needs rejection
        const user = await User.findById(userId);
        if (!user) {
            logger.error('[Auth Controller - Role Rejection] User not found:', {userId});
            throw new AppError('User not found', 404);
        }

        // Check if user has pending role request
        if (user.roleApprovalStatus !== 'PENDING') {
            logger.warn('[Auth Controller - Role Rejection] No pending role request:', {
                userId,
                currentStatus: user.roleApprovalStatus
            });
            throw new AppError('No pending role request found for this user', 400);
        }

        // Reject the roles
        user.pendingRoles = [];
        user.roleApprovalStatus = 'REJECTED';
        user.roleApprovalRequest = {
            ...user.roleApprovalRequest,
            rejectedBy: rejecterUserId.toString(),
            rejectedAt: new Date(),
            reason: reason || 'Role request rejected by owner'
        };

        await user.save();

        // Clear user caches
        await cache.del(`user:profile:${userId}`);
        await cache.del('users:list:all');
        // Clear pending requests cache since we just rejected/removed a request
        await cache.del('roles:pending');

        logger.info('[Auth Controller - Role Rejection] Role request rejected successfully:', {
            userId,
            rejectedBy: rejecterUserId,
            rejectedRoles: user.pendingRoles,
            reason
        });

        res.status(200).json({
            success: true,
            message: 'Role request rejected successfully',
            user: formatUserResponse(user)
        });
    }),

    requestRoleElevation: asyncHandler(async (req, res) => {
        const {roles, reason} = req.body;
        const requesterId = req.user.id;

        logger.info('Role elevation request received', {requesterId, roles, reason});
        logger.verbose('[Auth Controller - Role Elevation] Request details:', {
            requesterId,
            roles,
            reason,
            ip: req.ip
        });

        if (!roles || !Array.isArray(roles) || roles.length === 0) {
            logger.warn('[Auth Controller - Role Elevation] Invalid roles provided:', {roles});
            throw new AppError('Please provide valid roles to request', 400);
        }

        // Find the requesting user
        const user = await User.findById(requesterId);
        if (!user) {
            logger.error('[Auth Controller - Role Elevation] User not found:', {requesterId});
            throw new AppError('User not found', 404);
        }

        // Check if user already has a pending request
        if (user.roleApprovalStatus === 'PENDING') {
            logger.warn('[Auth Controller - Role Elevation] User already has pending request:', {requesterId});
            throw new AppError('You already have a pending role request. Please wait for approval or contact an owner.', 400);
        }

        // Validate that the requested roles require owner approval
        const normalizedRoles = normalizeRoles(roles);
        const elevatedRoles = normalizedRoles.filter(role => requiresOwnerApproval(role));

        if (elevatedRoles.length === 0) {
            logger.warn('[Auth Controller - Role Elevation] No elevated roles requested:', {
                requesterId,
                roles: normalizedRoles
            });
            throw new AppError('No elevated roles were requested. Regular user role assignment does not require approval.', 400);
        }

        // Check if user already has all requested roles
        const currentRoles = normalizeRoles(user.roles);
        const newRoles = elevatedRoles.filter(role => !currentRoles.includes(role));

        if (newRoles.length === 0) {
            logger.warn('[Auth Controller - Role Elevation] User already has all requested roles:', {
                requesterId,
                currentRoles,
                requestedRoles: elevatedRoles
            });
            throw new AppError('You already have all the requested roles.', 400);
        }

        // Set up role approval request
        user.pendingRoles = newRoles;
        user.roleApprovalStatus = 'PENDING';
        user.roleApprovalRequest = {
            requestedRoles: newRoles,
            requestedBy: requesterId.toString(),
            requestedAt: new Date(),
            reason: reason || 'Role elevation requested by user'
        };

        await user.save();

        // Clear user caches
        await cache.del(`user:profile:${requesterId}`);
        await cache.del('users:list:all');
        // Clear pending requests cache since we just added a new request
        await cache.del('roles:pending');

        logger.info('[Auth Controller - Role Elevation] Role elevation request submitted successfully:', {
            requesterId,
            requestedRoles: newRoles,
            reason
        });

        res.status(200).json({
            success: true,
            message: 'Role elevation request submitted successfully. Please wait for owner approval.',
            pendingRoles: newRoles,
            roleApprovalStatus: 'PENDING'
        });
    }),

    getPendingRoleRequests: asyncHandler(async (req, res) => {
        const requesterId = req.user.id;

        logger.info('Get pending role requests', {requesterId});
        logger.verbose('[Auth Controller - Get Pending Requests] Request details:', {
            requesterId,
            ip: req.ip
        });

        // Find all users with pending role requests
        const usersWithPendingRequests = await User.find({
            roleApprovalStatus: 'PENDING'
        }).select('firstName lastName username email roles pendingRoles roleApprovalRequest roleApprovalStatus');

        logger.info('[Auth Controller - Get Pending Requests] Found pending requests:', {
            requesterId,
            count: usersWithPendingRequests.length
        });

        const pendingRequests = usersWithPendingRequests.map(user => ({
            id: user.id,
            firstName: user.firstName,
            lastName: user.lastName,
            username: user.username,
            email: user.email,
            currentRoles: normalizeRoles(user.roles),
            pendingRoles: normalizeRoles(user.pendingRoles),
            roleApprovalRequest: user.roleApprovalRequest,
            roleApprovalStatus: user.roleApprovalStatus
        }));

        res.status(200).json({
            success: true,
            message: 'Pending role requests retrieved successfully',
            pendingRequests: pendingRequests,
            totalCount: pendingRequests.length
        });
    })
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Generate backup codes for 2FA recovery
 */
const generateBackupCodes = () => {
    const codes = [];
    for (let i = 0; i < 10; i++) {
        codes.push(crypto.randomBytes(4).toString('hex').toUpperCase());
    }
    return codes;
};

/**
 * Verify 2FA token during login
 */
const verify2FAToken = async (userId, token) => {
    try {
        const user = await User.findById(userId).select('+twoFactorSecret +twoFactorBackupCodes');

        if (!user || !user.twoFactorEnabled || !user.twoFactorSecret) {
            return false;
        }

        // First try TOTP verification
        const totpVerified = speakeasy.totp.verify({
            secret: user.twoFactorSecret,
            encoding: 'base32',
            token: token,
            window: 2
        });

        if (totpVerified) {
            logger.info('2FA TOTP verification successful', {userId});
            return true;
        }

        // If TOTP fails, try backup codes
        if (user.twoFactorBackupCodes && user.twoFactorBackupCodes.length > 0) {
            const hashedToken = crypto.createHash('sha256').update(token.toUpperCase()).digest('hex');
            const backupCodeIndex = user.twoFactorBackupCodes.indexOf(hashedToken);

            if (backupCodeIndex !== -1) {
                // Remove used backup code
                user.twoFactorBackupCodes.splice(backupCodeIndex, 1);
                await user.save();

                logger.info('2FA backup code verification successful', {
                    userId,
                    remainingBackupCodes: user.twoFactorBackupCodes.length
                });
                return true;
            }
        }

        return false;
    } catch (error) {
        logger.error('2FA token verification error:', {userId, error: error.message});
        return false;
    }
};
