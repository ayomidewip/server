const mongoose = require('mongoose');
const User = require('../models/user.model');
const {AppError} = require('./error.middleware');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const {asyncHandler} = require('./app.middleware');
const {
    hasRight,
    RIGHTS,
    ROLES,
    canAssignRole,
    getElevatedRoles,
    isOwner
} = require('../config/rights');
const logger = require('../utils/app.logger'); // Added logger

/**
 * Helper function to normalize user roles
 * @param {String|Array} roles - User roles
 * @returns {Array} - Normalized roles array
 */
const normalizeRoles = (roles) => {
    // If roles is null, undefined, or empty, return default role
    if (!roles || (Array.isArray(roles) && roles.length === 0)) {
        return [ROLES.USER]; // Default role
    }

    // If roles is an array, filter out invalid roles
    if (Array.isArray(roles)) {
        const validRoles = roles.filter(role => typeof role === 'string' && Object.values(ROLES).includes(role));

        // If there are no valid roles after filtering, use default
        return validRoles.length > 0 ? validRoles : [ROLES.USER];
    }

    // If roles is a string and valid, return it as a single-item array
    if (typeof roles === 'string' && Object.values(ROLES).includes(roles)) {
        return [roles];
    }

    // Default fallback
    return [ROLES.USER];
};

/**
 * Process roles with approval logic
 * @param {Array} requestedRoles - Roles requested for user
 * @param {Object} currentUser - Current user making the request (for role assignment)
 * @param {Object} targetUser - User receiving the roles (for approval tracking)
 * @returns {Object} - Object containing assignedRoles, pendingRoles, and approval status
 */
const processRolesWithApproval = (requestedRoles, currentUser = null, targetUser = null) => {
    const normalizedRoles = normalizeRoles(requestedRoles);
    const elevatedRoles = getElevatedRoles(normalizedRoles);

    // If no elevated roles requested, assign directly
    if (elevatedRoles.length === 0) {
        return {
            assignedRoles: [ROLES.USER],
            pendingRoles: [],
            roleApprovalStatus: 'NONE',
            roleApprovalRequest: null
        };
    }

    // If current user is owner, they can assign any roles directly
    if (currentUser && isOwner(currentUser.roles)) {
        const userId = currentUser.id ? currentUser.id.toString() : currentUser._id ? currentUser._id.toString() : 'unknown';
        return {
            assignedRoles: normalizedRoles,
            pendingRoles: [],
            roleApprovalStatus: 'APPROVED',
            roleApprovalRequest: {
                requestedRoles: elevatedRoles,
                requestedBy: userId,
                requestedAt: new Date(),
                approvedBy: userId,
                approvedAt: new Date(),
                reason: 'Auto-approved by owner'
            }
        };
    }

    // Otherwise, elevated roles need approval
    return {
        assignedRoles: [ROLES.USER], // Start with basic user role
        pendingRoles: elevatedRoles,
        roleApprovalStatus: 'PENDING',
        roleApprovalRequest: {
            requestedRoles: elevatedRoles,
            requestedBy: currentUser ?
                (currentUser.id ? currentUser.id.toString() : currentUser._id ? currentUser._id.toString() : null) :
                (targetUser ?
                    (targetUser.id ? targetUser.id.toString() : targetUser._id ? targetUser._id.toString() : null) :
                    null),
            requestedAt: new Date(),
            reason: currentUser ? 'Role assignment by authorized user' : 'Self-requested during registration'
        }
    };
};

/**
 * Middleware to check if a user exists
 */
exports.checkUserExists = asyncHandler(async (req, res, next) => {
    if (!req.params.id) {
        logger.warn(`${logger.safeColor(logger.colors.yellow)}[User Middleware]${logger.safeColor(logger.colors.reset)} User ID is required for checkUserExists middleware`, {originalUrl: req.originalUrl});
        return next(new AppError('User ID is required', 400));
    }

    logger.info(`${logger.safeColor(logger.colors.cyan)}[User Middleware]${logger.safeColor(logger.colors.reset)} Checking if user exists: ${req.params.id}`);

    try {
        const user = await User.findById(req.params.id).select('-password -resetPasswordToken -refreshTokens +active');
        if (!user) {
            logger.warn(`${logger.safeColor(logger.colors.yellow)}[User Middleware]${logger.safeColor(logger.colors.reset)} User not found: ${req.params.id}`, {originalUrl: req.originalUrl});
            return res.status(404).json({
                success: false, message: 'User not found'
            });
        }
        req.targetUser = user; // Store user for later middleware
        next();
    } catch (error) {
        if (error.name === 'CastError') {
            logger.warn(`${logger.safeColor(logger.colors.yellow)}[User Middleware]${logger.safeColor(logger.colors.reset)} Invalid user ID format: ${req.params.id}`, {
                error, originalUrl: req.originalUrl
            });
            return res.status(400).json({
                success: false, message: 'Invalid user ID format'
            });
        }
        logger.error(`${logger.safeColor(logger.colors.red)}[User Middleware]${logger.safeColor(logger.colors.reset)} Error in checkUserExists middleware`, {
            message: error.message, stack: error.stack, userId: req.params.id
        });
        next(error);
    }
});

/**
 * Middleware to check if user has the right to access/modify this resource
 */
exports.checkResourceOwnership = asyncHandler(async (req, res, next) => {
    logger.info(`${logger.safeColor(logger.colors.cyan)}[User Middleware]${logger.safeColor(logger.colors.reset)} Checking resource ownership: ${req.params.id}, requestor: ${req.user.id}`);
    if (hasRight(req.user.roles, RIGHTS.MANAGE_ALL_USERS)) {
        logger.info(`${logger.safeColor(logger.colors.cyan)}[User Middleware]${logger.safeColor(logger.colors.reset)} Overriding Resource ownership for Admin User: ${req.params.id}`);
        return next();
    }    // Regular users can only access their own profile
    if (req.user.id === req.params.id) {
        logger.info(`${logger.safeColor(logger.colors.cyan)}[User Middleware]${logger.safeColor(logger.colors.reset)} User is accessing their own profile`);
        return next();
    }    // Access denied for other users' profiles
    logger.warn(`${logger.safeColor(logger.colors.yellow)}[User Middleware]${logger.safeColor(logger.colors.reset)} Access denied - user ${req.user.id} cannot access ${req.params.id}`);
    return res.status(403).json({
        success: false, message: 'Access denied: You do not have permission to access this resource'
    });
});

/**
 * Middleware to check if user has delete permission
 * Only OWNER (with DELETE_USERS permission) can delete other users
 * Any user can delete their own account
 */
exports.checkDeletePermission = asyncHandler(async (req, res, next) => {
    logger.info(`${logger.safeColor(logger.colors.cyan)}[User Middleware]${logger.safeColor(logger.colors.reset)} Checking delete permission: ${req.params.id}, requester: ${req.user.id}`);

    // Users can delete their own account
    if (req.user.id === req.params.id) {
        logger.info(`${logger.safeColor(logger.colors.cyan)}[User Middleware]${logger.safeColor(logger.colors.reset)} User ${req.user.id} is deleting their own account.`);
        return next();
    }

    // Check if the user has the DELETE_USERS permission
    if (hasRight(req.user.roles, RIGHTS.DELETE_USERS)) {
        logger.info(`${logger.safeColor(logger.colors.cyan)}[User Middleware]${logger.safeColor(logger.colors.reset)} User ${req.user.id} has permission to delete user ${req.params.id}.`);
        return next();
    }

    // If none of the above, deny access
    logger.warn(`${logger.safeColor(logger.colors.yellow)}[User Middleware]${logger.safeColor(logger.colors.reset)} Access denied - user ${req.user.id} cannot delete user ${req.params.id}.`);
    return res.status(403).json({
        success: false, message: 'Access denied: You do not have permission to delete this user'
    });
});

/**
 * Middleware to check for duplicate username or email
 */
exports.checkDuplicateUsernameOrEmail = asyncHandler(async (req, res, next) => {
    const {username, email} = req.body;
    const currentUserId = req.params.id; // User ID being updated (if any)

    logger.info(`${logger.safeColor(logger.colors.cyan)}[User Middleware]${logger.safeColor(logger.colors.reset)} Checking for Duplicate Email or Username: ${currentUserId}`);

    // Check for existing username (exclude current user during updates)
    if (username) {
        const query = {username};
        if (currentUserId) {
            query._id = {$ne: currentUserId};
        }

        const existingUsername = await User.findOne(query);
        if (existingUsername) {
            logger.warn(`Username already exists: ${existingUsername.username} (ID: ${existingUsername._id})`);
            return res.status(400).json({
                success: false, message: 'Username already exists'
            });
        }
    }

    // Check for existing email (exclude current user during updates)
    if (email) {
        const query = {email};
        if (currentUserId) {
            query._id = {$ne: currentUserId};
        }

        const existingEmail = await User.findOne(query);
        if (existingEmail) {
            logger.warn(`Email already exists: ${existingEmail.email} (ID: ${existingEmail._id})`);
            return res.status(400).json({
                success: false, message: 'Email already exists'
            });
        }
    }

    next();
});

/**
 * Middleware to validate roles and enforce role hierarchy
 */
exports.checkRoles = () => {
    return (req, res, next) => {
        const {roles} = req.body;

        // If roles not provided, default will be set in controller
        if (!roles) {
            return next();
        }

        // Ensure roles is an array for further processing
        let rolesArray;

        if (Array.isArray(roles)) {
            rolesArray = roles;
        } else if (typeof roles === 'string') {
            rolesArray = [roles];
        } else {
            logger.warn('Roles must be provided as a string or an array of strings', {originalUrl: req.originalUrl});
            return res.status(400).json({
                success: false,
                message: 'Roles must be provided as a string or an array of strings',
                validRoles: Object.values(ROLES)
            });
        }

        // Check if any invalid roles were submitted
        const invalidRoles = rolesArray.filter(role => !Object.values(ROLES).includes(role));
        if (invalidRoles.length > 0) {
            logger.warn(`Invalid roles provided: ${invalidRoles.join(', ')}`, {originalUrl: req.originalUrl});
            return res.status(400).json({
                success: false,
                message: `Invalid roles provided: ${invalidRoles.join(', ')}`,
                validRoles: Object.values(ROLES)
            });
        }        // Role hierarchy enforcement: Check if the current user can assign the requested roles
        if (req.user && req.user.roles) {
            const unauthorizedRoles = rolesArray.filter(role => !canAssignRole(req.user.roles, role));

            if (unauthorizedRoles.length > 0) {
                logger.warn(`${logger.safeColor(logger.colors.yellow)}[User Middleware]${logger.safeColor(logger.colors.reset)} User ${req.user.id} cannot assign roles: ${unauthorizedRoles.join(', ')}. User roles: ${JSON.stringify(req.user.roles)}`);

                // For updates to their own profile, remove unauthorized roles instead of blocking
                if (req.params.id && req.user.id === req.params.id) {
                    logger.info(`${logger.safeColor(logger.colors.cyan)}[User Middleware]${logger.safeColor(logger.colors.reset)} User updating own profile - removing unauthorized roles from request`);
                    // Remove roles field entirely to let controller handle it
                    delete req.body.roles;
                    return next();
                }

                // For user creation (POST), allow the controller to handle role approval workflow
                if (req.method === 'POST' && req.originalUrl && req.originalUrl.endsWith('/users')) {
                    logger.info(`${logger.safeColor(logger.colors.cyan)}[User Middleware]${logger.safeColor(logger.colors.reset)} User creating new user with unauthorized roles - letting controller handle role approval workflow`);
                    // Mark the request for role approval processing
                    req.roleApprovalRequired = true;
                    req.unauthorizedRoles = unauthorizedRoles;
                    return next();
                }

                // For other operations (like updating other users), block the request
                return res.status(403).json({
                    success: false,
                    message: `Access denied: You cannot assign roles higher than or equal to your own level: ${unauthorizedRoles.join(', ')}`
                });
            }
        }

        // Normalize and validate roles
        const normalizedRoles = normalizeRoles(rolesArray);
        req.body.roles = normalizedRoles;

        logger.info(`${logger.safeColor(logger.colors.cyan)}[User Middleware]${logger.safeColor(logger.colors.reset)} Roles validated: ${req.body.roles}`);
        next();
    };
};

/**
 * Middleware to hash password
 */
exports.hashPassword = asyncHandler(async (req, res, next) => {
    logger.info(`${logger.safeColor(logger.colors.cyan)}[User Middleware]${logger.safeColor(logger.colors.reset)} Hashing Password`);

    // Hash newPassword for password change operations
    if (req.body.newPassword) {
        const salt = await bcrypt.genSalt(12);
        req.body.password = await bcrypt.hash(req.body.newPassword, salt);
    }
    // Hash password for user creation/update operations
    else if (req.body.password) {
        const salt = await bcrypt.genSalt(12);
        req.body.password = await bcrypt.hash(req.body.password, salt);
    }

    next();
});

/**
 * Middleware to normalize role field to roles array
 * Converts singular 'role' field to 'roles' array for consistency
 */
exports.normalizeRoleField = (req, res, next) => {
    // If 'role' is provided but not 'roles', convert it
    if (req.body.role && !req.body.roles) {
        req.body.roles = Array.isArray(req.body.role) ? req.body.role : [req.body.role];
        delete req.body.role;
        logger.info(`${logger.safeColor(logger.colors.cyan)}[User Middleware]${logger.safeColor(logger.colors.reset)} Normalized 'role' field to 'roles' array: ${JSON.stringify(req.body.roles)}`);
    }
    next();
};

// Export the normalizeRoles function for use in other modules
exports.normalizeRoles = normalizeRoles;

/**
 * Process roles with approval logic
 */
exports.processRolesWithApproval = processRolesWithApproval;

/**
 * Middleware to check if user can assign roles during user creation
 * Only owners can assign roles above USER
 */
exports.checkRoleAssignmentPermission = asyncHandler(async (req, res, next) => {
    const {roles} = req.body;

    // If no roles specified or only USER role, allow
    if (!roles || (Array.isArray(roles) && roles.length === 0) ||
        (Array.isArray(roles) && roles.every(role => role === ROLES.USER))) {
        return next();
    }

    // If single role and it's USER, allow
    if (typeof roles === 'string' && roles === ROLES.USER) {
        return next();
    }

    // Check if user is authenticated and is owner
    if (!req.user) {
        logger.warn('[User Middleware] Attempted role assignment without authentication');
        return res.status(401).json({
            success: false,
            message: 'Authentication required to assign elevated roles'
        });
    }

    // Check if user has owner role
    if (!isOwner(req.user.roles)) {
        logger.warn('[User Middleware] Non-owner attempted role assignment:', {
            userId: req.user.id,
            userRoles: req.user.roles,
            requestedRoles: roles
        });
        return res.status(403).json({
            success: false,
            message: 'Only owners can assign roles above USER level during account creation'
        });
    }

    logger.info('[User Middleware] Owner authorized to assign roles:', {
        ownerId: req.user.id,
        requestedRoles: roles
    });

    next();
});

/**
 * Device detection and tracking functions
 * Handles device fingerprinting and recognition for security purposes
 */

/**
 * Generate a device fingerprint based on request headers and client info
 * @param {Object} req - Express request object
 * @returns {Object} Device information
 */
exports.generateDeviceFingerprint = (req) => {
    try {
        const userAgent = req.headers['user-agent'] || '';
        const acceptLanguage = req.headers['accept-language'] || '';
        const acceptEncoding = req.headers['accept-encoding'] || '';
        const xForwardedFor = req.headers['x-forwarded-for'] || '';
        const ipAddress = exports.getClientIP(req);

        // Parse user agent for more detailed info
        const deviceInfo = exports.parseUserAgent(userAgent);

        // Create a unique fingerprint based on multiple factors
        const fingerprintData = {
            userAgent: userAgent.substring(0, 200), // Limit length
            acceptLanguage: acceptLanguage.substring(0, 100),
            acceptEncoding: acceptEncoding.substring(0, 100),
            browser: deviceInfo.browser,
            os: deviceInfo.os,
            platform: deviceInfo.platform
        };

        // Generate a hash for the fingerprint
        const fingerprintString = JSON.stringify(fingerprintData);
        const deviceFingerprint = crypto
            .createHash('sha256')
            .update(fingerprintString)
            .digest('hex')
            .substring(0, 32); // Use first 32 characters

        // Generate a shorter device ID for easier reference
        const deviceId = crypto
            .createHash('md5')
            .update(fingerprintString + Date.now())
            .digest('hex')
            .substring(0, 16);

        return {
            deviceId, deviceFingerprint, userAgent: userAgent.substring(0, 500), // Store limited user agent
            browser: deviceInfo.browser, os: deviceInfo.os, platform: deviceInfo.platform, ipAddress, ...deviceInfo
        };
    } catch (error) {
        logger.error('[User Middleware - Device] Error generating device fingerprint:', {
            message: error.message, error
        });

        // Return a basic fingerprint in case of error
        return {
            deviceId: exports.generateFallbackDeviceId(req),
            deviceFingerprint: exports.generateFallbackFingerprint(req),
            userAgent: req.headers['user-agent'] || 'Unknown',
            browser: 'Unknown',
            os: 'Unknown',
            platform: 'Unknown',
            ipAddress: exports.getClientIP(req)
        };
    }
};

/**
 * Parse user agent string to extract browser, OS, and platform info
 * @param {string} userAgent - User agent string
 * @returns {Object} Parsed device information
 */
exports.parseUserAgent = (userAgent) => {
    if (!userAgent) {
        return {
            browser: 'Unknown', os: 'Unknown', platform: 'Unknown'
        };
    }

    const ua = userAgent.toLowerCase();

    // Detect browser
    let browser = 'Unknown';
    if (ua.includes('chrome') && !ua.includes('edg')) {
        browser = 'Chrome';
    } else if (ua.includes('firefox')) {
        browser = 'Firefox';
    } else if (ua.includes('safari') && !ua.includes('chrome')) {
        browser = 'Safari';
    } else if (ua.includes('edg')) {
        browser = 'Edge';
    } else if (ua.includes('opera') || ua.includes('opr')) {
        browser = 'Opera';
    } else if (ua.includes('msie') || ua.includes('trident')) {
        browser = 'Internet Explorer';
    }

    // Detect platform first as it helps with OS detection
    let platform = 'Unknown';

    // Specifically check for iPad - higher priority than mobile check
    if (ua.includes('ipad')) {
        platform = 'Tablet';
    }
    // Then check for other tablets
    else if (ua.includes('tablet') || (ua.includes('android') && !ua.includes('mobile')) || (ua.includes('silk/')) || (ua.includes('kindle'))) {
        platform = 'Tablet';
    }
    // Then check for mobile devices
    else if (ua.includes('mobile') || ua.includes('iphone') || ua.includes('ipod')) {
        platform = 'Mobile';
    }
    // Default to desktop for everything else
    else {
        platform = 'Desktop';
    }

    // Detect operating system
    let os = 'Unknown';

    // iOS devices (check for iPad specifically for iOS)
    if (ua.includes('iphone') || ua.includes('ipad') || ua.includes('ipod') || (ua.includes('mac os') && (platform === 'Mobile' || platform === 'Tablet'))) {
        os = 'iOS';
    }
    // Android (specifically check that it's not a Linux desktop)
    else if (ua.includes('android')) {
        os = 'Android';
    }
    // Windows
    else if (ua.includes('windows')) {
        os = 'Windows';
    }
    // macOS (desktop Macs)
    else if (ua.includes('macintosh') || (ua.includes('mac os') && platform === 'Desktop')) {
        os = 'macOS';
    }    // Linux (ensure it's not Android)
    else if (ua.includes('linux') && !ua.includes('android')) {
        os = 'Linux';
    }

    return {browser, os, platform};
};

/**
 * Get client IP address from request
 * @param {Object} req - Express request object
 * @returns {string} Client IP address
 */
exports.getClientIP = (req) => {
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) {
        return forwarded.split(',')[0].trim();
    }
    return req.connection?.remoteAddress || req.socket?.remoteAddress || req.ip || 'Unknown';
};

/**
 * Check if a device is recognized for a user
 * @param {Object} user - User object
 * @param {string} deviceFingerprint - Device fingerprint to check
 * @returns {Object} Recognition result
 */
exports.isDeviceRecognized = (user, deviceFingerprint) => {
    if (!user.knownDevices || !Array.isArray(user.knownDevices)) {
        return {
            isRecognized: false, device: null, isNewDevice: true
        };
    }

    const recognizedDevice = user.knownDevices.find(device => device.isActive && device.deviceFingerprint === deviceFingerprint);

    return {
        isRecognized: !!recognizedDevice, device: recognizedDevice || null, isNewDevice: !recognizedDevice
    };
};

/**
 * Add or update a device for a user with retry mechanism for concurrency conflicts
 * @param {Object} user - User object
 * @param {Object} deviceInfo - Device information
 * @returns {Object} Updated user object
 */
exports.addOrUpdateDevice = async (user, deviceInfo) => {
    const maxRetries = 3;
    let attempts = 0;

    while (attempts < maxRetries) {
        try {
            // Reload the user to get the latest version
            const currentUser = await User.findById(user._id || user.id);
            if (!currentUser) {
                throw new Error(`User ${user._id || user.id} not found`);
            }

            if (!currentUser.knownDevices) {
                currentUser.knownDevices = [];
            }

            // Check if device already exists
            const existingDeviceIndex = currentUser.knownDevices.findIndex(device => device.deviceFingerprint === deviceInfo.deviceFingerprint);

            if (existingDeviceIndex >= 0) {
                // Update existing device
                currentUser.knownDevices[existingDeviceIndex].lastSeenAt = new Date();
                currentUser.knownDevices[existingDeviceIndex].ipAddress = deviceInfo.ipAddress;
                currentUser.knownDevices[existingDeviceIndex].isActive = true;

            } else {
                // Add new device
                const newDevice = {
                    deviceId: deviceInfo.deviceId,
                    deviceFingerprint: deviceInfo.deviceFingerprint,
                    userAgent: deviceInfo.userAgent,
                    browser: deviceInfo.browser,
                    os: deviceInfo.os,
                    platform: deviceInfo.platform,
                    ipAddress: deviceInfo.ipAddress,
                    firstSeenAt: new Date(),
                    lastSeenAt: new Date(),
                    isActive: true
                };

                currentUser.knownDevices.push(newDevice);

                logger.info('[User Middleware - Device] Added new device for user:', {
                    userId: currentUser.id,
                    deviceId: newDevice.deviceId,
                    browser: newDevice.browser,
                    os: newDevice.os,
                    platform: newDevice.platform
                });
            }

            // Limit the number of stored devices (keep last 20)
            if (currentUser.knownDevices.length > 20) {
                currentUser.knownDevices.sort((a, b) => new Date(b.lastSeenAt) - new Date(a.lastSeenAt));
                currentUser.knownDevices = currentUser.knownDevices.slice(0, 20);
            }

            // Save with retry mechanism
            await currentUser.save();

            // Invalidate user caches after device update
            const {cache} = require('./cache.middleware');
            await cache.invalidateUserCaches(currentUser.id);

            return currentUser;

        } catch (error) {
            attempts++;

            // Check if it's a version error (optimistic concurrency control failure)
            const isVersionError = error.name === 'VersionError' ||
                error.message.includes('No matching document found') ||
                error.message.includes('version') ||
                error.code === 11000; // Duplicate key error can also happen

            if (isVersionError && attempts < maxRetries) {
                logger.warn(`[User Middleware - Device] Version conflict detected (attempt ${attempts}/${maxRetries}), retrying...`, {
                    userId: user._id || user.id,
                    error: error.message,
                    attempt: attempts
                });

                // Wait a bit before retrying (exponential backoff)
                await new Promise(resolve => setTimeout(resolve, Math.pow(2, attempts - 1) * 10));
                continue;
            }

            logger.error('[User Middleware - Device] Error adding/updating device:', {
                message: error.message,
                userId: user._id || user.id,
                attempts,
                error
            });

            // If it's not a version error or we've exhausted retries, throw the error
            throw error;
        }
    }

    throw new Error(`Failed to update device after ${maxRetries} attempts due to concurrency conflicts`);
};

/**
 * Generate fallback device ID when main fingerprinting fails
 * @param {Object} req - Express request object
 * @returns {string} Fallback device ID
 */
exports.generateFallbackDeviceId = (req) => {
    const userAgent = req.headers['user-agent'] || 'unknown';
    const ip = exports.getClientIP(req);
    const timestamp = Date.now();

    return crypto
        .createHash('md5')
        .update(`${userAgent}${ip}${timestamp}`)
        .digest('hex')
        .substring(0, 16);
};

/**
 * Generate fallback fingerprint when main fingerprinting fails
 * @param {Object} req - Express request object
 * @returns {string} Fallback fingerprint
 */
exports.generateFallbackFingerprint = (req) => {
    const userAgent = req.headers['user-agent'] || 'unknown';
    const ip = exports.getClientIP(req);

    return crypto
        .createHash('sha256')
        .update(`${userAgent}${ip}`)
        .digest('hex')
        .substring(0, 32);
};

/**
 * Remove inactive devices for a user
 * @param {Object} user - User object
 * @param {number} inactiveDays - Days after which to consider device inactive
 * @returns {Object} Updated user object
 */
exports.removeInactiveDevices = async (user, inactiveDays = 90) => {
    try {
        if (!user.knownDevices || !Array.isArray(user.knownDevices)) {
            return user;
        }

        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - inactiveDays);

        const activeDevices = user.knownDevices.filter(device => device.lastSeenAt && new Date(device.lastSeenAt) > cutoffDate);

        if (activeDevices.length !== user.knownDevices.length) {
            const removedCount = user.knownDevices.length - activeDevices.length;
            user.knownDevices = activeDevices;
            await user.save();

            // Invalidate user caches after device cleanup
            const {cache} = require('./cache.middleware');
            await cache.invalidateUserCaches(user.id);

            logger.info('[User Middleware - Device] Removed inactive devices:', {
                userId: user.id, removedCount, remainingDevices: activeDevices.length
            });
        }

        return user;
    } catch (error) {
        logger.error('[User Middleware - Device] Error removing inactive devices:', {
            message: error.message, userId: user.id, error
        });
        return user;
    }
};

/**
 * Get device summary information for a user
 * @param {Object} user - User object
 * @returns {Array} Array of device summaries
 */
exports.getDeviceSummary = (user) => {
    if (!user.knownDevices || !Array.isArray(user.knownDevices)) {
        return [];
    }

    return user.knownDevices
        .filter(device => device.isActive)
        .map(device => ({
            deviceId: device.deviceId,
            browser: device.browser,
            os: device.os,
            platform: device.platform,
            ipAddress: device.ipAddress,
            firstSeenAt: device.firstSeenAt,
            lastSeenAt: device.lastSeenAt,
            location: device.location || null
        }))
        .sort((a, b) => new Date(b.lastSeenAt) - new Date(a.lastSeenAt));
};

/**
 * User Statistics Middleware Functions
 */

/**
 * Parse time period for statistics queries
 * @param {String} period - Period string like 30d, 12h, 2w, 6m, 1y
 * @returns {Object} - Start date for the period
 */
exports.parseTimePeriod = (period) => {
    if (!period) return {startDate: null};

    const now = new Date();
    const value = parseInt(period.slice(0, -1));
    const unit = period.slice(-1);

    let startDate = new Date(now);

    switch (unit) {
        case 'h':
            startDate.setHours(now.getHours() - value);
            break;
        case 'd':
            startDate.setDate(now.getDate() - value);
            break;
        case 'w':
            startDate.setDate(now.getDate() - (value * 7));
            break;
        case 'm':
            startDate.setMonth(now.getMonth() - value);
            break;
        case 'y':
            startDate.setFullYear(now.getFullYear() - value);
            break;
        default:
            startDate = null;
    }

    return {startDate};
};

/**
 * Prepare user statistics filters
 * Converts query parameters to MongoDB query filters
 */
exports.prepareUserStatsFilters = asyncHandler(async (req, res, next) => {
    const Log = require('../models/log.model');
    const mongoose = require('mongoose');

    try {
        // Initialize filters object
        req.statsFilters = {};
        req.statsOptions = {
            sort: {},
            pagination: {page: 1, limit: 20}
        };

        // Process time-based filters
        if (req.query.startDate) {
            req.statsFilters.createdAt = {$gte: new Date(req.query.startDate)};
        }

        if (req.query.endDate) {
            req.statsFilters.createdAt = {
                ...req.statsFilters.createdAt,
                $lte: new Date(req.query.endDate)
            };
        }

        if (req.query.period) {
            const {startDate} = exports.parseTimePeriod(req.query.period);
            if (startDate) {
                req.statsFilters.createdAt = {
                    ...req.statsFilters.createdAt,
                    $gte: startDate
                };
            }
        }

        // Process user filters
        if (req.query.active !== undefined) {
            req.statsFilters.active = req.query.active === 'true';
        }

        if (req.query.roles) {
            const roles = req.query.roles.split(',').map(r => r.trim());
            req.statsFilters.roles = {$in: roles};
        }

        // Process pagination
        if (req.query.page) {
            req.statsOptions.pagination.page = parseInt(req.query.page);
        }

        if (req.query.limit) {
            req.statsOptions.pagination.limit = parseInt(req.query.limit);
            req.statsOptions.pagination.limit = Math.min(req.statsOptions.pagination.limit, 100);
        }

        req.statsOptions.pagination.skip = (req.statsOptions.pagination.page - 1) * req.statsOptions.pagination.limit;

        // Process sorting
        if (req.query.sortBy) {
            const sortOrder = req.query.sortOrder === 'desc' ? -1 : 1;
            req.statsOptions.sort[req.query.sortBy] = sortOrder;
        } else {
            req.statsOptions.sort.createdAt = -1; // Default sorting
        }

        next();
    } catch (error) {
        logger.error('Error preparing user stats filters:', error);
        return next(error);
    }
});
