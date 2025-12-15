import {Router} from 'express';
import authController from '../controllers/auth.controller.js';
import * as authMiddleware from '../middleware/auth.middleware.js';
import {validateRequest} from '../middleware/validation.middleware.js';
import {
    authSchemas,
    twoFactorSchemas,
    emailVerificationSchemas
} from '../models/schemas.js';
import {ROLES, RIGHTS} from '../config/rights.js';
import {
    clearCache,
    cacheResponse,
    autoInvalidateCache
} from '../middleware/cache.middleware.js';

const router = Router();

// Define auth routes for validation
router.validRoutes = [
    '/api/v1/auth/signup',
    '/api/v1/auth/login',
    '/api/v1/auth/refresh-token',
    '/api/v1/auth/ws-token',
    '/api/v1/auth/logout',
    '/api/v1/auth/me',
    '/api/v1/auth/devices',
    '/api/v1/auth/forgot-password',
    '/api/v1/auth/reset-password/:token',
    '/api/v1/auth/socket-token',
    '/api/v1/auth/csrf-token',  // CSRF token endpoint
    // Two-Factor Authentication
    '/api/v1/auth/2fa/setup',
    '/api/v1/auth/2fa/verify-setup',
    '/api/v1/auth/2fa/disable',
    '/api/v1/auth/2fa/status',
    '/api/v1/auth/2fa/backup-codes',
    // Email Verification
    '/api/v1/auth/send-verification-email',
    '/api/v1/auth/verify-email/:token',
    // Role Management
    '/api/v1/auth/roles/approve/:userId',
    '/api/v1/auth/roles/reject/:userId',
    '/api/v1/auth/roles/request-elevation',
    '/api/v1/auth/roles/pending-requests'
];

// =============================================================================
// CSRF Token Endpoint - Get a fresh CSRF token
// =============================================================================
router.get('/csrf-token', authMiddleware.getCsrfToken);

router.post('/signup',
    validateRequest(authSchemas.signup),
    authMiddleware.optionalAuth(), // Allow optional authentication for owner-created accounts
    clearCache(['users:list:all']),
    autoInvalidateCache('user', (req) => 'new_user'),
    authController.signup);

router.post('/login',
    validateRequest(authSchemas.login),
    authController.login);

router.post('/refresh-token',
    validateRequest(authSchemas.refreshToken),
    authController.refreshToken);

// WebSocket token endpoint for cross-origin authentication
router.get('/ws-token',
    authMiddleware.verifyToken(),
    authController.getWebSocketToken);

router.post('/logout',
    validateRequest(authSchemas.logout),
    authMiddleware.verifyToken(),
    clearCache(['users:online']),
    authController.logout);

// Add a route to get user profile with caching
router.get('/me',
    authMiddleware.verifyToken(),
    cacheResponse(1800, (req) => `user:profile:${req.user.id}`), // Cache for 30 minutes
    (req, res) => {
        // Use formatUserResponse for consistent response structure
        // Format user response directly (internal formatting logic)
        const formattedUser = {
            user: {
                id: req.user.id,
                firstName: req.user.firstName,
                lastName: req.user.lastName,
                username: req.user.username,
                email: req.user.email,
                roles: req.user.roles,
                createdAt: req.user.createdAt,
                emailVerified: req.user.emailVerified,
                twoFactorEnabled: req.user.twoFactorEnabled,
                profilePhoto: req.user.profilePhoto,
                active: req.user.active !== undefined ? req.user.active : true
            }
        };
        res.status(200).json({
            success: true,
            message: 'User profile retrieved successfully',
            user: formattedUser.user,
            meta: {
                timestamp: new Date().toISOString()
            }
        });
    }
);

// Get user devices
router.get('/devices',
    authMiddleware.verifyToken(),
    authController.getUserDevices
);

// Password reset routes
router.post('/forgot-password',
    validateRequest(authSchemas.forgotPassword),
    authController.forgotPassword
);

router.post('/reset-password/:token',
    validateRequest(authSchemas.resetPassword),
    authController.resetPassword
);

// =============================================================================
// Two-Factor Authentication Routes
// =============================================================================
router.post('/2fa/setup',
    authMiddleware.verifyToken(),
    authController.setup2FA
);

router.post('/2fa/verify-setup',
    authMiddleware.verifyToken(),
    validateRequest(twoFactorSchemas.verifySetup),
    authController.verify2FASetup
);

router.post('/2fa/disable',
    authMiddleware.verifyToken(),
    validateRequest(twoFactorSchemas.disable2FA),
    authController.disable2FA
);

router.get('/2fa/status',
    authMiddleware.verifyToken(),
    authController.get2FAStatus
);

router.post('/2fa/backup-codes',
    authMiddleware.verifyToken(),
    validateRequest(twoFactorSchemas.generateBackupCodes),
    authController.generateNewBackupCodes
);

// =============================================================================
// Email Verification Routes
// =============================================================================
router.post('/send-verification-email',
    authMiddleware.verifyToken(),
    validateRequest(emailVerificationSchemas.sendVerification),
    authController.sendVerificationEmail
);

router.get('/verify-email/:token',
    validateRequest(emailVerificationSchemas.verifyEmail, 'params'),
    authController.verifyEmail
);

// =============================================================================
// Role Management Routes (Owner Only)
// =============================================================================

// Approve role request
router.post('/roles/approve/:userId',
    authMiddleware.verifyToken(),
    authMiddleware.checkRole(ROLES.OWNER),
    clearCache(['users:list:all']),
    autoInvalidateCache('user', (req) => req.params.userId),
    authController.approveRoleRequest
);

// Reject role request
router.post('/roles/reject/:userId',
    authMiddleware.verifyToken(),
    authMiddleware.checkRole(ROLES.OWNER),
    clearCache(['users:list:all']),
    autoInvalidateCache('user', (req) => req.params.userId),
    authController.rejectRoleRequest
);

// Request role elevation
router.post('/roles/request-elevation',
    authMiddleware.verifyToken(),
    clearCache(['users:list:all']),
    autoInvalidateCache('user', (req) => req.user.id),
    authController.requestRoleElevation
);

// Get pending role requests (Owner only)
router.get('/roles/pending-requests',
    authMiddleware.verifyToken(),
    authMiddleware.checkRole(ROLES.OWNER),
    cacheResponse(300, () => 'roles:pending'), // Cache for 5 minutes
    authController.getPendingRoleRequests
);

export default router;
