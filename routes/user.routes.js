const router = require('express').Router();
const userController = require('../controllers/user.controller');
const userMiddleware = require('../middleware/user.middleware');
const authMiddleware = require('../middleware/auth.middleware');
const {validateRequest} = require('../middleware/validation.middleware');
const {userSchemas, fileSchemas, statsSchemas} = require('../models/schemas');
const {RIGHTS} = require('../config/rights');
const {cacheResponse, clearCache, autoInvalidateCache} = require('../middleware/cache.middleware');

// Define user routes for validation
router.validRoutes = [
    '/api/v1/users',
    '/api/v1/users/public',
    '/api/v1/users/stats/overview',
    '/api/v1/users/:id',
    '/api/v1/users/:id/password',
    '/api/v1/users/:id/files',
    '/api/v1/users/:id/stats',
    '/api/v1/users/:id/stats/fields'
];

/**
 * Get Public Users (limited info):
 * Route Definition: GET /api/v1/users/public
 * Permission: Any authenticated user
 * Returns: firstName, lastName, username, email, roles only
 */
router.get('/public',
    authMiddleware.verifyToken(),
    cacheResponse(1800, (req) => {
        const params = req.query ? new URLSearchParams(req.query).toString() : '';
        return `users:public:${params ? Buffer.from(params).toString('base64') : 'all'}`;
    }), // Cache for 30 minutes
    userController.getPublicUsers
);

// Ensure all routes are authenticated first
router.use(authMiddleware.verifyToken());

// ADMIN-ONLY ROUTES (require MANAGE_ALL_USERS permission)

/**
 * Get All Users:
 * Route Definition:
 * Permission: Super Admin, Admin
 */
router.get('/',
    authMiddleware.checkPermission(RIGHTS.MANAGE_ALL_USERS),
    cacheResponse(1800, (req) => {
        const params = req.query ? new URLSearchParams(req.query).toString() : '';
        return `users:list:${params ? Buffer.from(params).toString('base64') : 'all'}`;
    }), // Cache for 30 minutes with query params
    userController.getAllUsers
);

/**
 * Get User Overview Stats:
 * Route Definition:
 * Permission: Super Admin, Admin
 */
router.get('/stats/overview',
    authMiddleware.checkPermission(RIGHTS.MANAGE_ALL_USERS),
    validateRequest(statsSchemas.userStats, 'query'),
    userMiddleware.prepareUserStatsFilters,
    cacheResponse(300, (req) => {
        const params = req.query ? new URLSearchParams(req.query).toString() : '';
        return `users:stats:overview:${params ? Buffer.from(params).toString('base64') : 'all'}`;
    }), // Cache for 5 minutes
    userController.getUsersOverviewStats
);

/**
 * Create New User
 * Route definition:
 * Permissions: Super Admin, Admin only; Users use Auth routes
 */
router.post('/',
    authMiddleware.checkPermission(RIGHTS.MANAGE_ALL_USERS),
    userMiddleware.normalizeRoleField,
    userMiddleware.checkRoles(),
    validateRequest(userSchemas.createUser),
    userMiddleware.checkDuplicateUsernameOrEmail,
    userMiddleware.hashPassword,
    clearCache(['users:list:*', 'users:stats:*']),
    autoInvalidateCache('user', (req) => req.body.id || 'new_user'),
    userController.createUser
);

// SELF-ACCESS AND ADMIN ROUTES (use checkResourceOwnership for permission control)

/**
 * Get Single User
 * Route definition:
 * Permissions: Unrestricted => Super Admin, Admin; Restricted => Logged-in User (own profile only)
 */
router.get('/:id',
    userMiddleware.checkUserExists,
    userMiddleware.checkResourceOwnership,
    cacheResponse(3600, (req) => `user:profile:${req.params.id}`), // Cache for 1 hour
    userController.getUserById
);

/**
 * Update Existing User
 * Route definition:
 * Permissions: Unrestricted => super admin, admin; Restricted => Logged-in User (own profile only)
 */
router.put('/:id',
    userMiddleware.checkUserExists,
    userMiddleware.checkResourceOwnership,
    userMiddleware.normalizeRoleField,
    userMiddleware.checkRoles(),
    validateRequest(userSchemas.updateUser),
    userMiddleware.checkDuplicateUsernameOrEmail,
    clearCache((req) => ['users:list:*', 'users:stats:*', `user:profile:${req.params.id}`]),
    autoInvalidateCache('user'),
    userController.updateUser
);

/**
 * Delete User
 * Route definition:
 * Permissions: Unrestricted => super admin, admin; Restricted => Logged-in User (own account only)
 */
router.delete('/:id',
    userMiddleware.checkUserExists,
    userMiddleware.checkDeletePermission,
    clearCache((req) => ['users:list:*', 'users:stats:*', `user:profile:${req.params.id}`]),
    autoInvalidateCache('user'),
    userController.deleteUser
);

/**
 * Change User Password
 * Route definition:
 * Permissions: Unrestricted => super admin, admin; Restricted => Logged-in User (own password only)
 */
router.put('/:id/password',
    userMiddleware.checkUserExists,
    userMiddleware.checkResourceOwnership,
    validateRequest(userSchemas.changePassword),
    userMiddleware.hashPassword,
    clearCache((req) => [`user:profile:${req.params.id}`]),
    userController.changePassword
);

/**
 * Get User Files
 * Route definition:
 * Permissions: Unrestricted => super admin, admin; Restricted => Logged-in User (own files only)
 */
router.get('/:id/files',
    userMiddleware.checkUserExists,
    userMiddleware.checkResourceOwnership,
    validateRequest(fileSchemas.getFiles, 'query'),
    cacheResponse(300, (req) => {
        const params = req.query ? new URLSearchParams(req.query).toString() : '';
        return `user:files:${req.params.id}:${params ? Buffer.from(params).toString('base64') : 'all'}`;
    }), // Cache for 5 minutes
    userController.getUserFiles
);

/**
 * Get User Statistics
 * Route definition:
 * Permissions: Unrestricted => super admin, admin; Restricted => Logged-in User (own stats only)
 */
router.get('/:id/stats',
    userMiddleware.checkUserExists,
    userMiddleware.checkResourceOwnership,
    validateRequest(statsSchemas.userStats, 'query'),
    userMiddleware.prepareUserStatsFilters,
    cacheResponse(120, (req) => {
        // Sort query parameters for consistent cache keys
        const sortedParams = req.query ?
            Object.keys(req.query)
                .sort()
                .map(key => `${key}=${req.query[key]}`)
                .join('&') : '';
        return `user:stats:${req.params.id}:${sortedParams ? Buffer.from(sortedParams).toString('base64') : 'all'}`;
    }), // Cache for 2 minutes
    userController.getUserStats
);

/**
 * Get Specific User Data Fields
 * Route definition:
 * Permissions: Unrestricted => super admin, admin; Restricted => Logged-in User (own data only)
 * Query params: fields=activity.loginHistory,files.totalFiles,security.active
 */
router.get('/:id/stats/fields',
    userMiddleware.checkUserExists,
    userMiddleware.checkResourceOwnership,
    validateRequest(statsSchemas.userStatsFields, 'query'),
    userMiddleware.prepareUserStatsFilters,
    cacheResponse(60, (req) => {
        // Create cache key based on user ID and requested fields
        const fields = req.query.fields || '';
        const sortedParams = req.query ?
            Object.keys(req.query)
                .sort()
                .map(key => `${key}=${req.query[key]}`)
                .join('&') : '';
        return `user:stats:fields:${req.params.id}:${fields ? Buffer.from(fields).toString('base64') : 'all'}:${sortedParams ? Buffer.from(sortedParams).toString('base64') : 'default'}`;
    }), // Cache for 1 minute for specific field queries
    userController.getUserStatsFields
);

module.exports = router;
