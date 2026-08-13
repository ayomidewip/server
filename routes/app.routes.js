import {Router} from 'express';
import * as appController from '../controllers/app.controller.js';
import * as authMiddleware from '../middleware/auth.middleware.js';
import {RIGHTS} from '../config/rights.js';
import {cacheResponse, noCacheResponse, clearCache} from '../middleware/cache.middleware.js';
import {validateRequest} from '../middleware/validation.middleware.js';
import {appStatsSchemas, themeSchemas} from '../models/schemas.js';

const router = Router();

// Define app routes for validation
router.validRoutes = [
    '/api/v1/health',
    '/api/v1/logs',
    '/api/v1/logs/stats',
    '/api/v1/logs/:id',
    '/api/v1/email/template/render',
    '/api/v1/email/test',
    '/api/v1/stats/overview',
    '/api/v1/stats/performance',
    '/api/v1/contact',
    '/api/v1/themes',
    '/api/v1/themes/presets',
    '/api/v1/themes/public',
    '/api/v1/themes/:id',
    '/api/v1/themes/:id/fork'
];

// Health check route - NO CACHING (health endpoints should always be real-time)
router.get('/health', noCacheResponse(), // Use no-cache middleware instead of cacheResponse
    appController.getApiHealth);

// Contact form submission (public)
router.post('/contact', appController.submitContactForm);

// Get logs route (admin only)
router.get('/logs', authMiddleware.verifyToken(), authMiddleware.checkPermission(RIGHTS.MANAGE_ALL_USERS), cacheResponse(30, (req) => {
        // Include query parameters in cache key to avoid returning wrong filtered results
        const params = req.query ? new URLSearchParams(req.query).toString() : '';
        return `app:logs${params ? `?${params}` : ''}`;
    }), // Cache for 30 seconds with query-aware key
    appController.getLogs);

// Get log statistics route (admin only) - supports optional userId filter
router.get('/logs/stats', authMiddleware.verifyToken(), authMiddleware.checkPermission(RIGHTS.MANAGE_ALL_USERS), cacheResponse(60, (req) => {
        // Include userId in cache key if provided to ensure correct stats by user
        const userId = req.query.userId;
        return `log:stats${userId ? `:user:${userId}` : ':all'}`;
    }), // Cache for 60 seconds with user-aware key
    appController.getLogStats);

// Get single log by ID route (admin only)
router.get('/logs/:id', authMiddleware.verifyToken(), authMiddleware.checkPermission(RIGHTS.MANAGE_ALL_USERS), cacheResponse(60, (req) => {
        // Include log ID in cache key to avoid returning wrong log data
        return `single_log_${req.params.id}`;
    }), // Cache for 60 seconds with ID-specific key
    appController.getLogById);

// Clear logs route (admin only)
router.delete('/logs', authMiddleware.verifyToken(), authMiddleware.checkPermission(RIGHTS.MANAGE_ALL_USERS), appController.clearLogs);

// Email template render route (admin only)
router.post('/email/template/render', authMiddleware.verifyToken(), authMiddleware.checkPermission(RIGHTS.MANAGE_ALL_USERS), appController.renderEmailTemplate);

// Send test email route (admin only)
router.post('/email/test', authMiddleware.verifyToken(), authMiddleware.checkPermission(RIGHTS.MANAGE_ALL_USERS), appController.sendTestEmail);

// Application statistics routes (admin only)
router.get('/stats/overview',
    authMiddleware.verifyToken(),
    authMiddleware.checkPermission(RIGHTS.MANAGE_ALL_USERS),
    validateRequest(appStatsSchemas.overview, 'query'),
    cacheResponse(60, (req) => {
        // Include period parameter in cache key to avoid returning wrong time-filtered results
        const period = req.query.period || '30d';
        return `app_stats_overview_${period}`;
    }),
    appController.getApplicationOverviewStats
);

router.get('/stats/performance',
    authMiddleware.verifyToken(),
    authMiddleware.checkPermission(RIGHTS.MANAGE_ALL_USERS),
    validateRequest(appStatsSchemas.performance, 'query'),
    cacheResponse(60, (req) => {
        // Include period parameter in cache key to avoid returning wrong time-filtered results
        const period = req.query.period || '7d';
        return `app_stats_performance_${period}`;
    }),
    appController.getApplicationPerformanceStats
);

/* ============================================================================
 * Theme routes — /api/v1/themes
 *
 * Static segments (/presets, /public) are declared before /:id so the param
 * route does not swallow them. Auth is applied per-route rather than via
 * router.use() so it cannot leak onto the app routes above.
 * ========================================================================= */

/**
 * Get Preset Themes (the seeded built-ins):
 * Route Definition: GET /api/v1/themes/presets
 * Permission: Public
 */
router.get('/themes/presets',
    cacheResponse(3600, () => 'themes:presets'), // Cache for 1 hour
    appController.getPresets
);

/**
 * Get Public Theme Gallery:
 * Route Definition: GET /api/v1/themes/public
 * Permission: Public
 */
router.get('/themes/public',
    validateRequest(themeSchemas.listThemes, 'query'),
    cacheResponse(300, (req) => {
        const params = req.query ? new URLSearchParams(req.query).toString() : '';
        return `themes:public:${params ? Buffer.from(params).toString('base64') : 'all'}`;
    }), // Cache for 5 minutes
    appController.getPublicThemes
);

/**
 * Get Own Themes:
 * Route Definition: GET /api/v1/themes
 * Permission: Authenticated
 */
router.get('/themes',
    authMiddleware.verifyToken(),
    appController.getMyThemes
);

/**
 * Create Theme:
 * Route Definition: POST /api/v1/themes
 * Permission: CREATE_CONTENT (CREATOR and above)
 */
router.post('/themes',
    authMiddleware.verifyToken(),
    authMiddleware.checkPermission(RIGHTS.CREATE_CONTENT),
    validateRequest(themeSchemas.createTheme),
    clearCache(['themes:public:*']),
    appController.createTheme
);

/**
 * Get Single Theme:
 * Route Definition: GET /api/v1/themes/:id
 * Permission: Authenticated (visibility rules enforced in controller)
 */
router.get('/themes/:id',
    authMiddleware.verifyToken(),
    validateRequest(themeSchemas.themeId, 'params'),
    appController.getThemeById
);

/**
 * Update Theme:
 * Route Definition: PUT /api/v1/themes/:id
 * Permission: Owner of theme | MANAGE_ALL_CONTENT (enforced in controller)
 */
router.put('/themes/:id',
    authMiddleware.verifyToken(),
    validateRequest(themeSchemas.themeId, 'params'),
    validateRequest(themeSchemas.updateTheme),
    clearCache((req) => ['themes:public:*', `theme:${req.params.id}`]),
    appController.updateTheme
);

/**
 * Delete Theme:
 * Route Definition: DELETE /api/v1/themes/:id
 * Permission: Owner of theme | MANAGE_ALL_CONTENT (enforced in controller)
 */
router.delete('/themes/:id',
    authMiddleware.verifyToken(),
    validateRequest(themeSchemas.themeId, 'params'),
    clearCache((req) => ['themes:public:*', `theme:${req.params.id}`]),
    appController.deleteTheme
);

/**
 * Fork Theme:
 * Route Definition: POST /api/v1/themes/:id/fork
 * Permission: CREATE_CONTENT (CREATOR and above)
 */
router.post('/themes/:id/fork',
    authMiddleware.verifyToken(),
    validateRequest(themeSchemas.themeId, 'params'),
    authMiddleware.checkPermission(RIGHTS.CREATE_CONTENT),
    appController.forkTheme
);

export default router;
