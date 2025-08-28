const router = require('express').Router();
const appController = require('../controllers/app.controller');
const authMiddleware = require('../middleware/auth.middleware');
const {RIGHTS} = require('../config/rights');
const {cacheResponse, noCacheResponse} = require('../middleware/cache.middleware');
const {validateRequest} = require('../middleware/validation.middleware');
const {appStatsSchemas} = require('../models/schemas');

// Define app routes for validation
router.validRoutes = [
    '/api/v1/health',
    '/api/v1/logs',
    '/api/v1/logs/stats',
    '/api/v1/logs/:id',
    '/api/v1/email/template/render',
    '/api/v1/email/test',
    '/api/v1/stats/overview',
    '/api/v1/stats/performance'
];

// Health check route - NO CACHING (health endpoints should always be real-time)
router.get('/health', noCacheResponse(), // Use no-cache middleware instead of cacheResponse
    appController.getApiHealth);

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

module.exports = router;
