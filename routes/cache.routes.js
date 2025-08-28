const router = require('express').Router();
const cacheController = require('../controllers/cache.controller');
const authMiddleware = require('../middleware/auth.middleware');
const {RIGHTS} = require('../config/rights');
const {cacheResponse, noCacheResponse} = require('../middleware/cache.middleware');

// Define cache routes for validation
router.validRoutes = [
    '/api/v1/cache/stats',
    '/api/v1/cache/cleanup',
    '/api/v1/cache/health',
    '/api/v1/cache'
];

// Cache stats route (admin only)
router.get('/stats', 
    authMiddleware.verifyToken(), 
    authMiddleware.checkPermission(RIGHTS.MANAGE_ALL_USERS), 
    cacheResponse(10, 'cache:stats'), // Cache for just 10 seconds as this could change frequently
    cacheController.getCacheStats
);

// Clear cache route (admin only)
router.delete('/', 
    authMiddleware.verifyToken(), 
    authMiddleware.checkPermission(RIGHTS.MANAGE_ALL_USERS), 
    cacheController.clearCache
);

// Cache cleanup status and configuration endpoint (admin only)
router.get('/cleanup',
    authMiddleware.verifyToken(),
    authMiddleware.checkPermission(RIGHTS.MANAGE_ALL_USERS),
    noCacheResponse(),
    cacheController.getCleanupStatus
);

// Manual cache cleanup trigger endpoint (admin only)
router.post('/cleanup',
    authMiddleware.verifyToken(),
    authMiddleware.checkPermission(RIGHTS.MANAGE_ALL_USERS),
    noCacheResponse(),
    cacheController.runCleanup
);

// Cache health and statistics endpoint (admin only)
router.get('/health',
    authMiddleware.verifyToken(),
    authMiddleware.checkPermission(RIGHTS.MANAGE_ALL_USERS),
    noCacheResponse(), // Never cache health endpoints
    cacheController.getCacheHealth
);

module.exports = router;
