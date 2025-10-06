/**
 * Cache Controller
 * Handles all cache-related operations including statistics, cleanup, and management
 */

const logger = require('../utils/app.logger');
const {cache} = require('../middleware/cache.middleware');
const {asyncHandler} = require('../middleware/app.middleware');

const cleanupIntervalHours = parseInt(process.env.CACHE_CLEANUP_INTERVAL_HOURS, 10);
const cleanupMinAgeHours = parseInt(process.env.CACHE_CLEANUP_MIN_AGE_HOURS, 10);
const cleanupMaxKeysPerRun = parseInt(process.env.CACHE_CLEANUP_MAX_KEYS_PER_RUN, 10);

if ([cleanupIntervalHours, cleanupMinAgeHours, cleanupMaxKeysPerRun].some(
    value => !Number.isFinite(value) || value <= 0
)) {
    throw new Error('[CacheCleanup] CACHE_CLEANUP_* environment variables must be positive integers');
}

/**
 * Cache Cleanup Service Class
 * Provides scheduled cleanup for cache maintenance and optimization
 * Conservative approach - only cleans truly expired/orphaned data
 */
class CacheCleanupService {
    constructor() {
        this.isRunning = false;
        this.cleanupInterval = null;
        this.stats = {
            lastCleanup: null,
            totalCleaned: 0,
            cleanupRuns: 0,
            lastRunDuration: 0,
            keysScanned: 0,
            keysSkipped: 0
        };
    }

    /**
     * Start the cache cleanup service with conservative settings
     * @param {number} intervalHours - Cleanup interval in hours (default: 24)
     */
    start(intervalHours = null) {
        if (this.isRunning) {
            logger.warn('[CacheCleanup] Service already running');
            return;
        }

        // Check if cleanup is enabled
        const isEnabled = process.env.CACHE_CLEANUP_ENABLED !== 'false';
        if (!isEnabled) {
            logger.info('[CacheCleanup] Cache cleanup disabled via environment variable');
            return;
        }

        // Use environment variable or provided override
        let actualInterval = cleanupIntervalHours;

        if (intervalHours != null) {
            const overrideInterval = parseInt(intervalHours, 10);
            if (!Number.isFinite(overrideInterval) || overrideInterval <= 0) {
                throw new Error('[CacheCleanup] CACHE_CLEANUP_INTERVAL_OVERRIDE must be a positive integer');
            }
            actualInterval = overrideInterval;
        }
        const intervalMs = actualInterval * 60 * 60 * 1000;

        this.isRunning = true;

        logger.info(`🧹 Conservative cache cleanup service started (every ${actualInterval} hours)`);

        // Set up recurring cleanup - first cleanup happens after the full interval
        this.cleanupInterval = setInterval(() => {
            this.runCleanup();
        }, intervalMs);
    }

    /**
     * Stop the cache cleanup service
     */
    stop() {
        if (this.cleanupInterval) {
            clearInterval(this.cleanupInterval);
            this.cleanupInterval = null;
        }
        this.isRunning = false;
        logger.info('🧹 Cache cleanup service stopped');
    }

    /**
     * Get service statistics and configuration
     */
    getStats() {
        return {
            enabled: process.env.CACHE_CLEANUP_ENABLED !== 'false',
            isRunning: this.isRunning,
            intervalHours: cleanupIntervalHours,
            minAgeHours: cleanupMinAgeHours,
            maxKeysPerRun: cleanupMaxKeysPerRun,
            lastRun: this.stats.lastCleanup,
            nextRun: this.stats.lastCleanup ?
                new Date(this.stats.lastCleanup.getTime() + (cleanupIntervalHours * 60 * 60 * 1000)) :
                null,
            totalRuns: this.stats.cleanupRuns,
            lastRunStats: {
                keysRemoved: this.stats.lastRunKeysRemoved || 0,
                duration: this.stats.lastRunDuration,
                keysScanned: this.stats.lastRunKeysScanned || 0,
                keysSkipped: this.stats.lastRunKeysSkipped || 0
            }
        };
    }

    /**
     * Run cache cleanup process
     * Conservative approach - only removes truly expired/orphaned data
     */
    async runCleanup() {
        const startTime = Date.now();
        logger.info('[CacheCleanup] Starting conservative cache cleanup...');

        try {
            const {redisClient} = require('../middleware/app.middleware');

            if (!redisClient || !redisClient.isReady) {
                logger.warn('[CacheCleanup] Redis client not available, skipping cleanup');
                return;
            }

            // Get configuration from environment variables
            let totalKeysRemoved = 0;
            let totalKeysScanned = 0;
            let totalKeysSkipped = 0;

            // Conservative cleanup of expired autosave data
            totalKeysRemoved += await this.cleanupExpiredAutosave(redisClient, cleanupMaxKeysPerRun, cleanupMinAgeHours);

            // Conservative cleanup of old orphaned keys
            const {
                removed,
                scanned,
                skipped
            } = await this.cleanupOldOrphanedKeys(redisClient, cleanupMaxKeysPerRun, cleanupMinAgeHours);
            totalKeysRemoved += removed;
            totalKeysScanned += scanned;
            totalKeysSkipped += skipped;

            // Update statistics
            this.stats.lastCleanup = new Date();
            this.stats.totalCleaned += totalKeysRemoved;
            this.stats.cleanupRuns++;
            this.stats.lastRunDuration = Date.now() - startTime;
            this.stats.lastRunKeysRemoved = totalKeysRemoved;
            this.stats.lastRunKeysScanned = totalKeysScanned;
            this.stats.lastRunKeysSkipped = totalKeysSkipped;

            logger.info(`[CacheCleanup] Conservative cleanup completed: removed ${totalKeysRemoved} keys, scanned ${totalKeysScanned}, skipped ${totalKeysSkipped} (${this.stats.lastRunDuration}ms)`);

            return {
                success: true,
                keysRemoved: totalKeysRemoved,
                keysScanned: totalKeysScanned,
                keysSkipped: totalKeysSkipped,
                duration: this.stats.lastRunDuration,
                timestamp: this.stats.lastCleanup
            };

        } catch (error) {
            logger.error('[CacheCleanup] Error during cleanup:', error);
            throw error;
        }
    }

    /**
     * Clean up expired autosave data with TTL validation
     */
    async cleanupExpiredAutosave(redisClient, maxKeys, minAgeHours) {
        let keysRemoved = 0;
        let keysProcessed = 0;

        try {
            const cursor = redisClient.scanIterator({
                MATCH: 'autosave:*',
                COUNT: 100
            });

            for await (const key of cursor) {
                if (keysProcessed >= maxKeys) break;
                keysProcessed++;

                try {
                    // Check TTL - if -1, key doesn't expire, if -2, key doesn't exist
                    const ttl = await redisClient.ttl(key);
                    if (ttl === -2) {
                        // Key doesn't exist anymore, skip
                        continue;
                    }

                    // If TTL is 0 or negative (but not -1 or -2), key is expired
                    if (ttl <= 0 && ttl !== -1) {
                        // Additional age check for safety
                        const keyAge = await this.getKeyAge(redisClient, key);
                        if (keyAge >= minAgeHours) {
                            await redisClient.del(key);
                            keysRemoved++;
                        }
                    }
                } catch (keyError) {
                }
            }

            logger.info(`[CacheCleanup] Autosave cleanup: processed ${keysProcessed} keys, removed ${keysRemoved}`);
            return keysRemoved;

        } catch (error) {
            logger.error('[CacheCleanup] Error cleaning autosave data:', error);
            return 0;
        }
    }

    /**
     * Clean up old orphaned keys with conservative age checking
     */
    async cleanupOldOrphanedKeys(redisClient, maxKeys, minAgeHours) {
        let keysRemoved = 0;
        let keysScanned = 0;
        let keysSkipped = 0;

        try {
            const cursor = redisClient.scanIterator({
                MATCH: '*',
                COUNT: 50
            });

            for await (const key of cursor) {
                if (keysScanned >= maxKeys) break;
                keysScanned++;

                try {
                    // Skip certain patterns that should be preserved
                    if (this.shouldSkipKey(key)) {
                        keysSkipped++;
                        continue;
                    }

                    // Check if key has TTL and if it's expired
                    const ttl = await redisClient.ttl(key);

                    // Skip keys that don't expire (-1) or don't exist (-2)
                    if (ttl === -1 || ttl === -2) {
                        keysSkipped++;
                        continue;
                    }

                    // Only remove if truly expired (TTL <= 0) and old enough
                    if (ttl <= 0) {
                        const keyAge = await this.getKeyAge(redisClient, key);
                        if (keyAge >= minAgeHours) {
                            await redisClient.del(key);
                            keysRemoved++;
                        } else {
                            keysSkipped++;
                        }
                    } else {
                        keysSkipped++;
                    }

                } catch (keyError) {
                    keysSkipped++;
                }
            }

            logger.info(`[CacheCleanup] Orphaned keys cleanup: scanned ${keysScanned}, removed ${keysRemoved}, skipped ${keysSkipped}`);
            return {removed: keysRemoved, scanned: keysScanned, skipped: keysSkipped};

        } catch (error) {
            logger.error('[CacheCleanup] Error cleaning orphaned keys:', error);
            return {removed: 0, scanned: keysScanned, skipped: keysSkipped};
        }
    }

    /**
     * Determine if a key should be skipped during cleanup
     */
    shouldSkipKey(key) {
        const skipPatterns = [
            'session:',
            'auth:',
            'user:',
            'app:',
            'system:'
        ];

        return skipPatterns.some(pattern => key.startsWith(pattern));
    }

    /**
     * Get the age of a key in hours (approximation based on current time)
     * This is a conservative estimate
     */
    async getKeyAge(redisClient, key) {
        try {
            // Try to get creation time from key metadata if available
            // For now, use a conservative approach - assume minimum age
            const ttl = await redisClient.ttl(key);

            // If TTL is set, we can't determine exact age, so be conservative
            if (ttl > 0) {
                return 0; // Conservative - don't clean keys with positive TTL
            }

            // For expired keys, assume they're old enough (since TTL <= 0)
            return 24; // Conservative assumption

        } catch (error) {
            return 0; // Conservative - don't clean if we can't determine age
        }
    }
}

// Create singleton instance
const cleanupService = new CacheCleanupService();

/**
 * @desc    Get Redis cache statistics
 * @route   GET /api/v1/cache/stats
 * @access  Admin only
 */
const getCacheStats = asyncHandler(async (req, res, next) => {
    try {
        // Get Redis server info through appMiddleware
        const redisClient = require('../middleware/app.middleware').redisClient;

        if (!redisClient || !redisClient.isReady) {
            return res.status(503).json({success: false, message: 'Redis cache is not available'});
        }

        const info = await redisClient.info();
        const memory = await redisClient.info('memory');
        const stats = await redisClient.info('stats');

        // Parse Redis stats for cache hit rate calculation
        const redisStats = stats
            .split(/[\r\n]+/)
            .filter(line => line.includes(':'))
            .reduce((obj, line) => {
                const [key, value] = line.split(':');
                obj[key.trim()] = value.trim();
                return obj;
            }, {});

        // Calculate cache hit rate on the server
        const keyspaceHits = parseInt(redisStats.keyspace_hits || 0);
        const keyspaceMisses = parseInt(redisStats.keyspace_misses || 0);
        const totalOps = keyspaceHits + keyspaceMisses;
        const cacheHitRate = totalOps > 0 ? ((keyspaceHits / totalOps) * 100).toFixed(2) : '0.00';

        // Create Redis server statistics object (single source of truth)
        const cacheStats = {
            success: true,
            timestamp: new Date().toISOString(),
            cacheHitRate: parseFloat(cacheHitRate),

            // Redis server statistics (only source now)
            redisInfo: {
                memory: memory
                    .split(/[\r\n]+/)
                    .filter(line => line.includes(':'))
                    .reduce((obj, line) => {
                        const [key, value] = line.split(':');
                        obj[key.trim()] = value.trim();
                        return obj;
                    }, {}),
                stats: redisStats
            }
        };

        logger.info('Cache stats retrieved from Redis server');
        res.status(200).json({
            success: true,
            message: 'Cache statistics retrieved successfully',
            cacheStats,
            meta: {
                timestamp: new Date().toISOString()
            }
        });
    } catch (error) {
        logger.error('Error retrieving cache stats:', error);
        return next(error);
    }
});

/**
 * @desc    Clear Redis cache and reset all statistics
 * @route   DELETE /api/v1/cache
 * @access  Admin only
 */
const clearCache = asyncHandler(async (req, res, next) => {
    try {
        const {redisClient} = require('../middleware/app.middleware');

        logger.info('Clearing Redis cache and resetting all statistics...');

        if (!redisClient || !redisClient.isReady) {
            return res.status(503).json({
                success: false,
                message: 'Redis cache is not available'
            });
        }

        // Clear all data and reset statistics using Redis commands
        await redisClient.flushAll(); // Clear all databases
        await redisClient.configResetStat(); // Reset all statistics

        logger.info('Redis cache cleared and all statistics reset successfully');
        res.status(200).json({
            success: true,
            message: 'Cache data and statistics cleared successfully',
            meta: {
                resetTimestamp: new Date().toISOString(),
                method: 'redis_commands'
            }
        });
    } catch (error) {
        logger.error('Error clearing Redis cache:', error);
        return next(error);
    }
});

/**
 * @desc    Get cache cleanup service status and configuration
 * @route   GET /api/v1/cache/cleanup
 * @access  Admin only
 */
const getCleanupStatus = asyncHandler(async (req, res, next) => {
    try {
        const stats = cleanupService.getStats();
        res.status(200).json({
            success: true,
            message: 'Cache cleanup status retrieved successfully',
            cleanup: stats,
            meta: {
                timestamp: new Date().toISOString()
            }
        });
    } catch (error) {
        logger.error('Error getting cache cleanup status:', error);
        return next(error);
    }
});

/**
 * @desc    Manually trigger cache cleanup
 * @route   POST /api/v1/cache/cleanup
 * @access  Admin only
 */
const runCleanup = asyncHandler(async (req, res, next) => {
    try {
        logger.info('Manual cache cleanup triggered by admin');
        const result = await cleanupService.runCleanup();

        res.status(200).json({
            success: true,
            message: 'Manual cache cleanup completed successfully',
            cleanup: result,
            meta: {
                timestamp: new Date().toISOString()
            }
        });
    } catch (error) {
        logger.error('Error running manual cache cleanup:', error);
        return next(error);
    }
});

/**
 * @desc    Get cache health information
 * @route   GET /api/v1/cache/health
 * @access  Admin only
 */
const getCacheHealth = asyncHandler(async (req, res, next) => {
    try {
        const healthInfo = await cache.getHealthInfo();
        res.status(200).json({
            success: true,
            message: 'Cache health information retrieved successfully',
            cache: healthInfo,
            meta: {
                timestamp: new Date().toISOString()
            }
        });
    } catch (error) {
        logger.error('Error getting cache health info:', error);
        return next(error);
    }
});

module.exports = {
    getCacheStats,
    clearCache,
    getCleanupStatus,
    runCleanup,
    getCacheHealth,
    cleanupService
};
