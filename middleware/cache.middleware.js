/**
 * Redis Cache Middleware
 * Provides middleware functions for caching API responses and cache consistency
 * Ensures that database updates also update the relevant caches
 */

// Using a function to get redisClient to avoid circular dependencies
const getRedisClient = () => require('./app.middleware').redisClient;
const logger = require('../utils/app.logger');

// Check if caching is enabled via environment variable
const isCacheEnabled = () => {
    return process.env.CACHE_ENABLED !== 'false';
};

// Core cache operations
const cache = {
    get: async (key) => {
        // Return null immediately if caching is disabled
        if (!isCacheEnabled()) {
            return null;
        }

        try {
            const redisClient = getRedisClient();
            const data = await redisClient.get(key);
            const result = data ? JSON.parse(data) : null;
            return result;
        } catch (err) {
            logger.error(`${logger.safeColor(logger.colors.red)}[Cache]${logger.safeColor(logger.colors.reset)} Redis GET error:`, err);
            return null;
        }
    },

    set: async (key, value, expiration = 3600) => {
        // Do nothing if caching is disabled
        if (!isCacheEnabled()) {
            return 'OK'; // Return success to maintain compatibility
        }

        try {
            const redisClient = getRedisClient();
            const result = await redisClient.setEx(key, expiration, JSON.stringify(value));
            return result;
        } catch (err) {
            logger.error(`${logger.safeColor(logger.colors.red)}[Cache]${logger.safeColor(logger.colors.reset)} Redis SET error:`, err);
        }
    },

    del: async (key) => {
        // Do nothing if caching is disabled
        if (!isCacheEnabled()) {
            return 1; // Return success to maintain compatibility
        }

        try {
            const redisClient = getRedisClient();
            const result = await redisClient.del(key);
            return result || 1; // Ensure we return at least 1 for successful operation
        } catch (err) {
            logger.error(`${logger.safeColor(logger.colors.red)}[Cache]${logger.safeColor(logger.colors.reset)} Redis DEL error:`, err);
            return 1; // Return success in case of error to maintain compatibility
        }
    },

    flush: async () => {
        // Do nothing if caching is disabled
        if (!isCacheEnabled()) {
            return 'OK'; // Return success to maintain compatibility
        }

        try {
            const redisClient = getRedisClient();
            const result = await redisClient.flushDb();
            return result;
        } catch (err) {
            logger.error(`${logger.safeColor(logger.colors.red)}[Cache]${logger.safeColor(logger.colors.reset)} Redis FLUSH error:`, err);
        }
    },

    // Helper method to delete multiple cache keys by pattern
    delPattern: async (pattern) => {
        // Do nothing if caching is disabled
        if (!isCacheEnabled()) {
            return 0;
        }

        try {
            const redisClient = getRedisClient();

            // Check if the client has the keys method
            if (typeof redisClient.keys !== 'function') {
                return 0;
            }

            // Get all keys matching the pattern
            const keys = await redisClient.keys(pattern);
            if (keys.length === 0) {
                return 0;
            }

            // Delete all matching keys
            const result = await redisClient.del(keys);
            return result;
        } catch (err) {
            logger.error(`${logger.safeColor(logger.colors.red)}[Cache]${logger.safeColor(logger.colors.reset)} Redis PATTERN DELETE error:`, err);
            return 0;
        }
    },

    // Helper method to delete multiple specific keys
    delMultiple: async (keys) => {
        // Do nothing if caching is disabled
        if (!isCacheEnabled()) {
            return 0;
        }

        if (!Array.isArray(keys) || keys.length === 0) {
            return 0;
        }

        try {
            const redisClient = getRedisClient();
            const result = await redisClient.del(keys);
            return result;
        } catch (err) {
            logger.error(`${logger.safeColor(logger.colors.red)}[Cache]${logger.safeColor(logger.colors.reset)} Redis MULTIPLE DELETE error:`, err);
            return 0;
        }
    },

    // Helper method to invalidate user-related caches
    invalidateUserCaches: async (userId) => {
        if (!isCacheEnabled()) return;

        try {
            const keysToDelete = [
                `user:profile:${userId}`,
                `user:files:${userId}:all`,
                'users:list:all'
            ];

            // Also delete session patterns
            await cache.delPattern(`auth:session:${userId}:*`);

            // Delete specific keys
            await cache.delMultiple(keysToDelete);

        } catch (err) {
            logger.error(`${logger.safeColor(logger.colors.red)}[Cache]${logger.safeColor(logger.colors.reset)} Error invalidating user caches:`, err);
        }
    },

    // Helper method to invalidate file-related caches
    invalidateFileCaches: async (filePath, userId = null) => {
        if (!isCacheEnabled()) return;

        try {
            const encodedFilePath = Buffer.from(filePath).toString('base64');
            const keysToDelete = [
                // Note: Deliberately NOT clearing `file:autosave:${encodedFilePath}` 
                // Auto-save cache should persist until explicitly saved or replaced
                `file:cache:${encodedFilePath}`,
                `file:metadata:${encodedFilePath}:latest`,
                `file:content:${encodedFilePath}:latest`,
                `file:versions:${encodedFilePath}`
            ];

            // If userId provided, also clear user-specific file caches
            if (userId) {
                keysToDelete.push(
                    `user:files:${userId}:all`
                );
            }

            await cache.delMultiple(keysToDelete);

        } catch (err) {
            logger.error(`${logger.safeColor(logger.colors.red)}[Cache]${logger.safeColor(logger.colors.reset)} Error invalidating file caches:`, err);
        }
    },

    // Helper method to invalidate all caches after any data update
    invalidateAllRelatedCaches: async (type, id, userId = null) => {
        if (!isCacheEnabled()) return;

        try {

            // Define common caches to invalidate for different entity types
            const commonCaches = [];

            switch (type) {
                case 'user':
                    await cache.invalidateUserCaches(id);
                    // Also clear global auth-related caches
                    commonCaches.push(
                        'users:list:all',
                        `user:profile:${id}`,
                        `user:files:${id}:all`
                    );
                    // Clear session patterns
                    await cache.delPattern(`auth:session:${id}:*`);
                    break;

                case 'file':
                    await cache.invalidateFileCaches(id, userId);
                    // Also clear global file-related caches
                    commonCaches.push(
                        'files:all',
                        `file:types:supported`,
                        `file:metadata:${id}:latest`,
                        `file:content:${id}:latest`,
                        `file:versions:${id}`
                    );
                    if (userId) {
                        commonCaches.push(`user:files:${userId}:all`);
                    }
                    break;

                case 'auth':
                    // Clear authentication-related caches
                    if (id) {
                        await cache.invalidateUserCaches(id);
                        await cache.delPattern(`auth:session:${id}:*`);
                        await cache.delPattern(`auth:refresh:${id}:*`);
                    }
                    break;

                case 'log':
                    // Clear log-related caches
                    break;

                default:
                    // For unknown types, no additional cache clearing
                    break;
            }

            // Delete common caches
            if (commonCaches.length > 0) {
                await cache.delMultiple(commonCaches);
            }

            // Clear any wildcard patterns for the entity, but exclude autosave and other critical cache keys
            // Use more specific patterns to avoid accidentally deleting autosave cache
            const specificPatterns = [
                `${type}:cache:*${id}*`,           // file:cache:* patterns
                `${type}:metadata:*${id}*`,        // file:metadata:* patterns  
                `${type}:content:*${id}*`,         // file:content:* patterns
                `${type}_${id}_*`,                 // file_id_ patterns
                `*_${type}_${id}*`                 // *_file_id* patterns
            ];

            for (const pattern of specificPatterns) {
                await cache.delPattern(pattern);
            }

        } catch (err) {
            logger.error(`${logger.safeColor(logger.colors.red)}[Cache]${logger.safeColor(logger.colors.reset)} Error invalidating related caches:`, err);
        }
    },

    // Helper method to check if caching is enabled
    isEnabled: isCacheEnabled,

    // Get cache health information
    getHealthInfo: async () => {
        try {
            const redisClient = getRedisClient();
            const isEnabled = isCacheEnabled();
            
            if (!isEnabled) {
                return {
                    success: true,
                    enabled: false,
                    redis: {
                        status: 'disabled'
                    },
                    cache: {
                        enabled: false
                    }
                };
            }

            const isReady = redisClient && redisClient.isReady;
            const status = isReady ? 'connected' : 'disconnected';

            return {
                success: true,
                enabled: isEnabled,
                redis: {
                    status,
                    connected: isReady
                },
                cache: {
                    enabled: isEnabled,
                    operational: isReady
                }
            };
        } catch (error) {
            logger.error(`${logger.safeColor(logger.colors.red)}[Cache]${logger.safeColor(logger.colors.reset)} Health check error:`, error);
            return {
                success: false,
                enabled: isCacheEnabled(),
                redis: {
                    status: 'error',
                    connected: false
                },
                cache: {
                    enabled: isCacheEnabled(),
                    operational: false
                },
                error: error.message
            };
        }
    }
};

/**
 * Middleware to cache API responses
 * @param {number} duration - Cache duration in seconds
 * @param {Function} [keyFn] - Optional function to generate cache key, receives req object
 * @param {Object} [options] - Additional options
 * @param {boolean} [options.forceDisable=false] - Force disable caching for this middleware (used for health endpoints)
 * @returns {Function} Express middleware
 */
const cacheResponse = (duration = 3600, keyFn = null, options = {}) => {
    return async (req, res, next) => {        // Skip caching if globally disabled or force disabled
        if (!cache.isEnabled() || options.forceDisable) {
            if (options.forceDisable) {
            } else {
            }
            // Add headers to indicate no caching
            res.set('X-Cache', 'DISABLED');
            res.set('X-Cache-Status', 'DISABLED');
            res.set('Cache-Control', 'no-cache, no-store, must-revalidate');
            res.set('Pragma', 'no-cache');
            res.set('Expires', '0');
            return next();
        }

        // Skip caching for non-GET requests
        if (req.method !== 'GET') {
            return next();
        }// Generate cache key
        const generateKey = () => {
            if (keyFn && typeof keyFn === 'function') {
                return keyFn(req);
            } else if (typeof keyFn === 'string') {
                // Allow static string as cache key
                return keyFn;
            }

            // Default key generation: url+query params+user ID (for personalized responses)
            const params = req.query ? new URLSearchParams(req.query).toString() : '';
            const userId = req.user?.id ? `-user-${req.user.id}` : '';
            return `${req.originalUrl}${params ? `?${params}` : ''}${userId}`;
        };

        const key = generateKey();

        // Skip caching if key function returned null/undefined (explicit no-cache signal)
        if (key === null || key === undefined) {
            res.set('X-Cache', 'DISABLED');
            res.set('X-Cache-Status', 'DISABLED');
            return next();
        }

        try {
            // Try to get data from cache
            const cachedData = await cache.get(key);

            if (cachedData) {
                logger.info(`${logger.safeColor(logger.colors.cyan)}[Cache Middleware]${logger.safeColor(logger.colors.reset)} Cache hit for ${key}`);

                // Add standard cache headers
                res.set('X-Cache', 'HIT');
                res.set('X-Cache-Status', 'HIT');

                // Return cached data exactly as it was stored, without any processing or wrapping
                return res.status(200).json(cachedData);
            }

            logger.info(`${logger.safeColor(logger.colors.cyan)}[Cache Middleware]${logger.safeColor(logger.colors.reset)} Cache miss for ${key}`);

            // Add standard cache headers for miss
            res.set('X-Cache', 'MISS');
            res.set('X-Cache-Status', 'MISS');

            // Store the original json function
            const originalJson = res.json;
            // Override the json function to cache the response
            res.json = function (data) {
                try {
                    // Only cache successful responses
                    if (res.statusCode >= 200 && res.statusCode < 300) {
                        // Cache asynchronously - don't await to avoid blocking response
                        cache.set(key, data, duration).then(() => {
                        }).catch(err => {
                            logger.error(`${logger.safeColor(logger.colors.red)}[Cache Middleware]${logger.safeColor(logger.colors.reset)} Error caching response for ${key}:`, err);
                        });
                    } else {
                    }
                } catch (err) {
                    logger.error(`${logger.safeColor(logger.colors.red)}[Cache Middleware]${logger.safeColor(logger.colors.reset)} Error caching response for ${key}:`, err);
                }
                // Call the original json function
                return originalJson.call(this, data);
            };
            next();
        } catch (err) {
            logger.error(`${logger.safeColor(logger.colors.red)}[Cache Middleware]${logger.safeColor(logger.colors.reset)} Cache middleware error for ${key}:`, err);
            next(); // Continue without caching on error
        }
    };
};

/**
 * Middleware to clear cache for specific patterns
 * @param {Array<string>|Function} patterns - Array of cache key patterns to clear or function that returns patterns
 * @returns {Function} Express middleware
 */
const clearCache = (patterns = []) => {
    return async (req, res, next) => {
        const originalJson = res.json;

        res.json = async function (body) {
            try {
                // Only clear cache for successful responses (2xx status codes) and if caching is enabled
                if (res.statusCode >= 200 && res.statusCode < 300 && cache.isEnabled()) {
                    let patternsToUse = patterns;

                    // If patterns is a function, call it with request object
                    if (typeof patternsToUse === 'function') {
                        patternsToUse = patternsToUse(req, body);
                    }
                    if (Array.isArray(patternsToUse) && patternsToUse.length > 0) {
                        for (const pattern of patternsToUse) {
                            try {
                                await cache.del(pattern);
                                logger.info(`${logger.safeColor(logger.colors.cyan)}[Cache Middleware]${logger.safeColor(logger.colors.reset)} Cleared cache for pattern: ${pattern}`);
                            } catch (err) {
                                logger.error(`${logger.safeColor(logger.colors.red)}[Cache Middleware]${logger.safeColor(logger.colors.reset)} Error clearing cache for pattern ${pattern}:`, err);
                            }
                        }
                    }
                } else if (!cache.isEnabled()) {
                }
            } catch (err) {
                logger.error(`${logger.safeColor(logger.colors.red)}[Cache Middleware]${logger.safeColor(logger.colors.reset)} Error clearing cache:`, err);
            }

            return originalJson.call(this, body);
        };

        next();
    };
};

/**
 * Create a no-cache middleware for endpoints that should never use caching (like health checks)
 * @returns {Function} Express middleware that bypasses all caching
 */
const noCacheResponse = () => {
    return (req, res, next) => {
        // Always add no-cache headers
        res.set('X-Cache', 'NEVER');
        res.set('X-Cache-Status', 'NEVER');
        res.set('Cache-Control', 'no-cache, no-store, must-revalidate');
        res.set('Pragma', 'no-cache');
        res.set('Expires', '0');

        next();
    };
};

/**
 * Auto-invalidation middleware that automatically clears related caches after successful operations
 * @param {string} entityType - Type of entity being modified ('user', 'file', 'auth', etc.)
 * @param {Function} getEntityId - Function to extract entity ID from request (receives req object)
 * @param {Function} getUserId - Optional function to extract user ID from request (receives req object)
 * @returns {Function} Express middleware
 */
const autoInvalidateCache = (entityType, getEntityId = null, getUserId = null) => {
    return async (req, res, next) => {
        // Store the original json method
        const originalJson = res.json;
        const originalSend = res.send;

        // Override both json and send methods to ensure cache invalidation
        const wrapResponse = function (data) {
            try {
                // Only invalidate cache for successful operations (2xx status codes)
                if (res.statusCode >= 200 && res.statusCode < 300) {
                    const entityId = getEntityId ? getEntityId(req) : (req.params.id || 'unknown');
                    const userId = getUserId ? getUserId(req) : (req.user ? req.user.id : null);

                    // Log cache invalidation

                    // Use cache utility to invalidate all related caches
                    cache.invalidateAllRelatedCaches(entityType, entityId, userId)
                        .catch(err => {
                            logger.error(`${logger.safeColor(logger.colors.red)}[AutoCacheInvalidation]${logger.safeColor(logger.colors.reset)} Error during auto cache invalidation:`, err);
                        });
                }
            } catch (err) {
                // Log error but don't block the response
                logger.error(`${logger.safeColor(logger.colors.red)}[AutoCacheInvalidation]${logger.safeColor(logger.colors.reset)} Auto cache invalidation error:`, err);
            }

            return originalJson.call(this, data);
        };

        res.json = wrapResponse;
        res.send = function (data) {
            // For non-JSON responses, still trigger cache invalidation
            if (res.statusCode >= 200 && res.statusCode < 300) {
                try {
                    const entityId = getEntityId ? getEntityId(req) : (req.params.id || 'unknown');
                    const userId = getUserId ? getUserId(req) : (req.user ? req.user.id : null);


                    cache.invalidateAllRelatedCaches(entityType, entityId, userId)
                        .catch(err => {
                            logger.error(`${logger.safeColor(logger.colors.red)}[AutoCacheInvalidation]${logger.safeColor(logger.colors.reset)} Error during auto cache invalidation (send):`, err);
                        });
                } catch (err) {
                    logger.error(`${logger.safeColor(logger.colors.red)}[AutoCacheInvalidation]${logger.safeColor(logger.colors.reset)} Auto cache invalidation error (send):`, err);
                }
            }
            return originalSend.call(this, data);
        };

        next();
    };
};

/**
 * Manual cache invalidation helper for controllers
 * Use this in controllers when you need explicit cache invalidation
 * @param {string} entityType - Type of entity being modified
 * @param {string} entityId - ID of the entity
 * @param {string} userId - Optional user ID
 */
const invalidateEntityCache = async (entityType, entityId, userId = null) => {
    try {
        await cache.invalidateAllRelatedCaches(entityType, entityId, userId);
    } catch (err) {
        logger.error(`${logger.safeColor(logger.colors.red)}[ManualCacheInvalidation]${logger.safeColor(logger.colors.reset)} Manual cache invalidation error:`, err);
    }
};

/**
 * Cache invalidation for multiple entities at once
 * @param {Array} entities - Array of {type, id, userId} objects
 */
const invalidateMultipleEntityCaches = async (entities) => {
    try {
        const invalidationPromises = entities.map(entity =>
            cache.invalidateAllRelatedCaches(entity.type, entity.id, entity.userId)
        );

        await Promise.all(invalidationPromises);
    } catch (err) {
        logger.error(`${logger.safeColor(logger.colors.red)}[MultipleCacheInvalidation]${logger.safeColor(logger.colors.reset)} Multiple cache invalidation error:`, err);
    }
};

/**
 * Database transaction wrapper that ensures cache consistency
 * Use this wrapper for database transactions to ensure cache is invalidated
 * @param {Function} transactionFn - Function that performs database operations
 * @param {Array} cacheEntities - Array of entities to invalidate after transaction
 */
const withCacheInvalidation = async (transactionFn, cacheEntities = []) => {
    try {
        // Execute the database transaction
        const result = await transactionFn();

        // If transaction succeeded, invalidate related caches
        if (cacheEntities.length > 0) {
            await invalidateMultipleEntityCaches(cacheEntities);
        }

        return result;
    } catch (error) {
        // Don't invalidate cache if transaction failed
        throw error;
    }
};

/**
 * Real-time cache invalidation for WebSocket events
 * Use this when you need to invalidate cache due to real-time events
 * @param {string} event - Event type
 * @param {Object} data - Event data containing entity information
 */
const invalidateCacheForEvent = async (event, data) => {
    try {

        // Determine entity type based on event
        let entityType = 'unknown';
        let entityId = data.id || data.entityId;
        let userId = data.userId;

        if (event.includes('user')) {
            entityType = 'user';
            entityId = data.userId || data.id;
        } else if (event.includes('file')) {
            entityType = 'file';
            entityId = data.filePath || data.id;
        } else if (event.includes('auth')) {
            entityType = 'auth';
            entityId = data.userId || data.id;
        }

        await cache.invalidateAllRelatedCaches(entityType, entityId, userId);
    } catch (err) {
        logger.error(`${logger.safeColor(logger.colors.red)}[EventCacheInvalidation]${logger.safeColor(logger.colors.reset)} Event cache invalidation error:`, err);
    }
};

// Data Manager Functions - Unified data operations with cache management

/**
 * Unified data operation handler
 * Handles database operations with automatic cache invalidation
 */
class DataManager {
    constructor() {
        // Removed stats functionality
    }

    /**
     * Execute a data operation with unified cache handling
     * @param {Object} options - Operation options
     * @param {Function} options.operation - The database operation to execute
     * @param {string} options.entityType - Type of entity ('user', 'file', 'auth', 'log')
     * @param {string} options.entityId - ID of the entity
     * @param {string} options.userId - User ID (optional)
     * @param {string} options.operationType - Type of operation ('create', 'read', 'update', 'delete')
     * @param {Array} options.cacheKeys - Specific cache keys to invalidate (optional)
     */
    async executeOperation(options) {
        const {
            operation,
            entityType,
            entityId,
            userId,
            operationType = 'unknown',
            cacheKeys = []
        } = options;

        try {
            // Execute the database operation
            const result = await operation();

            // Only proceed with cache if operation was successful
            if (result) {
                // Handle cache invalidation
                await this.handleCacheInvalidation(entityType, entityId, userId, cacheKeys);
            }

            return result;
        } catch (error) {
            logger.error('Unified operation failed:', {
                error: error.message,
                entityType,
                entityId,
                operationType
            });
            throw error;
        }
    }

    /**
     * Handle cache invalidation in a unified way
     */
    async handleCacheInvalidation(entityType, entityId, userId, additionalKeys = []) {
        try {
            // Use the existing comprehensive cache invalidation
            await cache.invalidateAllRelatedCaches(entityType, entityId, userId);

            // Invalidate additional specific keys if provided
            if (additionalKeys.length > 0) {
                await cache.delMultiple(additionalKeys);
            }
        } catch (error) {
        }
    }

    /**
     * Wrapper for CREATE operations
     */
    async create(entityType, operation, entityId, userId) {
        return this.executeOperation({
            operation,
            entityType,
            entityId,
            userId,
            operationType: 'create'
        });
    }

    /**
     * Wrapper for UPDATE operations
     */
    async update(entityType, operation, entityId, userId) {
        return this.executeOperation({
            operation,
            entityType,
            entityId,
            userId,
            operationType: 'update'
        });
    }

    /**
     * Wrapper for DELETE operations
     */
    async delete(entityType, operation, entityId, userId) {
        return this.executeOperation({
            operation,
            entityType,
            entityId,
            userId,
            operationType: 'delete'
        });
    }

    /**
     * Get entity-specific cache keys for manual invalidation
     */
    getEntityCacheKeys(entityType, entityId, userId) {
        const keys = [];

        switch (entityType) {
            case 'user':
                keys.push(
                    `user:${entityId}`,
                    `user:profile:${entityId}`,
                    `user:files:${entityId}:all`,
                    'users:list:all'
                );
                break;
            case 'file':
                keys.push(
                    `file:autosave:${entityId}`,
                    `file:cache:${entityId}`,
                    `file:metadata:${entityId}:latest`,
                    `file:content:${entityId}:latest`
                );
                if (userId) {
                    keys.push(`user:files:${userId}:all`);
                }
                break;
            case 'auth':
                if (entityId) {
                    keys.push(`auth:session:${entityId}:*`);
                }
                break;
            case 'log':
                break;
        }

        return keys;
    }

    /**
     * Bulk invalidate multiple entities
     */
    async bulkInvalidate(entities) {
        try {
            const promises = entities.map(entity =>
                this.handleCacheInvalidation(
                    entity.type,
                    entity.id,
                    entity.userId,
                    entity.additionalKeys || []
                )
            );

            await Promise.all(promises);
        } catch (error) {
            logger.error('Bulk invalidation failed:', error.message);
        }
    }
}

// Create singleton instance
const dataManager = new DataManager();

module.exports = {
    cache,
    cacheResponse,
    clearCache,
    noCacheResponse,
    autoInvalidateCache,
    invalidateEntityCache,
    invalidateMultipleEntityCaches,
    withCacheInvalidation,
    invalidateCacheForEvent,
    dataManager,
    DataManager
};