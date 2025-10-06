const logger = require('../utils/app.logger');
const Log = require('../models/log.model');
const mongoose = require('mongoose');
const {cache} = require('../middleware/cache.middleware');
const handlebars = require('handlebars');
const nodemailer = require('nodemailer');
const fs = require('fs').promises;
const path = require('path');
const {AppError} = require('../middleware/error.middleware');
const {asyncHandler} = require('../middleware/app.middleware');
const {GridFSBucket} = require('mongodb');

/**
 * Email templates cache
 */
const emailTemplatesCache = new Map();

/**
 * Email service state
 */
let emailTransporter = null;
let isEmailConfigured = false;

/**
 * App controller for handling application-level endpoints
 */

/**
 * Internal function to get health status without req/res
 */
const getHealthStatus = async () => {
    const startTime = process.hrtime();

    let dbStatus = 'error';
    let dbLatency = 0;

    try {
        // Check DB connection with timeout
        const dbStart = process.hrtime();
        if (mongoose.connection.readyState === 1) {
            await mongoose.connection.db.admin().ping();
            dbStatus = 'connected';
            const dbEnd = process.hrtime(dbStart);
            dbLatency = (dbEnd[0] * 1000 + dbEnd[1] / 1000000).toFixed(2);
        } else {
            dbStatus = 'disconnected';
        }
    } catch (err) {
        logger.error('Database health check failed:', err);
        dbStatus = 'error';
    }

    // Calculate total response time
    const endTime = process.hrtime(startTime);
    const responseTime = (endTime[0] * 1000 + endTime[1] / 1000000).toFixed(2);

    // Prepare memory usage info
    const memoryInfo = process.memoryUsage();

    // Check Yjs Redis pub/sub health
    let yjsRedisHealth = { status: 'not_available' };
    try {
        const fileController = require('./file.controller');
        if (fileController.yjsService && fileController.yjsService.isInitialized) {
            yjsRedisHealth = await fileController.yjsService.redisHealthCheck();
        }
    } catch (error) {
        yjsRedisHealth = { status: 'error', message: error.message };
    }

    const overallStatus = dbStatus === 'connected' ? 'ok' : 'error';

    return {
        status: overallStatus,
        timestamp: new Date().toISOString(),
        env: process.env.NODE_ENV,
        system: {
            nodeVersion: process.version,
            platform: process.platform,
            arch: process.arch,
            uptime: process.uptime(),
            memoryUsage: memoryInfo,
            cpuUsage: process.cpuUsage()
        },
        database: {
            status: dbStatus,
            latencyMs: parseFloat(dbLatency),
            connection: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
        },
        collaborative: {
            redis: yjsRedisHealth
        },
        responseTimeMs: parseFloat(responseTime)
    };
};

/**
 * @desc    Get basic health status
 * @route   GET /health
 * @access  Public
 */
const getHealth = (req, res) => {
    logger.info(`💚 Basic health check requested`, {ip: req.ip});

    const health = {
        success: true,
        status: 'ok',
        timestamp: new Date().toISOString(),
        env: process.env.NODE_ENV,
        version: process.version,
        uptime: Math.floor(process.uptime())
    };
    // Pretty-print the health info with 2-space indentation
    const prettyHealthInfo = JSON.stringify(health, null, 2);
    logger.info(`💚 Basic health check completed:\n${logger.safeColor(logger.colors.green)}${prettyHealthInfo}${logger.safeColor(logger.colors.reset)}`);

    res.json(health);
};

/**
 * @desc    Get detailed API health status
 * @route   GET /api/v1/health
 * @access  Public
 */
const getApiHealth = asyncHandler(async (req, res, next) => {
    try {
        // Health endpoints should NEVER use caching - always return real-time data
        const healthStatus = await getHealthStatus();

        // Add success flag for test compatibility
        const response = {
            success: true, ...healthStatus
        };

        logger.info('API health status fetched successfully', {ip: req.ip});
        res.status(200).json(response);
    } catch (error) {
        logger.error('Error in getApiHealth:', error);
        return next(error);
    }
});

/**
 * @desc    Setup health check routes
 * @param   {Object} app - Express application
 */
const setupHealthRoutes = async (app) => {    // Keep emojis for startup logs as per requirements
    logger.info('🏥 Setting up health check routes...');
    app.get('/health', getHealth);
    app.get('/api/v1/health', getApiHealth);

    // Perform initial health check and log application details
    try {
        logger.info('🔍 Performing initial application health check...');

        // Database health check
        let dbStatus = 'error';
        let dbLatency = 0;

        if (mongoose.connection.readyState === 1) {
            const dbStart = process.hrtime();
            await mongoose.connection.db.admin().ping();
            dbStatus = 'connected';
            const dbEnd = process.hrtime(dbStart);
            dbLatency = (dbEnd[0] * 1000 + dbEnd[1] / 1000000).toFixed(2);
        } else {
            dbStatus = 'disconnected';
        }

        // System information
        const memoryInfo = process.memoryUsage();
        const totalMemoryMB = (memoryInfo.heapTotal / 1024 / 1024).toFixed(2);
        const usedMemoryMB = (memoryInfo.heapUsed / 1024 / 1024).toFixed(2);
        const freeMemoryMB = (totalMemoryMB - usedMemoryMB).toFixed(2);

        // Log comprehensive application status        // Keep emojis for health check logs as per requirements
        logger.info('📊 Application Health Status:');
        logger.info(`   🗄️  Database: ${dbStatus === 'connected' ? '✅ Connected' : '❌ Disconnected'} (${dbLatency}ms)`);
        logger.info(`   🧠 Memory Usage: ${usedMemoryMB}MB / ${totalMemoryMB}MB (${freeMemoryMB}MB free)`);
        logger.info(`   ⚡ Node Version: ${process.version}`);
        logger.info(`   🖥️  Platform: ${process.platform} (${process.arch})`);
        logger.info(`   🌍 Environment: ${process.env.NODE_ENV}`);
        logger.info(`   ⏱️  Uptime: ${Math.floor(process.uptime())}s`);

        if (dbStatus === 'connected') {
            logger.info('🎉 All systems operational!');
        } else {
            logger.warn('⚠️  Database connection issues detected!');
        }
    } catch (error) {
        // Keep emojis for error logs in health check as per requirements
        logger.error('❌ Health check failed during setup:', error.message);
    }

    logger.info('✅ Health routes registered: GET /health and GET /api/v1/health');
};

/**
 * @desc    Get Redis cache stats
 * @route   GET /api/v1/cache/stats
 * @access  Admin only
 */
const getCacheStats = asyncHandler(async (req, res, next) => {
    try {
        // Get Redis server info through appMiddleware
        const redisClient = require('../middleware/app.middleware').redisClient;

        if (!redisClient || !redisClient.isReady) {
            return res.status(503).json({
                success: false,
                message: 'Redis cache is not available',
                meta: {
                    timestamp: new Date().toISOString()
                }
            });
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

        // Create a structured stats object
        const cacheStats = {
            success: true,
            timestamp: new Date().toISOString(),
            cacheHitRate: parseFloat(cacheHitRate), // Pre-calculated cache hit rate
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

        logger.info('Cache stats retrieved');
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
 * @desc    Clear Redis cache
 * @route   DELETE /api/v1/cache
 * @access  Admin only
 */
const clearCache = asyncHandler(async (req, res, next) => {
    try {
        await cache.flush();
        logger.info('Cache cleared successfully');
        res.status(200).json({
            success: true,
            message: 'Cache cleared successfully',
            meta: {
                timestamp: new Date().toISOString()
            }
        });
    } catch (error) {
        logger.error('Error clearing cache:', error);
        return next(error);
    }
});

/**
 * @desc    Get logs from database with pagination and filtering
 * @route   GET /api/v1/logs
 * @access  Admin only
 */
const getLogs = asyncHandler(async (req, res, next) => {
    try {
        // Parse filters and options using the universal filter system
        const {filters, options} = parseFilters(req.query);

        // Ensure logs are always ordered by newest first when pagination is applied
        const enforcedSort = {createdAt: -1, _id: -1};
        if (options.sort && Object.keys(options.sort).length > 0) {
            for (const [field, direction] of Object.entries(options.sort)) {
                if (field !== 'createdAt' && field !== '_id') {
                    enforcedSort[field] = direction;
                }
            }
        }
        options.sort = enforcedSort;

        // Apply the filters to get logs
        const logs = await applyFilters(Log, filters, options);

        // Get total count for pagination metadata
        const totalLogs = await Log.countDocuments(filters);

        // Get filter summary for response metadata
        const filterSummary = getFilterSummary(filters, options);

        logger.info(`Logs retrieved: ${logs.length} logs on page ${filterSummary.pagination?.page || 1}${!filterSummary.pagination ? ' (all logs)' : ''}`);

        res.status(200).json({
            success: true,
            message: 'Logs retrieved successfully',
            logs,
            meta: {
                count: logs.length,
                totalLogs,
                pagination: filterSummary.pagination ? {
                    page: filterSummary.pagination.page,
                    limit: filterSummary.pagination.limit,
                    totalPages: Math.ceil(totalLogs / filterSummary.pagination.limit),
                    hasNextPage: filterSummary.pagination.page < Math.ceil(totalLogs / filterSummary.pagination.limit),
                    hasPrevPage: filterSummary.pagination.page > 1
                } : null,
                filters: filterSummary,
                timestamp: new Date().toISOString()
            }
        });
    } catch (error) {
        logger.error('Error retrieving logs:', error);
        return next(error);
    }
});

/**
 * @desc    Get a single log by ID
 * @route   GET /api/v1/logs/:id
 * @access  Admin only
 */
const getLogById = asyncHandler(async (req, res, next) => {
    try {
        const {id} = req.params;        // Validate ObjectId format
        if (!mongoose.Types.ObjectId.isValid(id)) {
            return res.status(400).json({
                success: false, message: 'Invalid ObjectId format'
            });
        }

        // Find log by ID
        const log = await Log.findById(id);

        if (!log) {
            return res.status(404).json({
                success: false, message: 'Log not found'
            });
        }
        logger.info(`Log retrieved by ID: ${id}`);
        res.status(200).json({
            success: true,
            message: 'Log retrieved successfully',
            log: log,
            meta: {
                timestamp: new Date().toISOString()
            }
        });
    } catch (error) {
        logger.error('Error retrieving log by ID:', error);
        return next(error);
    }
});

/**
 * @desc    Get log statistics - supports optional userId filtering
 * @route   GET /api/v1/logs/stats
 * @route   GET /api/v1/logs/stats?userId=<userId>
 * @access  Admin only
 */
const getLogStats = asyncHandler(async (req, res, next) => {
    try {
        // Extract userId filter from query params if provided
        const {userId} = req.query;

        // Log the request with filtering info
        logger.info(`Retrieving log statistics${userId ? ` for user: ${userId}` : ' for all users'}`);

        // Base filter - will be applied to all queries
        const baseFilter = {};
        if (userId) {
            // Validate userId format if provided
            if (!mongoose.Types.ObjectId.isValid(userId)) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid userId format. Must be a valid ObjectId.'
                });
            }

            // Check if user exists (optional performance optimization)
            // Note: We don't fail if user doesn't exist, just return empty stats
            baseFilter.userId = new mongoose.Types.ObjectId(userId);
        }

        // Helper function to create match stages for aggregation pipelines
        const createMatchStage = (additionalCriteria = {}) => {
            return {
                $match: {
                    ...baseFilter, // Use baseFilter consistently
                    ...additionalCriteria
                }
            };
        };

        // Helper function for status code categorization (reusable)
        const getStatusCodeCategorization = () => ({
            $switch: {
                branches: [
                    {case: {$and: [{$gte: ['$statusCode', 200]}, {$lt: ['$statusCode', 300]}]}, then: 'Success (2xx)'},
                    {case: {$and: [{$gte: ['$statusCode', 300]}, {$lt: ['$statusCode', 400]}]}, then: 'Redirect (3xx)'},
                    {
                        case: {$and: [{$gte: ['$statusCode', 400]}, {$lt: ['$statusCode', 500]}]},
                        then: 'Client Error (4xx)'
                    },
                    {case: {$gte: ['$statusCode', 500]}, then: 'Server Error (5xx)'}
                ],
                default: 'Other'
            }
        });

        // Centralized date calculations for consistency
        const now = new Date();
        const startOfDay = new Date();
        startOfDay.setHours(0, 0, 0, 0);

        const startOfWeek = new Date();
        startOfWeek.setDate(startOfWeek.getDate() - 7);

        const startOfMonth = new Date();
        startOfMonth.setDate(startOfMonth.getDate() - 30);

        // Historical comparison periods
        const yesterday = new Date(startOfDay);
        yesterday.setDate(yesterday.getDate() - 1);

        const lastWeek = new Date(startOfWeek);
        lastWeek.setDate(lastWeek.getDate() - 7);

        // Last hour for throughput metrics
        const lastHour = new Date(now.getTime() - 60 * 60 * 1000);

        // Query execution tracking
        let queryCount = 0;
        const incrementQueryCount = () => ++queryCount;

        // Basic counts with user filtering
        const totalLogs = await Log.countDocuments(baseFilter);
        incrementQueryCount();
        const logsToday = await Log.countDocuments({...baseFilter, timestamp: {$gte: startOfDay}});
        incrementQueryCount();
        const logsThisWeek = await Log.countDocuments({...baseFilter, timestamp: {$gte: startOfWeek}});
        incrementQueryCount();
        const logsThisMonth = await Log.countDocuments({...baseFilter, timestamp: {$gte: startOfMonth}});
        incrementQueryCount();

        // Error statistics (status codes >= 400)
        const errorQuery = {
            ...baseFilter,
            statusCode: {$gte: 400}
        };

        const totalErrors = await Log.countDocuments(errorQuery);
        const errorsToday = await Log.countDocuments({
            timestamp: {$gte: startOfDay},
            ...errorQuery
        });
        const errorsThisWeek = await Log.countDocuments({
            timestamp: {$gte: startOfWeek},
            ...errorQuery
        });

        // Warning statistics (status codes 300-399)
        const warningQuery = {
            ...baseFilter,
            statusCode: {$gte: 300, $lt: 400}
        };

        const totalWarnings = await Log.countDocuments(warningQuery);
        const warningsToday = await Log.countDocuments({
            timestamp: {$gte: startOfDay},
            ...warningQuery
        });

        // Success statistics
        const successQuery = {...baseFilter, statusCode: {$gte: 200, $lt: 300}};
        const successesToday = await Log.countDocuments({
            timestamp: {$gte: startOfDay},
            ...successQuery
        });

        // Get last entries
        const lastError = await Log.findOne(errorQuery).sort({timestamp: -1});
        const lastWarning = await Log.findOne(warningQuery).sort({timestamp: -1});
        const lastLog = await Log.findOne(baseFilter).sort({timestamp: -1});

        // Status code categories breakdown - FIXED: Now uses helper for consistency
        const statusCodeCategoryStats = await Log.aggregate([
            createMatchStage({
                statusCode: {$exists: true}
            }),
            {
                $group: {
                    _id: getStatusCodeCategorization(),
                    count: {$sum: 1}
                }
            },
            {$sort: {count: -1}}
        ]);

        // HTTP status code breakdown - Uses different format for compatibility
        const statusCodeStats = await Log.aggregate([
            createMatchStage({statusCode: {$exists: true}}),
            {
                $group: {
                    _id: {
                        $switch: {
                            branches: [
                                {
                                    case: {$and: [{$gte: ['$statusCode', 200]}, {$lt: ['$statusCode', 300]}]},
                                    then: '2xx-Success'
                                },
                                {
                                    case: {$and: [{$gte: ['$statusCode', 300]}, {$lt: ['$statusCode', 400]}]},
                                    then: '3xx-Redirect'
                                },
                                {
                                    case: {$and: [{$gte: ['$statusCode', 400]}, {$lt: ['$statusCode', 500]}]},
                                    then: '4xx-Client Error'
                                },
                                {case: {$gte: ['$statusCode', 500]}, then: '5xx-Server Error'}
                            ],
                            default: 'Other'
                        }
                    },
                    count: {$sum: 1},
                    avgResponseTime: {$avg: '$responseTime'}
                }
            },
            {$sort: {count: -1}}
        ]);

        // Request method breakdown
        const methodStats = await Log.aggregate([
            createMatchStage({method: {$exists: true}}),
            {
                $group: {
                    _id: '$method',
                    count: {$sum: 1},
                    avgResponseTime: {$avg: '$responseTime'}
                }
            },
            {$sort: {count: -1}}
        ]);

        // Recent activity (hourly breakdown for last 24 hours)
        const recentActivity = await Log.aggregate([
            createMatchStage({timestamp: {$gte: startOfDay}}),
            {
                $group: {
                    _id: {
                        hour: {$hour: '$timestamp'}
                    },
                    count: {$sum: 1},
                    errors: {
                        $sum: {
                            $cond: [
                                {$gte: ['$statusCode', 400]},
                                1,
                                0
                            ]
                        }
                    }
                }
            },
            {$sort: {'_id.hour': 1}}
        ]);

        // Top error endpoints
        const topErrorEndpoints = await Log.aggregate([
            createMatchStage({
                timestamp: {$gte: startOfWeek},
                statusCode: {$gte: 400}
            }),
            {
                $group: {
                    _id: {
                        url: '$url',
                        method: '$method',
                        statusCode: '$statusCode'
                    },
                    count: {$sum: 1},
                    avgResponseTime: {$avg: '$responseTime'}
                }
            },
            {$sort: {count: -1}},
            {$limit: 10}
        ]);

        // Performance metrics
        const performanceStats = await Log.aggregate([
            createMatchStage({
                responseTime: {$exists: true},
                timestamp: {$gte: startOfDay}
            }),
            {
                $group: {
                    _id: null,
                    avgResponseTime: {$avg: '$responseTime'},
                    minResponseTime: {$min: '$responseTime'},
                    maxResponseTime: {$max: '$responseTime'},
                    totalRequests: {$sum: 1}
                }
            }
        ]);

        // Top user agents (for tracking different clients)
        const topUserAgents = await Log.aggregate([
            createMatchStage({
                userAgent: {$exists: true},
                timestamp: {$gte: startOfWeek}
            }),
            {
                $group: {
                    _id: '$userAgent',
                    count: {$sum: 1}
                }
            },
            {$sort: {count: -1}},
            {$limit: 5}
        ]);

        // Top IP addresses
        const topIPs = await Log.aggregate([
            createMatchStage({
                ip: {$exists: true},
                timestamp: {$gte: startOfDay}
            }),
            {
                $group: {
                    _id: '$ip',
                    count: {$sum: 1},
                    uniqueEndpoints: {$addToSet: '$url'}
                }
            },
            {
                $addFields: {
                    uniqueEndpointsCount: {$size: '$uniqueEndpoints'}
                }
            },
            {$sort: {count: -1}},
            {$limit: 10},
            {
                $project: {
                    _id: 1,
                    count: 1,
                    uniqueEndpointsCount: 1
                }
            }
        ]);

        // === ENHANCED ROBUST STATISTICS ===

        // 1. Response Time Percentiles & Distribution - FIXED: Now includes user filtering
        const responseTimePercentiles = await Log.aggregate([
            createMatchStage({
                responseTime: {$exists: true},
                timestamp: {$gte: startOfDay}
            }),
            {
                $group: {
                    _id: null,
                    responseTimes: {$push: '$responseTime'}
                }
            },
            {
                $project: {
                    _id: 0,
                    p50: {
                        $arrayElemAt: [{
                            $sortArray: {
                                input: '$responseTimes',
                                sortBy: 1
                            }
                        }, {$floor: {$multiply: [{$size: '$responseTimes'}, 0.5]}}]
                    },
                    p90: {
                        $arrayElemAt: [{
                            $sortArray: {
                                input: '$responseTimes',
                                sortBy: 1
                            }
                        }, {$floor: {$multiply: [{$size: '$responseTimes'}, 0.9]}}]
                    },
                    p95: {
                        $arrayElemAt: [{
                            $sortArray: {
                                input: '$responseTimes',
                                sortBy: 1
                            }
                        }, {$floor: {$multiply: [{$size: '$responseTimes'}, 0.95]}}]
                    },
                    p99: {
                        $arrayElemAt: [{
                            $sortArray: {
                                input: '$responseTimes',
                                sortBy: 1
                            }
                        }, {$floor: {$multiply: [{$size: '$responseTimes'}, 0.99]}}]
                    }
                }
            }
        ]);

        // Response time distribution buckets
        const responseTimeDistribution = await Log.aggregate([
            createMatchStage({
                responseTime: {$exists: true},
                timestamp: {$gte: startOfDay}
            }),
            {
                $group: {
                    _id: {
                        $switch: {
                            branches: [
                                {case: {$lt: ['$responseTime', 100]}, then: '0-100ms'},
                                {case: {$lt: ['$responseTime', 500]}, then: '100-500ms'},
                                {case: {$lt: ['$responseTime', 1000]}, then: '500ms-1s'},
                                {case: {$lt: ['$responseTime', 5000]}, then: '1-5s'},
                                {case: {$gte: ['$responseTime', 5000]}, then: '5s+'}
                            ],
                            default: 'unknown'
                        }
                    },
                    count: {$sum: 1},
                    avgResponseTime: {$avg: '$responseTime'}
                }
            },
            {$sort: {'_id': 1}}
        ]);

        // 2. Time-based Trends & Comparisons (using centralized date calculations)
        // Previous period comparisons - uses baseFilter consistently
        const logsYesterday = await Log.countDocuments({
            ...baseFilter,
            timestamp: {$gte: yesterday, $lt: startOfDay}
        });
        const logsLastWeek = await Log.countDocuments({
            ...baseFilter,
            timestamp: {$gte: lastWeek, $lt: startOfWeek}
        });

        const errorsYesterday = await Log.countDocuments({
            ...baseFilter,
            timestamp: {$gte: yesterday, $lt: startOfDay},
            statusCode: {$gte: 400}
        });
        const errorsLastWeek = await Log.countDocuments({
            ...baseFilter,
            timestamp: {$gte: lastWeek, $lt: startOfWeek},
            statusCode: {$gte: 400}
        });

        // Calculate trends (percentage change)
        const logsTrend = {
            daily: logsYesterday > 0 ? ((logsToday - logsYesterday) / logsYesterday * 100).toFixed(2) : 'N/A',
            weekly: logsLastWeek > 0 ? ((logsThisWeek - logsLastWeek) / logsLastWeek * 100).toFixed(2) : 'N/A'
        };

        const errorsTrend = {
            daily: errorsYesterday > 0 ? ((errorsToday - errorsYesterday) / errorsYesterday * 100).toFixed(2) : 'N/A',
            weekly: errorsLastWeek > 0 ? ((errorsThisWeek - errorsLastWeek) / errorsLastWeek * 100).toFixed(2) : 'N/A'
        };

        // 3. Peak Traffic Analysis
        const peakTrafficHours = await Log.aggregate([
            createMatchStage({timestamp: {$gte: startOfWeek}}),
            {
                $group: {
                    _id: {$hour: '$timestamp'},
                    count: {$sum: 1},
                    avgResponseTime: {$avg: '$responseTime'},
                    errors: {
                        $sum: {
                            $cond: [{$gte: ['$statusCode', 400]}, 1, 0]
                        }
                    }
                }
            },
            {$sort: {count: -1}},
            {$limit: 5}
        ]);

        // Weekend vs Weekday patterns
        const weekendVsWeekday = await Log.aggregate([
            createMatchStage({timestamp: {$gte: startOfMonth}}),
            {
                $group: {
                    _id: {
                        $cond: [
                            {$in: [{$dayOfWeek: '$timestamp'}, [1, 7]]}, // Sunday = 1, Saturday = 7
                            'weekend',
                            'weekday'
                        ]
                    },
                    count: {$sum: 1},
                    avgResponseTime: {$avg: '$responseTime'},
                    errors: {
                        $sum: {
                            $cond: [{$gte: ['$statusCode', 400]}, 1, 0]
                        }
                    }
                }
            }
        ]);

        // 4. Security & Anomaly Detection - FIXED: Now includes user filtering
        const suspiciousActivity = await Log.aggregate([
            createMatchStage({
                timestamp: {$gte: startOfDay},
                $or: [
                    {statusCode: {$in: [401, 403, 429]}},
                    {url: {$regex: /(login|auth|admin)/i}}
                ]
            }),
            {
                $group: {
                    _id: '$ip',
                    failedAttempts: {$sum: 1},
                    endpoints: {$addToSet: '$url'},
                    statusCodes: {$addToSet: '$statusCode'},
                    lastAttempt: {$max: '$timestamp'}
                }
            },
            {
                $match: {failedAttempts: {$gte: 3}}
            },
            {$sort: {failedAttempts: -1}},
            {$limit: 10}
        ]);

        // Rate limiting violations (429 status codes) - FIXED: Now includes user filtering
        const rateLimitViolations = await Log.countDocuments({
            ...baseFilter,
            timestamp: {$gte: startOfDay},
            statusCode: 429
        });

        // New vs returning IPs analysis - FIXED: Now includes user filtering
        const ipAnalysis = await Log.aggregate([
            createMatchStage({
                ip: {$exists: true},
                timestamp: {$gte: startOfDay}
            }),
            {
                $group: {
                    _id: '$ip',
                    firstSeen: {$min: '$timestamp'},
                    lastSeen: {$max: '$timestamp'},
                    requestCount: {$sum: 1},
                    uniqueEndpoints: {$addToSet: '$url'}
                }
            },
            {
                $group: {
                    _id: null,
                    totalUniqueIPs: {$sum: 1},
                    newIPs: {
                        $sum: {
                            $cond: [{$gte: ['$firstSeen', startOfDay]}, 1, 0]
                        }
                    },
                    returningIPs: {
                        $sum: {
                            $cond: [{$lt: ['$firstSeen', startOfDay]}, 1, 0]
                        }
                    },
                    avgRequestsPerIP: {$avg: '$requestCount'}
                }
            }
        ]);

        // 5. Enhanced Performance Metrics - FIXED: Now includes user filtering
        const slowestEndpoints = await Log.aggregate([
            createMatchStage({
                responseTime: {$exists: true},
                timestamp: {$gte: startOfDay}
            }),
            {
                $group: {
                    _id: {
                        url: '$url',
                        method: '$method'
                    },
                    avgResponseTime: {$avg: '$responseTime'},
                    maxResponseTime: {$max: '$responseTime'},
                    count: {$sum: 1}
                }
            },
            {$match: {count: {$gte: 5}}}, // Only endpoints with significant traffic
            {$sort: {avgResponseTime: -1}},
            {$limit: 10}
        ]);

        // Throughput metrics (requests per minute over last hour) - FIXED: Now includes user filtering
        const throughputMetrics = await Log.aggregate([
            createMatchStage({
                timestamp: {
                    $gte: lastHour // Use centralized date calculation
                }
            }),
            {
                $group: {
                    _id: {
                        minute: {$minute: '$timestamp'},
                        hour: {$hour: '$timestamp'}
                    },
                    requestsPerMinute: {$sum: 1}
                }
            },
            {
                $group: {
                    _id: null,
                    avgRequestsPerMinute: {$avg: '$requestsPerMinute'},
                    maxRequestsPerMinute: {$max: '$requestsPerMinute'},
                    minRequestsPerMinute: {$min: '$requestsPerMinute'}
                }
            }
        ]);

        // 6. Business Intelligence Metrics - FIXED: Now includes user filtering
        const endpointPopularity = await Log.aggregate([
            createMatchStage({
                url: {$exists: true},
                timestamp: {$gte: startOfWeek}
            }),
            {
                $group: {
                    _id: '$url',
                    count: {$sum: 1},
                    uniqueIPs: {$addToSet: '$ip'},
                    avgResponseTime: {$avg: '$responseTime'},
                    successRate: {
                        $avg: {
                            $cond: [{$lt: ['$statusCode', 400]}, 1, 0]
                        }
                    }
                }
            },
            {
                $addFields: {
                    uniqueIPCount: {$size: '$uniqueIPs'}
                }
            },
            {$sort: {count: -1}},
            {$limit: 15},
            {
                $project: {
                    _id: 1,
                    count: 1,
                    uniqueIPCount: 1,
                    avgResponseTime: {$round: ['$avgResponseTime', 2]},
                    successRate: {$round: [{$multiply: ['$successRate', 100]}, 2]}
                }
            }
        ]);

        // Content type distribution - FIXED: Now includes user filtering
        const contentTypeDistribution = await Log.aggregate([
            createMatchStage({
                contentType: {$exists: true},
                timestamp: {$gte: startOfWeek}
            }),
            {
                $group: {
                    _id: '$contentType',
                    count: {$sum: 1},
                    avgResponseTime: {$avg: '$responseTime'}
                }
            },
            {$sort: {count: -1}},
            {$limit: 10}
        ]);

        // 7. User Session Analysis (if userId exists) - FIXED: Now includes user filtering
        const userSessionStats = await Log.aggregate([
            createMatchStage({
                userId: {$exists: true},
                timestamp: {$gte: startOfDay}
            }),
            {
                $group: {
                    _id: '$userId',
                    maxTime: {$max: '$timestamp'},
                    minTime: {$min: '$timestamp'},
                    requestCount: {$sum: 1},
                    uniqueEndpoints: {$addToSet: '$url'},
                    errorCount: {
                        $sum: {
                            $cond: [{$gte: ['$statusCode', 400]}, 1, 0]
                        }
                    }
                }
            },
            {
                $addFields: {
                    sessionDuration: {$subtract: [{$toLong: "$maxTime"}, {$toLong: "$minTime"}]}
                }
            },
            {
                $group: {
                    _id: null,
                    totalActiveSessions: {$sum: 1},
                    avgSessionDuration: {$avg: '$sessionDuration'},
                    avgRequestsPerSession: {$avg: '$requestCount'},
                    avgErrorsPerSession: {$avg: '$errorCount'}
                }
            }
        ]);

        // 8. Health & Operational Metrics - FIXED: Now includes user filtering
        const serviceAvailability = await Log.aggregate([
            createMatchStage({
                timestamp: {$gte: startOfDay},
                url: {$regex: /health|ping/i}
            }),
            {
                $group: {
                    _id: null,
                    totalHealthChecks: {$sum: 1},
                    successfulHealthChecks: {
                        $sum: {
                            $cond: [{$lt: ['$statusCode', 400]}, 1, 0]
                        }
                    }
                }
            },
            {
                $project: {
                    _id: 0,
                    totalHealthChecks: 1,
                    successfulHealthChecks: 1,
                    availabilityPercentage: {
                        $round: [
                            {
                                $multiply: [
                                    {$divide: ['$successfulHealthChecks', '$totalHealthChecks']},
                                    100
                                ]
                            },
                            2
                        ]
                    }
                }
            }
        ]);

        // Error clustering (group similar errors) - FIXED: Now includes user filtering
        const errorClustering = await Log.aggregate([
            createMatchStage({
                statusCode: {$gte: 400},
                timestamp: {$gte: startOfWeek}
            }),
            {
                $group: {
                    _id: {
                        statusCode: '$statusCode',
                        url: '$url',
                        method: '$method'
                    },
                    count: {$sum: 1},
                    firstOccurrence: {$min: '$timestamp'},
                    lastOccurrence: {$max: '$timestamp'},
                    affectedIPs: {$addToSet: '$ip'}
                }
            },
            {
                $addFields: {
                    affectedIPCount: {$size: '$affectedIPs'},
                    errorDuration: {
                        $subtract: [{$toLong: "$lastOccurrence"}, {$toLong: "$firstOccurrence"}]
                    }
                }
            },
            {$sort: {count: -1}},
            {$limit: 10},
            {
                $project: {
                    _id: 1,
                    count: 1,
                    firstOccurrence: 1,
                    lastOccurrence: 1,
                    affectedIPCount: 1,
                    errorDurationMs: '$errorDuration'
                }
            }
        ]);

        // 9. Advanced User Agent Analysis - FIXED: Now includes user filtering
        const userAgentFamilies = await Log.aggregate([
            createMatchStage({
                userAgent: {$exists: true},
                timestamp: {$gte: startOfWeek}
            }),
            {
                $group: {
                    _id: {
                        $switch: {
                            branches: [
                                {
                                    case: {$regexMatch: {input: '$userAgent', regex: /mobile|android|iphone/i}},
                                    then: 'Mobile'
                                },
                                {case: {$regexMatch: {input: '$userAgent', regex: /bot|crawler|spider/i}}, then: 'Bot'},
                                {case: {$regexMatch: {input: '$userAgent', regex: /chrome/i}}, then: 'Chrome'},
                                {case: {$regexMatch: {input: '$userAgent', regex: /firefox/i}}, then: 'Firefox'},
                                {case: {$regexMatch: {input: '$userAgent', regex: /safari/i}}, then: 'Safari'},
                                {
                                    case: {$regexMatch: {input: '$userAgent', regex: /postman|insomnia|curl/i}},
                                    then: 'API Client'
                                }
                            ],
                            default: 'Other'
                        }
                    },
                    count: {$sum: 1},
                    uniqueIPs: {$addToSet: '$ip'},
                    avgResponseTime: {$avg: '$responseTime'}
                }
            },
            {
                $addFields: {
                    uniqueIPCount: {$size: '$uniqueIPs'}
                }
            },
            {$sort: {count: -1}},
            {
                $project: {
                    _id: 1,
                    count: 1,
                    uniqueIPCount: 1,
                    avgResponseTime: {$round: ['$avgResponseTime', 2]}
                }
            }
        ]);

        logger.info(`Ultra-comprehensive log statistics retrieved successfully${userId ? ` for user: ${userId}` : ' for all users'} (${totalLogs} logs analyzed)`);

        res.status(200).json({
            success: true,
            message: `Log statistics retrieved successfully${userId ? ` for user: ${userId}` : ' for all users'}`,
            stats: {
                // Core Overview
                overview: {
                    totalLogs,
                    logsToday,
                    logsThisWeek,
                    logsThisMonth,
                    logsYesterday,
                    logsLastWeek
                },

                // Trend Analysis
                trends: {
                    logs: logsTrend,
                    errors: errorsTrend
                },

                // Error tracking
                errors: {
                    total: totalErrors,
                    today: errorsToday,
                    thisWeek: errorsThisWeek,
                    yesterday: errorsYesterday,
                    lastWeek: errorsLastWeek,
                    lastError: lastError ? {
                        timestamp: lastError.timestamp,
                        url: lastError.url,
                        method: lastError.method,
                        statusCode: lastError.statusCode,
                        errorType: lastError.statusCode >= 500 ? `Server Error (${lastError.statusCode})` : `Client Error (${lastError.statusCode})`
                    } : null
                },

                // Warning tracking
                warnings: {
                    total: totalWarnings,
                    today: warningsToday,
                    lastWarning: lastWarning ? {
                        timestamp: lastWarning.timestamp,
                        url: lastWarning.url,
                        method: lastWarning.method,
                        statusCode: lastWarning.statusCode
                    } : null
                },

                // Success tracking
                successes: {
                    today: successesToday
                },

                // Performance Analytics
                performance: {
                    // Basic metrics
                    basic: performanceStats[0] || {
                        avgResponseTime: 0,
                        minResponseTime: 0,
                        maxResponseTime: 0,
                        totalRequests: 0
                    },

                    // Response time percentiles
                    percentiles: responseTimePercentiles[0] || {
                        p50: 0,
                        p90: 0,
                        p95: 0,
                        p99: 0
                    },

                    // Response time distribution
                    distribution: responseTimeDistribution || [],

                    // Slowest endpoints
                    slowestEndpoints: slowestEndpoints || [],

                    // Throughput metrics
                    throughput: throughputMetrics[0] || {
                        avgRequestsPerMinute: 0,
                        maxRequestsPerMinute: 0,
                        minRequestsPerMinute: 0
                    }
                },

                // Traffic Patterns
                trafficPatterns: {
                    peakHours: peakTrafficHours || [],
                    weekendVsWeekday: weekendVsWeekday || [],
                    recentActivity: recentActivity || []
                },

                // Security & Anomaly Detection
                security: {
                    suspiciousActivity: suspiciousActivity || [],
                    rateLimitViolations: rateLimitViolations || 0,
                    ipAnalysis: ipAnalysis[0] || {
                        totalUniqueIPs: 0,
                        newIPs: 0,
                        returningIPs: 0,
                        avgRequestsPerIP: 0
                    }
                },

                // Business Intelligence
                businessIntelligence: {
                    endpointPopularity: endpointPopularity || [],
                    contentTypeDistribution: contentTypeDistribution || [],
                    userSessions: userSessionStats[0] || {
                        totalActiveSessions: 0,
                        avgSessionDuration: 0,
                        avgRequestsPerSession: 0,
                        avgErrorsPerSession: 0
                    }
                },

                // Health & Operations
                operations: {
                    serviceAvailability: serviceAvailability[0] || {
                        totalHealthChecks: 0,
                        successfulHealthChecks: 0,
                        availabilityPercentage: 0
                    },
                    errorClustering: errorClustering || []
                },

                // Breakdowns & Classifications
                breakdowns: {
                    statusCodeCategories: statusCodeCategoryStats || [],
                    statusCodes: statusCodeStats || [],
                    methods: methodStats || [],
                    userAgentFamilies: userAgentFamilies || []
                },

                // Top Lists
                topLists: {
                    errorEndpoints: topErrorEndpoints || [],
                    userAgents: topUserAgents || [],
                    ipAddresses: topIPs || []
                },

                // Meta information
                meta: {
                    lastLog: lastLog ? {
                        timestamp: lastLog.timestamp,
                        url: lastLog.url,
                        method: lastLog.method,
                        statusCode: lastLog.statusCode
                    } : null,

                    // Time ranges for context
                    timeRanges: {
                        startOfDay: startOfDay.toISOString(),
                        startOfWeek: startOfWeek.toISOString(),
                        startOfMonth: startOfMonth.toISOString(),
                        yesterday: yesterday.toISOString(),
                        lastWeek: lastWeek.toISOString(),
                        now: now.toISOString()
                    },

                    // Statistics generation metadata
                    generated: {
                        timestamp: now.toISOString(),
                        totalQueries: queryCount, // Dynamic query count
                        processingNote: `Comprehensive log statistics with real metrics${userId ? ' for specific user' : ' for all users'}`,
                        generatedBy: 'LogStats API',
                        version: '1.2.0', // Updated version to reflect optimizations
                        environment: process.env.NODE_ENV,
                        scope: userId ? 'user-specific' : 'all-users',
                        userId: userId || null
                    }
                },

                // Analysis summary - derived from actual log data
                summary: {
                    // Derive error rate from existing data
                    errorRate: totalErrors > 0 && totalLogs > 0 ?
                        parseFloat(((totalErrors / totalLogs) * 100).toFixed(2)) : 0,

                    // Performance summary
                    avgResponseTime: performanceStats[0]?.avgResponseTime || 0,

                    // Traffic summary 
                    dailyRequestRate: logsToday / 24, // requests per hour

                    // Top client
                    topClient: userAgentFamilies[0]?._id || 'Unknown',

                    // System health derived from existing data
                    systemHealth: serviceAvailability[0]?.availabilityPercentage || 100
                },

                // Derived statistics from error metrics
                errorAnalysis: {
                    errorRatio: totalErrors > 0 && totalLogs > 0 ?
                        (totalErrors / totalLogs).toFixed(4) : 0,
                    errorTrendToday: errorsYesterday > 0 ?
                        ((errorsToday - errorsYesterday) / errorsYesterday).toFixed(2) : 0,
                    mostErroredEndpoint: topErrorEndpoints[0]?._id.url || 'None'
                }
            },
            meta: {
                userId: userId || null,
                scope: userId ? 'user-specific' : 'all-users',
                timestamp: new Date().toISOString()
            }
        });
    } catch (error) {
        logger.error('Error retrieving log statistics:', error);
        return next(error);
    }
});

/**
 * @desc    Clear logs from database
 * @route   DELETE /api/v1/logs
 * @access  Admin only
 */
const clearLogs = asyncHandler(async (req, res, next) => {
    try {
        const {
            olderThan, confirm
        } = req.body;

        // Safety check - require confirmation
        if (!confirm) {
            return res.status(400).json({
                success: false, message: 'Confirmation required. Set confirm: true in request body.'
            });
        }

        // Build delete filters
        const deleteFilters = {};

        if (olderThan) {
            deleteFilters.timestamp = {$lt: new Date(olderThan)};
        }

        // If no specific filters, require date filter for safety
        if (!olderThan) {
            // Default to deleting logs older than 7 days
            const defaultOlderThan = new Date();
            defaultOlderThan.setDate(defaultOlderThan.getDate() - 7);
            deleteFilters.timestamp = {$lt: defaultOlderThan};
        }

        const deleteResult = await Log.deleteMany(deleteFilters);

        logger.info(`Logs cleared: ${deleteResult.deletedCount} logs deleted`, {
            filters: deleteFilters, deletedCount: deleteResult.deletedCount
        });

        res.status(200).json({
            success: true,
            message: `Successfully deleted ${deleteResult.deletedCount} logs`,
            meta: {
                deletedCount: deleteResult.deletedCount,
                filters: deleteFilters,
                timestamp: new Date().toISOString()
            }
        });
    } catch (error) {
        logger.error('Error clearing logs:', error);
        return next(error);
    }
});

/**
 * Load and compile email template
 * @param {string} templateName - Name of the template file (without .hbs extension)
 * @returns {Function} - Compiled handlebars template
 */
const loadTemplate = async (templateName) => {
    try {
        // Validate templateName is a string
        if (typeof templateName !== 'string') {
            logger.error(`Invalid template name type: ${typeof templateName}, value:`, templateName);
            throw new AppError(`Template name must be a string, received ${typeof templateName}`, 400);
        }

        // Sanitize template name to prevent path traversal
        const sanitizedTemplateName = templateName.replace(/[^a-zA-Z0-9-_]/g, '');
        if (sanitizedTemplateName !== templateName) {
            logger.error(`Invalid template name format: ${templateName}`);
            throw new AppError(`Invalid template name format`, 400);
        }

        // Check cache first
        if (emailTemplatesCache.has(templateName)) {
            return emailTemplatesCache.get(templateName);
        }

        // Read template file
        const templatePath = path.join(__dirname, '../templates/emails', `${templateName}.hbs`);
        const templateContent = await fs.readFile(templatePath, 'utf8');

        // Compile template
        const compiledTemplate = handlebars.compile(templateContent);

        // Cache compiled template
        emailTemplatesCache.set(templateName, compiledTemplate);

        return compiledTemplate;
    } catch (error) {
        logger.error(`Failed to load email template "${templateName}":`, error);
        throw new AppError(`Email template "${templateName}" not found`, 500);
    }
};

/**
 * Send email using template
 * @param {Object} options - Email options
 * @param {string} options.to - Recipient email address
 * @param {string} options.subject - Email subject
 * @param {string} options.template - Template name
 * @param {Object} options.data - Template data
 * @param {string} [options.from] - Sender email (optional, uses default)
 * @param {Object} [transporter] - Email transporter (passed from server)
 * @returns {Promise<Object>} - Email send result
 */
const sendEmail = async ({to, subject, template, data, from}, transporter = null) => {
    try {
        if (!transporter) {
            logger.warn(`Email transporter not provided, skipping email to ${to} with template ${template}`);
            return {success: false, message: 'Email transporter not available'};
        }

        // Load and render template
        const compiledTemplate = await loadTemplate(template);
        const htmlContent = compiledTemplate({
            ...data,
            appName: process.env.APP_NAME,
            appUrl: process.env.APP_URL,
            currentYear: new Date().getFullYear()
        });

        // Prepare email options
        const mailOptions = {
            from: from || process.env.EMAIL_FROM, to, subject, html: htmlContent
        };

        // Send email
        const result = await transporter.sendMail(mailOptions);

        logger.info(`Email sent successfully to ${to} using template ${template}`, {
            messageId: result.messageId, template, recipient: to
        });

        return {
            success: true, messageId: result.messageId, message: 'Email sent successfully'
        };

    } catch (error) {
        logger.error(`Failed to send email to ${to}:`, error);
        throw new AppError('Failed to send email', 500);
    }
};

/**
 * Clear template cache (useful for development)
 */
const clearTemplateCache = () => {
    emailTemplatesCache.clear();
};

/**
 * Initialize email service with SMTP configuration
 * @returns {Promise<Object|null>} - The email transporter or null if not configured
 */
const initializeEmailService = async () => {
    try {
        // Check if email is enabled via environment variables
        if (!process.env.EMAIL_ENABLED || process.env.EMAIL_ENABLED === 'false') {
            logger.warn('Email service is disabled via EMAIL_ENABLED environment variable');
            return null;
        }

        // Validate required environment variables
        const requiredVars = ['EMAIL_HOST', 'EMAIL_PORT', 'EMAIL_USER', 'EMAIL_PASS'];
        const missingVars = requiredVars.filter(varName => !process.env[varName]);

        if (missingVars.length > 0) {
            logger.warn(`Email service not configured. Missing environment variables: ${missingVars.join(', ')}`);
            return null;
        }

        // Create SMTP transporter
        emailTransporter = nodemailer.createTransport({
            host: process.env.EMAIL_HOST,
            port: parseInt(process.env.EMAIL_PORT),
            secure: process.env.EMAIL_PORT === '465', // true for 465, false for other ports
            auth: {
                user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS
            },
            tls: {
                rejectUnauthorized: process.env.NODE_ENV === 'production'
            }
        });        // Verify SMTP connection
        await emailTransporter.verify();
        isEmailConfigured = true;
        // Email service success message will be logged once from server startup
        return emailTransporter;

    } catch (error) {
        logger.error('Failed to initialize email service:', error);
        isEmailConfigured = false;
        return null;
    }
};

/**
 * Check if email service is properly configured
 * @returns {boolean} true if email is ready
 */
const isEmailReady = () => {
    return isEmailConfigured && emailTransporter;
};

/**
 * Get email transporter instance
 * @returns {Object} Nodemailer transporter
 */
const getEmailTransporter = () => {
    return emailTransporter;
};

/**
 * @desc    Render email template for preview
 * @route   POST /api/v1/email/template/render
 * @access  Admin only
 */
const renderEmailTemplate = asyncHandler(async (req, res, next) => {
    try {
        const {template, data} = req.body;

        if (!template) {
            return res.status(400).json({
                success: false, message: 'Template name is required'
            });
        }

        // Load and render template
        const compiledTemplate = await loadTemplate(template);
        const htmlContent = compiledTemplate({
            ...data,
            appName: process.env.APP_NAME ,
            appUrl: process.env.APP_URL,
            currentYear: new Date().getFullYear()
        });

        logger.info(`Email template "${template}" rendered successfully`);
        res.status(200).json({
            success: true,
            message: `Email template "${template}" rendered successfully`,
            htmlContent,
            meta: {
                template,
                timestamp: new Date().toISOString()
            }
        });
    } catch (error) {
        logger.error('Error rendering email template:', error);
        return next(error);
    }
});

/**
 * @desc    Send test email
 * @route   POST /api/v1/email/test
 * @access  Admin only
 */
const sendTestEmail = asyncHandler(async (req, res, next) => {
    try {
        let {to, subject, template, data} = req.body;

        if (!to || !subject || !template) {
            return res.status(400).json({
                success: false, message: 'to, subject, and template are required'
            });
        }

        // Get email transporter
        const transporter = getEmailTransporter();
        if (!transporter) {
            return res.status(503).json({
                success: false, message: 'Email service is not configured'
            });
        }

        // Send the test email
        const result = await sendEmail({
            to, subject, template, data
        }, transporter);

        res.status(200).json({
            success: true,
            message: 'Test email sent successfully',
            result,
            meta: {
                timestamp: new Date().toISOString()
            }
        });
    } catch (error) {
        logger.error('Error sending test email:', error);
        return next(error);
    }
});

/**
 * GridFS bucket instance for app controller
 */
let gridFSBucket = null;
const bucketName = 'files';

/**
 * Initialize GridFS bucket
 */
const initializeGridFS = () => {
    if (!gridFSBucket && mongoose.connection.db) {
        gridFSBucket = new GridFSBucket(mongoose.connection.db, {
            bucketName: bucketName
        });
        logger.info('GridFS initialized in app controller');
    }
    return gridFSBucket;
};

/**
 * Get comprehensive file storage statistics (GridFS + Regular files)
 * @returns {Promise<Object>} - Storage statistics with breakdown
 */
const getGridFSStorageStats = async () => {
    try {
        initializeGridFS();

        // Debug: List all collections to see what's available
        const collections = await mongoose.connection.db.listCollections().toArray();
        const collectionNames = collections.map(c => c.name);
        logger.info('Available collections:', collectionNames);

        let regularFilesStats = {totalFiles: 0, totalSize: 0, averageSize: 0};
        let gridfsStats = {totalFiles: 0, totalSize: 0, averageSize: 0};

        // First, check for regular file collection (non-GridFS)
        if (collectionNames.includes('files')) {
            logger.info('Found regular files collection, counting documents...');
            try {
                const File = require('../models/file.model');

                // Get detailed breakdown of regular files
                const regularFiles = await File.aggregate([
                    {
                        $group: {
                            _id: null,
                            totalFiles: {$sum: 1},
                            totalSize: {$sum: {$ifNull: ['$size', 0]}}, // Handle null sizes
                            averageSize: {$avg: {$ifNull: ['$size', 0]}},
                            gridfsFiles: {
                                $sum: {
                                    $cond: [
                                        {$ne: ['$gridfsFileId', null]},
                                        1,
                                        0
                                    ]
                                }
                            },
                            inlineFiles: {
                                $sum: {
                                    $cond: [
                                        {$eq: ['$storageType', 'inline']},
                                        1,
                                        0
                                    ]
                                }
                            }
                        }
                    }
                ]);

                if (regularFiles && regularFiles[0]) {
                    regularFilesStats = regularFiles[0];
                    logger.info(`Regular files stats:`, regularFilesStats);

                    // Get additional file type breakdown
                    const fileTypeBreakdown = await File.aggregate([
                        {
                            $group: {
                                _id: '$type',
                                count: {$sum: 1},
                                totalSize: {$sum: {$ifNull: ['$size', 0]}}
                            }
                        },
                        {$sort: {count: -1}}
                    ]);

                    regularFilesStats.fileTypes = fileTypeBreakdown;
                    logger.info(`File type breakdown:`, fileTypeBreakdown);
                }
            } catch (error) {
                logger.warn('Error counting regular files:', error.message);
            }
        }

        // Then, try multiple possible GridFS collection names for additional files
        const possibleGridFSCollections = ['fs.files', 'files.files', 'uploads.files'];

        for (const collectionName of possibleGridFSCollections) {
            if (collectionNames.includes(collectionName)) {
                logger.info(`Found GridFS collection: ${collectionName}`);

                try {
                    const result = await mongoose.connection.db.collection(collectionName).aggregate([{
                        $group: {
                            _id: null,
                            totalFiles: {$sum: 1},
                            totalSize: {$sum: '$length'},
                            averageSize: {$avg: '$length'}
                        }
                    }]).toArray();

                    if (result && result[0] && result[0].totalFiles > 0) {
                        gridfsStats = result[0];
                        logger.info(`GridFS stats from ${collectionName}:`, gridfsStats);
                        break; // Found GridFS files, no need to check other collections
                    }
                } catch (error) {
                    logger.warn(`Error reading GridFS collection ${collectionName}:`, error.message);
                }
            }
        }

        // If no GridFS stats found with specific collections, try the default
        if (gridfsStats.totalFiles === 0) {
            logger.info(`Trying default GridFS collection: ${bucketName}.files`);
            try {
                const result = await mongoose.connection.db.collection(`${bucketName}.files`).aggregate([{
                    $group: {
                        _id: null,
                        totalFiles: {$sum: 1},
                        totalSize: {$sum: '$length'},
                        averageSize: {$avg: '$length'}
                    }
                }]).toArray();

                if (result && result[0]) {
                    gridfsStats = result[0];
                }
            } catch (error) {
                logger.warn(`Error reading default GridFS collection:`, error.message);
            }
        }

        // Combine stats and create comprehensive breakdown
        const combinedStats = {
            // Total across all storage types
            totalFiles: regularFilesStats.totalFiles + gridfsStats.totalFiles,
            totalSize: regularFilesStats.totalSize + gridfsStats.totalSize,
            averageSize: 0, // Will calculate below

            // Breakdown by storage type
            breakdown: {
                regular: {
                    totalFiles: regularFilesStats.totalFiles,
                    totalSize: regularFilesStats.totalSize,
                    averageSize: regularFilesStats.averageSize || 0,
                    inlineFiles: regularFilesStats.inlineFiles || 0,
                    gridfsLinkedFiles: regularFilesStats.gridfsFiles || 0,
                    fileTypes: regularFilesStats.fileTypes || []
                },
                gridfs: {
                    totalFiles: gridfsStats.totalFiles,
                    totalSize: gridfsStats.totalSize,
                    averageSize: gridfsStats.averageSize || 0
                }
            }
        };

        // Calculate combined average size
        if (combinedStats.totalFiles > 0) {
            combinedStats.averageSize = combinedStats.totalSize / combinedStats.totalFiles;
        }

        // Add human readable sizes
        const addHumanSize = (stats) => {
            if (stats.totalSize) {
                const sizeInMB = stats.totalSize / (1024 * 1024);
                stats.humanReadableSize = sizeInMB < 1 ?
                    `${(stats.totalSize / 1024).toFixed(2)} KB` :
                    `${sizeInMB.toFixed(2)} MB`;
            } else {
                stats.humanReadableSize = "0.00 MB";
            }
        };

        addHumanSize(combinedStats);
        addHumanSize(combinedStats.breakdown.regular);
        addHumanSize(combinedStats.breakdown.gridfs);

        logger.info('Final comprehensive file storage stats:', combinedStats);
        return combinedStats;
    } catch (error) {
        logger.error('Error getting file storage stats:', {error: error.message});
        throw error;
    }
};

// Query Filter Functions - Universal filtering capabilities for all data models

/**
 * Parse and validate filter parameters from query string
 * @param {Object} query - Express req.query object
 * @returns {Object} - Parsed filters and options
 */
const parseFilters = (query) => {
    const filters = {};
    const options = {
        sort: {},
        pagination: {},
        aggregation: []
    };

    // Date range filters
    if (query.startDate || query.endDate) {
        const dateFilter = {};
        if (query.startDate) {
            const startDate = new Date(query.startDate);
            if (!isNaN(startDate.getTime())) {
                dateFilter.$gte = startDate;
            }
        }
        if (query.endDate) {
            const endDate = new Date(query.endDate);
            if (!isNaN(endDate.getTime())) {
                // Add 1 day to include the entire end date
                endDate.setHours(23, 59, 59, 999);
                dateFilter.$lte = endDate;
            }
        }
        if (Object.keys(dateFilter).length > 0) {
            filters.createdAt = dateFilter;
        }
    }

    // Time period shortcuts
    if (query.period) {
        const now = new Date();
        let startDate;

        switch (query.period) {
            case '1h':
                startDate = new Date(now.getTime() - 60 * 60 * 1000);
                break;
            case '24h':
            case '1d':
                startDate = new Date(now.getTime() - 24 * 60 * 60 * 1000);
                break;
            case '7d':
            case '1w':
                startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
                break;
            case '30d':
            case '1m':
                startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
                break;
            case '90d':
            case '3m':
                startDate = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);
                break;
            case '1y':
                startDate = new Date(now.getTime() - 365 * 24 * 60 * 60 * 1000);
                break;
        }

        if (startDate) {
            filters.createdAt = {$gte: startDate};
        }
    }

    // Status code filters (for logs)
    if (query.statusCode) {
        if (query.statusCode.includes(',')) {
            // Multiple status codes
            const codes = query.statusCode.split(',').map(code => parseInt(code.trim())).filter(code => !isNaN(code));
            if (codes.length > 0) {
                filters.statusCode = {$in: codes};
            }
        } else if (query.statusCode.includes('-')) {
            // Range of status codes (e.g., "400-499")
            const [start, end] = query.statusCode.split('-').map(code => parseInt(code.trim()));
            if (!isNaN(start) && !isNaN(end)) {
                filters.statusCode = {$gte: start, $lte: end};
            }
        } else {
            // Single status code
            const code = parseInt(query.statusCode);
            if (!isNaN(code)) {
                filters.statusCode = code;
            }
        }
    }

    // HTTP method filters
    if (query.method) {
        if (query.method.includes(',')) {
            const methods = query.method.split(',').map(m => m.trim().toUpperCase());
            filters.method = {$in: methods};
        } else {
            filters.method = query.method.toUpperCase();
        }
    }

    // Status code filters (replacing level filters)
    if (query.statusCode) {
        if (query.statusCode.includes(',')) {
            const codes = query.statusCode.split(',').map(c => parseInt(c.trim()));
            filters.statusCode = {$in: codes};
        } else {
            filters.statusCode = parseInt(query.statusCode);
        }
    }

    // User role filters
    if (query.roles) {
        if (query.roles.includes(',')) {
            const roles = query.roles.split(',').map(r => r.trim().toUpperCase());
            filters.roles = {$in: roles};
        } else {
            // For single role, still use $in since roles is an array field
            filters.roles = {$in: [query.roles.toUpperCase()]};
        }
    }

    // Special handling for single role filter for backwards compatibility
    if (query.role && !query.roles) {
        filters.roles = {$in: [query.role.toUpperCase()]};
    }

    // User status filters
    if (query.active !== undefined) {
        filters.active = query.active === 'true';
    }

    // File type filters
    if (query.fileType) {
        if (query.fileType.includes(',')) {
            const types = query.fileType.split(',').map(t => t.trim().toLowerCase());
            filters.type = {$in: types};
        } else {
            filters.type = query.fileType.toLowerCase();
        }
    }

    // MIME type filters
    if (query.mimeType) {
        if (query.mimeType.includes(',')) {
            const types = query.mimeType.split(',').map(t => t.trim());
            filters.mimeType = {$in: types};
        } else {
            filters.mimeType = query.mimeType;
        }
    }

    // Tags filters (for files)
    if (query.tags) {
        if (query.tags.includes(',')) {
            const tags = query.tags.split(',').map(t => t.trim());
            filters.tags = {$in: tags};
        } else {
            filters.tags = query.tags;
        }
    }

    // File size filters
    if (query.minSize || query.maxSize) {
        const sizeFilter = {};
        if (query.minSize) {
            const minSize = parseInt(query.minSize);
            if (!isNaN(minSize)) {
                sizeFilter.$gte = minSize;
            }
        }
        if (query.maxSize) {
            const maxSize = parseInt(query.maxSize);
            if (!isNaN(maxSize)) {
                sizeFilter.$lte = maxSize;
            }
        }
        if (Object.keys(sizeFilter).length > 0) {
            filters.size = sizeFilter;
        }
    }

    // Response time filters
    if (query.minResponseTime || query.maxResponseTime) {
        const responseTimeFilter = {};
        if (query.minResponseTime) {
            const minTime = parseInt(query.minResponseTime);
            if (!isNaN(minTime)) {
                responseTimeFilter.$gte = minTime;
            }
        }
        if (query.maxResponseTime) {
            const maxTime = parseInt(query.maxResponseTime);
            if (!isNaN(maxTime)) {
                responseTimeFilter.$lte = maxTime;
            }
        }
        if (Object.keys(responseTimeFilter).length > 0) {
            filters.responseTime = responseTimeFilter;
        }
    }

    // IP address filters
    if (query.ip) {
        if (query.ip.includes(',')) {
            const ips = query.ip.split(',').map(ip => ip.trim());
            filters.ip = {$in: ips};
        } else {
            filters.ip = query.ip;
        }
    }

    // User ID filters
    if (query.userId) {
        if (mongoose.Types.ObjectId.isValid(query.userId)) {
            filters.userId = new mongoose.Types.ObjectId(query.userId);
        }
    }

    // Owner/Creator filters
    if (query.owner || query.createdBy) {
        const ownerField = query.owner || query.createdBy;
        if (mongoose.Types.ObjectId.isValid(ownerField)) {
            filters.owner = new mongoose.Types.ObjectId(ownerField);
            filters.createdBy = new mongoose.Types.ObjectId(ownerField);
        }
    }

    // URL pattern filters
    if (query.url) {
        filters.url = {$regex: query.url, $options: 'i'};
    }

    // Generic text search
    if (query.search) {
        const searchRegex = {$regex: query.search, $options: 'i'};
        filters.$or = [
            {url: searchRegex},
            {stack: searchRegex},
            {errorCode: searchRegex},
            {userAgent: searchRegex}
        ];
    }

    // Custom field filters (for any additional fields)
    Object.keys(query).forEach(key => {
        if (key.startsWith('filter_')) {
            const fieldName = key.replace('filter_', '');
            const value = query[key];

            // Handle different data types
            if (value === 'true' || value === 'false') {
                filters[fieldName] = value === 'true';
            } else if (!isNaN(value) && value.trim() !== '') {
                filters[fieldName] = parseFloat(value);
            } else if (mongoose.Types.ObjectId.isValid(value)) {
                filters[fieldName] = new mongoose.Types.ObjectId(value);
            } else if (value.includes(',')) {
                filters[fieldName] = {$in: value.split(',').map(v => v.trim())};
            } else {
                filters[fieldName] = value;
            }
        }
    });

    // Sorting
    if (query.sortBy) {
        const sortOrder = query.sortOrder === 'asc' ? 1 : -1;
        options.sort[query.sortBy] = sortOrder;
    } else {
        // Default sort by creation date (newest first)
        options.sort.createdAt = -1;
    }

    // Pagination
    if (query.limit) {
        const page = parseInt(query.page) || 1; // Default to page 1 if not provided
        const limit = parseInt(query.limit);
        
        // Validate pagination parameters
        if (page < 1 || limit < 1 || isNaN(page) || isNaN(limit)) {
            logger.warn(`Invalid pagination parameters: page=${query.page}, limit=${query.limit}. Skipping pagination to use smart loading.`);
            // Don't set pagination options - let smart pagination handle it
        } else {
            options.pagination = {
                skip: (page - 1) * limit,
                limit: limit // No limit cap - allow unlimited logs per page
            };
        }
    } else {
        // No pagination specified - smart pagination will be used
        options.pagination = {};
    }

    // Group by fields for aggregation
    if (query.groupBy) {
        const groupFields = query.groupBy.split(',').map(field => field.trim());
        options.aggregation.push({
            $group: {
                _id: groupFields.reduce((acc, field) => {
                    acc[field] = `$${field}`;
                    return acc;
                }, {}),
                count: {$sum: 1}
            }
        });
    }

    return {filters, options};
};

/**
 * Apply filters to a MongoDB query with smart pagination to avoid memory limits
 * @param {Object} model - Mongoose model
 * @param {Object} filters - Parsed filters
 * @param {Object} options - Query options
 * @returns {Promise} - Query result
 */
const applyFilters = async (model, filters, options) => {
    try {
        // If no pagination is specified, implement smart progressive loading
        if (!options.pagination.limit) {
            return await applySmartPagination(model, filters, options);
        }

        let query = model.find(filters);

        // Apply sorting
        if (Object.keys(options.sort).length > 0) {
            query = query.sort(options.sort);
        }

        // Apply pagination
        if (options.pagination.skip !== undefined) {
            query = query.skip(options.pagination.skip);
        }
        if (options.pagination.limit !== undefined) {
            query = query.limit(options.pagination.limit);
        }

        return await query.exec();
    } catch (error) {
        logger.error('Error applying filters:', error);
        throw error;
    }
};

/**
 * Smart pagination to load maximum logs without hitting MongoDB memory limits
 * @param {Object} model - Mongoose model
 * @param {Object} filters - Parsed filters
 * @param {Object} options - Query options
 * @returns {Promise} - Query result
 */
const applySmartPagination = async (model, filters, options) => {
    const limits = [null, 50000, 30000, 18000, 10800, 6400, 100, 50]; // null = unlimited
    
    for (let i = 0; i < limits.length; i++) {
        const limit = limits[i];
        const attempt = i + 1;
        
        try {
            logger.info(`${limit ? `Attempting to load ${limit} logs` : 'Attempting to load all available logs'} (attempt ${attempt}/${limits.length})`);
            
            let query = model.find(filters);
            
            if (Object.keys(options.sort).length > 0) {
                query = query.sort(options.sort);
            }
            
            if (limit) query = query.limit(limit);
            
            const result = await query.exec();
            logger.info(`Successfully loaded ${result.length} logs${limit ? ` (limit ${limit})` : ''}`);
            return result;
            
        } catch (error) {
            // Memory limit error - try next smaller limit
            if (error.code === 292 || error.message.includes('Sort exceeded memory limit')) {
                logger.warn(`Memory limit exceeded${limit ? ` with limit ${limit}` : ''}, retrying with limit ${limits[i + 1] || 'fallback'}`);
                continue;
            }
            throw error; // Non-memory errors
        }
    }
    
    // Final fallback with basic _id sort
    try {
        logger.info('Final fallback: loading 50 logs with _id sort');
        return await model.find(filters).sort({ _id: -1 }).limit(50).exec();
    } catch (error) {
        logger.error('All attempts failed:', error);
        throw error;
    }
};

/**
 * Apply filters to aggregation pipeline
 * @param {Object} model - Mongoose model
 * @param {Object} filters - Parsed filters
 * @param {Object} options - Query options
 * @returns {Promise} - Aggregation result
 */
const applyFiltersToAggregation = async (model, filters, options, additionalPipeline = []) => {
    try {
        const pipeline = [];

        // Add match stage if filters exist
        if (Object.keys(filters).length > 0) {
            pipeline.push({$match: filters});
        }

        // Add additional pipeline stages
        pipeline.push(...additionalPipeline);

        // Add custom aggregation stages
        if (options.aggregation && options.aggregation.length > 0) {
            pipeline.push(...options.aggregation);
        }

        // Add sorting
        if (Object.keys(options.sort).length > 0) {
            pipeline.push({$sort: options.sort});
        }

        // Add pagination
        if (options.pagination.skip !== undefined) {
            pipeline.push({$skip: options.pagination.skip});
        }
        if (options.pagination.limit !== undefined) {
            pipeline.push({$limit: options.pagination.limit});
        }

        return await model.aggregate(pipeline);
    } catch (error) {
        logger.error('Error applying filters to aggregation:', error);
        throw error;
    }
};

/**
 * Get filter summary for response metadata
 * @param {Object} filters - Applied filters
 * @param {Object} options - Query options
 * @returns {Object} - Filter summary
 */
const getFilterSummary = (filters, options) => {
    return {
        appliedFilters: Object.keys(filters).length,
        filters: filters,
        sort: options.sort,
        pagination: options.pagination.limit ? {
            page: Math.floor(options.pagination.skip / options.pagination.limit) + 1,
            limit: options.pagination.limit
        } : null
    };
};

/**
 * @desc    Get comprehensive application statistics overview
 * @route   GET /api/v1/stats/overview
 * @access  Admin only
 */
const getApplicationOverviewStats = asyncHandler(async (req, res, next) => {
    try {
        const User = require('../models/user.model');
        const File = require('../models/file.model');

        // Initialize stats object
        const stats = {
            summary: {},
            system: {},
            services: {},
            activity: {},
            timeline: {}
        };

        // Set time range based on query parameters
        const timeframeEnd = new Date();
        let timeframeStart = new Date();

        if (req.query.period) {
            const period = req.query.period;
            const number = parseInt(period.slice(0, -1));
            const unit = period.slice(-1);

            switch (unit) {
                case 'h':
                    timeframeStart.setHours(timeframeStart.getHours() - number);
                    break;
                case 'd':
                    timeframeStart.setDate(timeframeStart.getDate() - number);
                    break;
                case 'w':
                    timeframeStart.setDate(timeframeStart.getDate() - (number * 7));
                    break;
                case 'm':
                    timeframeStart.setMonth(timeframeStart.getMonth() - number);
                    break;
                case 'y':
                    timeframeStart.setFullYear(timeframeStart.getFullYear() - number);
                    break;
                default:
                    timeframeStart.setDate(timeframeStart.getDate() - 30); // Default 30 days
            }
        } else {
            timeframeStart.setDate(timeframeStart.getDate() - 30); // Default 30 days
        }

        // Get user statistics
        const totalUsers = await User.countDocuments();
        const activeUsers = await User.countDocuments({active: true});
        const adminUsers = await User.countDocuments({roles: {$in: ['ADMIN', 'OWNER']}});

        // Get file statistics
        const totalFiles = await File.countDocuments();
        const recentFiles = await File.countDocuments({
            createdAt: {$gte: timeframeStart}
        });

        // Get file storage stats
        const fileStorageStats = await getGridFSStorageStats();

        // Get log statistics for the time period
        const logStats = await Log.aggregate([
            {
                $match: {
                    timestamp: {$gte: timeframeStart, $lte: timeframeEnd}
                }
            },
            {
                $group: {
                    _id: null,
                    totalRequests: {$sum: 1},
                    errors: {
                        $sum: {
                            $cond: [{$gte: ['$statusCode', 400]}, 1, 0]
                        }
                    },
                    avgResponseTime: {$avg: '$responseTime'},
                    uniqueIPs: {$addToSet: '$ip'}
                }
            }
        ]);

        // Get cache status
        let cacheStatus = 'unknown';
        let cacheHitRate = 0;
        let cacheKeyCount = 0;

        try {
            const redisClient = require('../middleware/app.middleware').redisClient;

            if (redisClient && redisClient.isReady) {
                cacheStatus = 'connected';

                const stats = await redisClient.info('stats');
                const keyspace = await redisClient.info('keyspace');

                if (stats) {
                    const redisStats = stats
                        .split(/[\r\n]+/)
                        .filter(line => line.includes(':'))
                        .reduce((obj, line) => {
                            const [key, value] = line.split(':');
                            obj[key.trim()] = value.trim();
                            return obj;
                        }, {});

                    const keyspaceHits = parseInt(redisStats.keyspace_hits || 0);
                    const keyspaceMisses = parseInt(redisStats.keyspace_misses || 0);
                    const totalOps = keyspaceHits + keyspaceMisses;
                    cacheHitRate = totalOps > 0 ? Math.round((keyspaceHits / totalOps) * 100) : 0;
                }

                if (keyspace) {
                    const db0Match = keyspace.match(/db0:keys=(\d+)/);
                    cacheKeyCount = db0Match ? parseInt(db0Match[1]) : 0;
                }
            } else {
                cacheStatus = 'disconnected';
            }
        } catch (cacheError) {
            cacheStatus = 'error';
        }

        // Check email service status
        const emailReady = isEmailReady();

        // Build stats response
        stats.summary = {
            totalUsers,
            activeUsers,
            adminUsers,
            totalFiles,
            recentFiles,
            totalRequests: logStats[0]?.totalRequests || 0,
            errorRate: logStats[0] ? Math.round((logStats[0].errors / logStats[0].totalRequests) * 100) : 0,
            uniqueVisitors: logStats[0]?.uniqueIPs?.length || 0
        };

        stats.system = {
            nodeVersion: process.version,
            platform: process.platform,
            arch: process.arch,
            uptime: Math.floor(process.uptime()),
            environment: process.env.NODE_ENV,
            memory: {
                used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
                total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024),
                rss: Math.round(process.memoryUsage().rss / 1024 / 1024)
            }
        };

        stats.services = {
            database: {
                status: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
                collections: ['users', 'files', 'logs']
            },
            cache: {
                status: cacheStatus,
                hitRate: cacheHitRate,
                keyCount: cacheKeyCount
            },
            email: {
                status: emailReady ? 'configured' : 'not configured',
                host: process.env.EMAIL_HOST
            },
            storage: {
                totalFiles: fileStorageStats.totalFiles || 0,
                totalSize: fileStorageStats.totalSize || 0,
                humanReadableSize: fileStorageStats.humanReadableSize || '0.00 MB'
            }
        };

        stats.activity = {
            avgResponseTime: logStats[0]?.avgResponseTime || 0,
            totalErrors: logStats[0]?.errors || 0,
            period: `${Math.round((timeframeEnd - timeframeStart) / (1000 * 60 * 60 * 24))} days`
        };

        stats.timeline = {
            start: timeframeStart.toISOString(),
            end: timeframeEnd.toISOString()
        };

        res.status(200).json({
            success: true,
            message: 'Application overview statistics retrieved successfully',
            statistics: stats,
            meta: {
                timestamp: new Date().toISOString()
            }
        });
    } catch (error) {
        logger.error('Error retrieving application overview statistics:', error);
        next(new AppError('Failed to retrieve application overview statistics', 500));
    }
});

/**
 * @desc    Get detailed application performance statistics
 * @route   GET /api/v1/stats/performance
 * @access  Admin only
 */
const getApplicationPerformanceStats = asyncHandler(async (req, res, next) => {
    try {
        // Set time range
        const timeframeEnd = new Date();
        let timeframeStart = new Date();
        timeframeStart.setDate(timeframeStart.getDate() - 7); // Default 7 days

        if (req.query.period) {
            const period = req.query.period;
            const number = parseInt(period.slice(0, -1));
            const unit = period.slice(-1);

            switch (unit) {
                case 'h':
                    timeframeStart.setHours(timeframeStart.getHours() - number);
                    break;
                case 'd':
                    timeframeStart.setDate(timeframeStart.getDate() - number);
                    break;
                case 'w':
                    timeframeStart.setDate(timeframeStart.getDate() - (number * 7));
                    break;
            }
        }

        // Get performance metrics from logs
        const performanceStats = await Log.aggregate([
            {
                $match: {
                    timestamp: {$gte: timeframeStart, $lte: timeframeEnd}
                }
            },
            {
                $group: {
                    _id: null,
                    avgResponseTime: {$avg: '$responseTime'},
                    minResponseTime: {$min: '$responseTime'},
                    maxResponseTime: {$max: '$responseTime'},
                    totalRequests: {$sum: 1},
                    successfulRequests: {
                        $sum: {
                            $cond: [{$lt: ['$statusCode', 400]}, 1, 0]
                        }
                    },
                    errors: {
                        $sum: {
                            $cond: [{$gte: ['$statusCode', 400]}, 1, 0]
                        }
                    }
                }
            }
        ]);

        // Get endpoint performance breakdown
        const endpointStats = await Log.aggregate([
            {
                $match: {
                    timestamp: {$gte: timeframeStart, $lte: timeframeEnd}
                }
            },
            {
                $group: {
                    _id: '$url',
                    count: {$sum: 1},
                    avgResponseTime: {$avg: '$responseTime'},
                    errorCount: {
                        $sum: {
                            $cond: [{$gte: ['$statusCode', 400]}, 1, 0]
                        }
                    }
                }
            },
            {$sort: {count: -1}},
            {$limit: 10}
        ]);

        // Get hourly traffic pattern
        const trafficPattern = await Log.aggregate([
            {
                $match: {
                    timestamp: {$gte: timeframeStart, $lte: timeframeEnd}
                }
            },
            {
                $group: {
                    _id: {$hour: '$timestamp'},
                    requests: {$sum: 1},
                    avgResponseTime: {$avg: '$responseTime'}
                }
            },
            {$sort: {_id: 1}}
        ]);

        const performanceData = {
            overview: performanceStats[0] || {
                avgResponseTime: 0,
                minResponseTime: 0,
                maxResponseTime: 0,
                totalRequests: 0,
                successfulRequests: 0,
                errors: 0
            },
            endpoints: endpointStats,
            trafficPattern: trafficPattern,
            period: {
                start: timeframeStart.toISOString(),
                end: timeframeEnd.toISOString(),
                duration: `${Math.round((timeframeEnd - timeframeStart) / (1000 * 60 * 60 * 24))} days`
            }
        };

        res.status(200).json({
            success: true,
            message: 'Application performance statistics retrieved successfully',
            performance: performanceData,
            meta: {
                timestamp: new Date().toISOString()
            }
        });
    } catch (error) {
        logger.error('Error retrieving application performance statistics:', error);
        next(new AppError('Failed to retrieve application performance statistics', 500));
    }
});

module.exports = {
    getHealth,
    getApiHealth,
    setupHealthRoutes,
    getCacheStats,
    clearCache,
    getLogs,
    getLogById,
    getLogStats,
    clearLogs,

    // Application Statistics endpoints
    getApplicationOverviewStats,
    getApplicationPerformanceStats,

    // Email functions
    loadTemplate,
    sendEmail,
    clearTemplateCache,
    renderEmailTemplate,
    sendTestEmail,
    initializeEmailService,
    isEmailReady,
    getEmailTransporter,

    // GridFS functions
    initializeGridFS,
    getGridFSStorageStats,

    // Query filter functions
    parseFilters,
    applyFilters,
    applySmartPagination,
    applyFiltersToAggregation,
    getFilterSummary
};

/**
 * Export GridFS utility functions for use in other parts of the app
 */
module.exports.gridFSUtils = {
    initializeGridFS, getGridFSStorageStats
};