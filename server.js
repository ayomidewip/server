/**
 * Server Application Class
 * Provides a complete server instance with database connections, middleware and routes.
 */

const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const http = require('http');

// Load environment variables FIRST before importing logger
dotenv.config({path: path.resolve(process.cwd(), '.env')});

const {connectDB} = require('./config/db');
const errorHandler = require('./middleware/error.middleware');
const appMiddleware = require('./middleware/app.middleware');
const appController = require('./controllers/app.controller');
const {noCacheResponse} = require('./middleware/cache.middleware');
const logger = require('./utils/app.logger'); // Now imported AFTER env vars are loaded
const {redisClient} = require('./middleware/app.middleware');
const {cleanupService} = require('./controllers/cache.controller');
const Y = require('yjs');
const { setupWSConnection, setPersistence } = require('@y/websocket-server/utils');

// Import notification service from file middleware
const { getFileNotificationService } = require('./middleware/file.middleware');
const notificationService = getFileNotificationService();

/**
 * Server class that encapsulates the Express application
 */
class Server {
    /**
     * Creates a new Server instance
     * @param {Object} options - Server configuration options
     * @param {string} options.envPath - Path to .env file
     * @param {boolean} options.skipValidation - Skip environment validation (for tests)
     */

    constructor(options = {}) {
        // Load environment variables
        this.loadEnvironment(options.envPath);

        // Create Express app
        this.app = express();
        
    // Create HTTP server (shared with Express app)
    this.httpServer = http.createServer(this.app);

    // Initialize server and connections
    this.server = null;
        this.isInitialized = false;

        // Store configuration
        this.config = {
            port: process.env.PORT,
            environment: process.env.NODE_ENV,
            mongoUri: process.env.MONGODB_URI,
            cacheEnabled: process.env.CACHE_ENABLED !== 'false',
            allowedOrigins: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : []
        };

        // Debug log to test if debug level is working
        logger.debug('🔧 Server constructor initialized', {
            logLevel: process.env.LOG_LEVEL,
            environment: this.config.environment,
            port: this.config.port
        });

        // Register error handlers for uncaught exceptions
        this.registerProcessHandlers();
    }

    /**
     * Load environment variables from .env file
     * @param {string} envPath - Path to .env file
     */
    loadEnvironment(envPath) {
        // Environment variables are already loaded at the top of this file
        // This method now just handles alternative env paths for testing
        if (envPath && envPath !== path.resolve(process.cwd(), '.env')) {
            const envFile = path.resolve(envPath);
            dotenv.config({path: envFile});

            // Debug log to check if LOG_LEVEL is properly loaded
            logger.debug('🔧 ENV DEBUG - LOG_LEVEL after custom dotenv.config():', process.env.LOG_LEVEL);
            logger.debug('🔧 ENV DEBUG - NODE_ENV:', process.env.NODE_ENV);
        }

        // Skip validation if we're in test mode and variables haven't been loaded yet
        if (process.env.NODE_ENV !== 'test') {
            this.validateEnvironment();
        }
    }

    /**
     * Validate that all required environment variables are set
     */
    validateEnvironment() {
        const requiredEnvVars = [
            'PORT',
            'NODE_ENV',
            'MONGODB_URI',
            'ALLOWED_ORIGINS',
            'ACCESS_TOKEN_SECRET',
            'REFRESH_TOKEN_SECRET',
            'ACCESS_TOKEN_EXPIRY',
            'REFRESH_TOKEN_EXPIRY'
        ];

        const missingEnvVars = requiredEnvVars.filter(varName => !process.env[varName]);
        if (missingEnvVars.length > 0) {
            logger.error('Missing required environment variables:', missingEnvVars);
            throw new Error(`Missing required environment variables: ${missingEnvVars.join(', ')}`);
        }
    }

    /**
     * Register process event handlers for graceful shutdown
     */
    registerProcessHandlers() {
        // Handle unhandled promise rejections
        process.on('unhandledRejection', (err, promise) => {
            logger.error('Unhandled Rejection:', {message: err.message, stack: err.stack, promise, error: err});

            // In test mode, don't exit the process
            if (process.env.NODE_ENV !== 'test') {
                logger.info('Server shutting down due to unhandled rejection.');
                this.shutdown(1);
            }
        });

        // Add event listener for uncaught exceptions
        process.on('uncaughtException', (err) => {
            logger.error('Uncaught Exception:', {message: err.message, stack: err.stack, error: err});

            // In test mode, don't exit the process
            if (process.env.NODE_ENV !== 'test') {
                logger.info('Server shutting down due to uncaught exception.');
                this.shutdown(1);
            }
        });

        // Add SIGTERM handler for graceful shutdown with Docker/Kubernetes
        process.on('SIGTERM', () => {
            logger.info('SIGTERM received. Shutting down gracefully.');
            this.shutdown(0);
        });
    }

    /**
     * Initialize the serverwith all middleware and routes
     */
    async initialize() {
        if (this.isInitialized) {
            logger.warn('Server already initialized');
            return this;
        }

        // Setup middleware
        appMiddleware.setupMiddleware(this.app);

        // Setup basic health check route - unprotected and without API prefix
        // Health endpoints should NEVER use caching
        this.app.get('/health', noCacheResponse(), appController.getHealth);
        // Import route modules
        const authRouter = require('./routes/auth.routes');
        const userRouter = require('./routes/user.routes');
        const appRouter = require('./routes/app.routes');
        const fileRouter = require('./routes/file.routes');
        const cacheRouter = require('./routes/cache.routes');

        // Register all routes for validation
        appMiddleware.registerRoutes([
            '/health',
            ...appRouter.validRoutes,
            ...authRouter.validRoutes,
            ...userRouter.validRoutes,
            ...fileRouter.validRoutes,
            ...cacheRouter.validRoutes
        ]);

        // Apply route validation middleware specifically to /api routes
        this.app.use('/api', appMiddleware.validateRoute);

        // API Routes
        this.app.use('/api/v1/auth', authRouter);
        this.app.use('/api/v1/users', userRouter);
        this.app.use('/api/v1/files', fileRouter);
        this.app.use('/api/v1/cache', cacheRouter);
        this.app.use('/api/v1', appRouter);

        // Handle undefined routes
        appMiddleware.handleUndefinedRoutes(this.app);

        // Error handling middleware
        this.app.use(errorHandler);

        this.isInitialized = true;
        return this;
    }

    /**
     * Connect to MongoDB database
     * @returns {Promise<Object>} Mongoose connection object
     */
    async connectDatabase() {
        try {
            this.dbConnection = await connectDB();
            
            // Initialize Yjs service after database connection
            const { getYjsService } = require('./middleware/file.middleware');
            const yjsService = getYjsService();
            await yjsService.initialize();
            
            return this.dbConnection;
        } catch (error) {
            logger.error('Failed to connect to database:', error);
            throw error;
        }
    }

    /**
     * Checks if Redis client is connected
     * @returns {boolean} true if Redis is connected
     */
    isRedisConnected() {
        return redisClient && redisClient.isReady;
    }

    /**
     * Get Redis client instance
     * @returns {Object} Redis client
     */
    getRedisClient() {
        return redisClient;
    }

    /**
     * Get database connection instance
     * @returns {Object} Mongoose connection
     */
    getDbConnection() {
        return mongoose.connection;
    }

    /**
     * Initialize email service
     * @returns {Promise<void>}
     */  
    async initializeEmailService() {
        try {
            const {initializeEmailService} = require('./controllers/app.controller');
            logger.info('📧 Initializing email service...');

            const transporter = await initializeEmailService();
            if (transporter) {
                logger.info('✅ Email service initialized successfully');
            } else {
                logger.warn('⚠️ Email service not configured or disabled');
            }
        } catch (error) {
            logger.error('❌ Failed to initialize email service:', error);
            // Don't throw here - email service failure shouldn't prevent server startup
        }
    }

    /**
     * Check if email service is ready
     * @returns {boolean} true if email service is ready
     */
    isEmailServiceReady() {
        try {
            const {isEmailReady} = require('./controllers/app.controller');
            return isEmailReady();
        } catch (error) {
            return false;
        }
    }

    /**
     * Get email service instance
     * @returns {Object} Email transporter
     */
    getEmailService() {
        try {
            const {getEmailTransporter} = require('./controllers/app.controller');
            return getEmailTransporter();
        } catch (error) {
            logger.error('Failed to get email service:', error);
            return null;
        }
    }

    /**
     * Register process handlers for graceful shutdown
     */
    registerProcessHandlers() {
        // Handle uncaught exceptions
        process.on('uncaughtException', (error) => {
            logger.error('Uncaught Exception:', error);
            this.shutdown(1);
        });

        // Handle unhandled promise rejections
        process.on('unhandledRejection', (reason, promise) => {
            logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
            this.shutdown(1);
        });

        // Handle graceful shutdown signals
        process.on('SIGINT', () => {
            logger.info('Received SIGINT (Ctrl+C), initiating graceful shutdown...');
            this.shutdown(0);
        });

        process.on('SIGTERM', () => {
            logger.info('Received SIGTERM, initiating graceful shutdown...');
            this.shutdown(0);
        });
    }

    /**
     * Start the server
     * @param {number} port - Port to listen on (overrides environment variable)
     * @returns {Promise<Object>} Express server instance
     */
    async start(port) {
        try {
            // Initialize the server if not already done
            if (!this.isInitialized) {
                await this.initialize();
            }

            // Connect to database
            await this.connectDatabase();

            // Initialize email service
            await this.initializeEmailService();

            // Start the server using the HTTP server (shared with Express)
            const serverPort = port || this.config.port;
            return new Promise((resolve) => {
                this.server = this.httpServer.listen(serverPort, async () => {
                    // Start cache cleanup service if caching is enabled and cleanup is enabled
                    if (this.config.cacheEnabled && process.env.CACHE_CLEANUP_ENABLED !== 'false') {
                        try {
                            // Use hours instead of minutes, with conservative default
                            const cleanupIntervalHours = parseInt(process.env.CACHE_CLEANUP_INTERVAL_HOURS);
                            cleanupService.start(cleanupIntervalHours);
                        } catch (err) {
                            logger.warn('⚠️ Failed to start cache cleanup service:', err.message);
                        }
                    } else if (process.env.CACHE_CLEANUP_ENABLED === 'false') {
                        logger.info('🧹 Cache cleanup service disabled via configuration');
                    }

                    // Yjs service initialized - collaborative editing ready

                    

                    // Setup integrated Yjs WebSocket server on the same HTTP server
                    try {
                        logger.info('🚀 Setting up integrated Yjs WebSocket server');
                        
                        const WebSocket = require('ws');
                        const fileController = require('./controllers/file.controller');
                        const { docs } = require('@y/websocket-server/utils');
                        
                        // Create WebSocket server using the existing HTTP server - standard Yjs pattern
                        // Handle both /yjs/ and /notifications paths appropriately
                        const wss = new WebSocket.Server({ 
                            server: this.httpServer
                        });

                        const persistence = fileController.yjsService.getPersistence();

                        if (persistence) {
                            setPersistence({
                                provider: persistence,
                                bindState: async (docName, ydoc) => {
                                    try {
                                        // Load persisted state from MongoDB
                                        const persistedYdoc = await persistence.getYDoc(docName);
                                        const persistedUpdate = Y.encodeStateAsUpdate(persistedYdoc);

                                        // Apply persisted state to ensure consistency (idempotent)
                                        if (persistedUpdate.length > 0) {
                                            Y.applyUpdate(ydoc, persistedUpdate);
                                        }
                                        
                                        // Store any local changes back to persistence
                                        const currentState = Y.encodeStateAsUpdate(ydoc);
                                        const persistedStateVector = Y.encodeStateVector(persistedYdoc);
                                        const diff = Y.encodeStateAsUpdate(ydoc, persistedStateVector);
                                        
                                        if (diff.length > 2 && diff.some(value => value !== 0)) {
                                            await persistence.storeUpdate(docName, diff);
                                        }

                                        // Setup MongoDB persistence for updates with optimized batching
                                        let updateTimeout = null;
                                        let persistenceTimeout = null;
                                        const pendingUpdates = new Set();
                                        const pendingPersistenceUpdates = new Map(); // docName -> updates array
                                        
                                        ydoc.on('update', async (update) => {
                                            try {
                                                // Batch persistence updates to reduce MongoDB writes
                                                if (!pendingPersistenceUpdates.has(docName)) {
                                                    pendingPersistenceUpdates.set(docName, []);
                                                }
                                                pendingPersistenceUpdates.get(docName).push(update);
                                                
                                                // Clear existing persistence timeout
                                                if (persistenceTimeout) {
                                                    clearTimeout(persistenceTimeout);
                                                }
                                                
                                                // Batch persistence writes every 500ms for better performance
                                                persistenceTimeout = setTimeout(async () => {
                                                    for (const [docNameToPersist, updates] of pendingPersistenceUpdates) {
                                                        try {
                                                            // Store all batched updates
                                                            for (const batchedUpdate of updates) {
                                                                await persistence.storeUpdate(docNameToPersist, batchedUpdate);
                                                            }

                                                        } catch (batchError) {
                                                            logger.error('Failed to store batched Yjs updates', {
                                                                docName: docNameToPersist,
                                                                updateCount: updates.length,
                                                                error: batchError.message
                                                            });
                                                        }
                                                    }
                                                    pendingPersistenceUpdates.clear();
                                                    persistenceTimeout = null;
                                                }, 500); // 500ms batching for persistence
                                                
                                                // Debounce File model updates to avoid performance issues (longer delay)
                                                pendingUpdates.add(docName);
                                                
                                                // Clear existing timeout
                                                if (updateTimeout) {
                                                    clearTimeout(updateTimeout);
                                                }
                                                
                                                // Set new timeout to update file metadata after 3 seconds of inactivity
                                                updateTimeout = setTimeout(async () => {
                                                    for (const docNameToUpdate of pendingUpdates) {
                                                        try {
                                                            // Convert Yjs document name back to file path
                                                            const filePath = docNameToUpdate.startsWith('yjs/') ? 
                                                                '/' + docNameToUpdate.substring(4) : // Remove 'yjs/' prefix and add leading slash
                                                                '/' + docNameToUpdate; // Add leading slash if no prefix
                                                            
                                                            // Update the file metadata to reflect the content change
                                                            const File = require('./models/file.model');
                                                            await File.updateOne(
                                                                { filePath: filePath, type: 'text' },
                                                                { updatedAt: new Date() }
                                                            );
                                                            
                                                            logger.debug('Updated file metadata after Yjs content changes', {
                                                                docName: docNameToUpdate,
                                                                filePath
                                                            });
                                                        } catch (fileUpdateError) {
                                                            logger.error('Failed to update file metadata', {
                                                                docName: docNameToUpdate,
                                                                error: fileUpdateError.message
                                                            });
                                                        }
                                                    }
                                                    pendingUpdates.clear();
                                                    updateTimeout = null;
                                                }, 3000); // 3 second debounce for metadata updates
                                                
                                            } catch (storeError) {
                                                logger.error('Failed to handle Yjs update', {
                                                    docName,
                                                    error: storeError.message
                                                });
                                            }
                                        });

                                        // Bind Redis adapter for cross-server synchronization
                                        try {
                                            const redisAdapter = await fileController.yjsService.bindRedisAdapter(docName, ydoc);
                                            if (redisAdapter) {
                                                logger.debug('Redis adapter bound for cross-server sync', { docName });
                                            }
                                        } catch (redisError) {
                                            logger.warn('Failed to bind Redis adapter, continuing with MongoDB-only persistence', {
                                                docName,
                                                error: redisError.message
                                            });
                                        }

                                        persistedYdoc.destroy();
                                    } catch (error) {
                                        logger.error('Failed to bind Yjs persistence state', {
                                            docName,
                                            error: error.message
                                        });
                                    }
                                },
                                writeState: async (docName, ydoc) => {
                                    try {
                                        // Flush to MongoDB
                                        await persistence.flushDocument(docName);
                                        
                                        // Unbind Redis adapter when document is being written/closed
                                        try {
                                            await fileController.yjsService.unbindRedisAdapter(docName, ydoc);
                                        } catch (redisError) {
                                            logger.warn('Failed to unbind Redis adapter during writeState', {
                                                docName,
                                                error: redisError.message
                                            });
                                        }
                                    } catch (error) {
                                        logger.error('Failed to flush Yjs persistence state', {
                                            docName,
                                            error: error.message
                                        });
                                    }
                                }
                            });

                            const redisStats = fileController.yjsService.getRedisStats();
                            if (redisStats.isEnabled && redisStats.isConnected) {
                                logger.info('Yjs WebSocket persistence bound to MongoDB with Redis pub/sub scaling (multi-server mode)');
                            } else {
                                logger.info('Yjs WebSocket persistence bound to MongoDB provider (single-server mode)');
                            }
                        } else {
                            logger.warn('Yjs WebSocket server started without persistence binding; collaborative changes will not be persisted.');
                        }
                        
                        // Handle WebSocket connections with authentication
                        wss.on('connection', async (ws, req) => {
                            try {
                                const urlPath = req.url.split('?')[0];
                                
                                if (urlPath === '/notifications') {
                                    // This is a notification WebSocket connection - let the notification service handle it
                                    notificationService.handleConnection(ws, req);
                                    return;
                                } else if (!urlPath.startsWith('/yjs/')) {
                                    logger.warn('Invalid WebSocket path, rejecting connection', { urlPath });
                                    ws.close(1008, 'Invalid path');
                                    return;
                                }
                                
                                // Continue with Yjs WebSocket handling

                                if (!persistence) {
                                    logger.error('Yjs persistence not initialized');
                                    ws.close(1011, 'Persistence unavailable');
                                    return;
                                }

                                // Authenticate WebSocket connection
                                const authMiddleware = require('./middleware/auth.middleware');
                                const user = await authMiddleware.authenticateWebSocket(ws, req);

                                // Extract document name from URL
                                const docNameFromUrl = req.url.slice(1).split('?')[0];
                                
                                // Call setupWSConnection which handles the Yjs sync protocol  
                                // This will create or retrieve the Y.Doc from the docs cache
                                // gc: false prevents aggressive garbage collection that might
                                // cause documents to be prematurely removed from memory
                                setupWSConnection(ws, req, {
                                    gc: false  // Keep documents in memory for better collaboration
                                });

                                // CRITICAL FIX: Manually send full document state on every connection
                                // The standard Yjs sync protocol can fail on reconnections, so we
                                // explicitly send the document state to ensure clients always sync
                                try {
                                    const doc = docs.get(docNameFromUrl);
                                    if (doc && ws.readyState === WebSocket.OPEN) {
                                        const encoding = require('lib0/encoding');
                                        const syncProtocol = require('y-protocols/sync');
                                        
                                        // Create sync step 2 message with full document state
                                        const encoder = encoding.createEncoder();
                                        encoding.writeVarUint(encoder, 0); // messageSync
                                        const update = Y.encodeStateAsUpdate(doc);
                                        syncProtocol.writeUpdate(encoder, update);
                                        const message = encoding.toUint8Array(encoder);
                                        
                                        // Send the sync message
                                        ws.send(message, (err) => {
                                            if (err) {
                                                logger.error('Failed to send manual sync message', {
                                                    docName: docNameFromUrl,
                                                    error: err.message
                                                });
                                            }
                                        });
                                    }
                                } catch (syncError) {
                                    logger.error('Failed to manually sync document', {
                                        docName: docNameFromUrl,
                                        error: syncError.message
                                    });
                                }

                                logger.debug('Yjs WebSocket connection established', {
                                    userId: user.id,
                                    docName: docNameFromUrl
                                });
                                
                            } catch (error) {
                                logger.error('Yjs WebSocket authentication error:', error);
                                ws.close(1008, 'Authentication failed');
                            }
                        });
                        
                        // Handle server errors
                        wss.on('error', (error) => {
                            logger.error('Integrated WebSocket server error:', error);
                        });
                        
                        // Store WebSocket server reference for shutdown
                        this.yjsWebSocketServer = wss;
                        
                        logger.info('✅ Integrated Yjs WebSocket server running on /yjs path');
                        
                    } catch (error) {
                        logger.error('❌ Failed to start integrated Yjs WebSocket server:', error);
                    }

                    // Initialize notification WebSocket service (routing handled in main WebSocket server above)
                    try {
                        logger.info('🔔 Setting up notification WebSocket server');
                        // Initialize the service without creating a separate WebSocket server
                        notificationService.initialize();
                        logger.info('✅ Notification WebSocket server running on /notifications path');
                    } catch (error) {
                        logger.error('❌ Failed to start notification WebSocket server:', error);
                    }

                    // Log initial health check before showing startup banner
                    // Use the getHealth function from appController, but mock req/res
                    const mockReq = {ip: 'startup'};
                    const mockRes = {
                        json: () => {
                        }
                    }; // Suppress duplicate log output

                    appController.getHealth(mockReq, mockRes);

                    // Now show startup banner
                    await logger.startupMessage("App-Base", serverPort, this.config.environment);

                    resolve(this.server);
                });
            });
        } catch (error) {
            logger.error('Failed to start server:', error);
            throw error;
        }
    }
    


    /**
     * Stop the server and close connections
     * @returns {Promise<void>}
     */
    async stop() {
        return new Promise((resolve, reject) => {
            if (!this.server) {
                logger.warn('Server not running, nothing to stop');
                return resolve();
            }

            logger.info('Stopping server...');

            this.server.close(async (err) => {
                if (err) {
                    logger.error('Error stopping server:', err);
                    return reject(err);
                }

                try {
                    // Stop cache cleanup service
                    if (cleanupService) {
                        cleanupService.stop();
                        logger.info('Cache cleanup service stopped');
                    }

                    // Cleanup Yjs service
                    try {
                        const fileController = require('./controllers/file.controller');
                        await fileController.yjsService.destroy();
                        logger.info('Yjs service cleaned up');
                    } catch (error) {
                        logger.warn('Failed to cleanup Yjs service:', error.message);
                    }

                    // Close database connection
                    if (mongoose.connection.readyState !== 0) {
                        logger.info('Closing database connection...');
                        await mongoose.connection.close();
                        logger.info('Database connection closed');
                    }

                    // Close Redis connection if active
                    if (this.isRedisConnected()) {
                        logger.info('Closing Redis connection...');
                        await redisClient.quit();
                        logger.info('Redis connection closed');
                    }
                    
                    // Close integrated Yjs WebSocket server if active
                    if (this.yjsWebSocketServer) {
                        logger.info('Closing integrated Yjs WebSocket server...');
                        try {
                            this.yjsWebSocketServer.close();
                            logger.info('Integrated Yjs WebSocket server closed');
                        } catch (err) {
                            logger.warn('Error closing integrated Yjs WebSocket server:', err.message);
                        }
                        this.yjsWebSocketServer = null;
                    }

                    // Shutdown notification WebSocket service
                    try {
                        notificationService.shutdown();
                        logger.info('Notification WebSocket service shut down');
                    } catch (error) {
                        logger.warn('Error shutting down notification WebSocket service:', error.message);
                    }

                    logger.info('Server stopped successfully');
                    this.server = null;
                    resolve();
                } catch (error) {
                    logger.error('Error during cleanup:', error);
                    reject(error);
                }
            });
        });
    }

    /**
     * Shutdown the server and optionally exit the process
     * @param {number} exitCode - Process exit code
     */
    async shutdown(exitCode = 0) {
        try {
            await this.stop();

            // Don't exit in test mode
            if (process.env.NODE_ENV !== 'test') {
                process.exit(exitCode);
            }
        } catch (error) {
            logger.error('Error during shutdown:', error);

            // Force exit in non-test mode
            if (process.env.NODE_ENV !== 'test') {
                process.exit(1);
            }
        }
    }

    /**
     * Get the Express app instance
     * @returns {Object} Express app
     */
    getApp() {
        return this.app;
    }

    /**
     * Get the server instance
     * @returns {Object} HTTP server
     */
    getServer() {
        return this.server;
    }

    /**
     * Get server configuration
     * @returns {Object} Server configuration
     */
    getConfig() {
        return {...this.config};
    }
}

// Create singleton instance
const serverInstance = new Server();

// Export both the class and a singleton instance
module.exports = {
    Server,
    serverInstance,

    // Export convenience methods on the module itself
    start: (port) => serverInstance.start(port),
    stop: () => serverInstance.stop(),
    getApp: () => serverInstance.getApp(),
    getServer: () => serverInstance.getServer(),
    getConfig: () => serverInstance.getConfig(), 
    isRedisConnected: () => serverInstance.isRedisConnected(),
    getRedisClient: () => serverInstance.getRedisClient(),
    getDbConnection: () => serverInstance.getDbConnection(),
    isEmailReady: () => appMiddleware.isEmailReady(),
    getEmailTransporter: () => appMiddleware.getEmailTransporter()
};
