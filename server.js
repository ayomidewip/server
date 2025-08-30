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
        
        // Create HTTP server for WebSocket support
        this.httpServer = http.createServer(this.app);

        // Initialize server and connections
        this.server = null;
        this.wsServer = null;
        this.isInitialized = false;

        // Store configuration
        this.config = {
            port: process.env.PORT || 8080,
            environment: process.env.NODE_ENV || 'development',
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

        // Initialize WebSocket server for collaborative editing
        this.initializeWebSocketServer();

        this.isInitialized = true;
        return this;
    }

    /**
     * Initialize WebSocket server for collaborative editing
     */
    initializeWebSocketServer() {
        if (!this.wsServer) {
            const io = require('socket.io')(this.httpServer, {
                cors: {
                    origin: this.config.allowedOrigins.length > 0 ? this.config.allowedOrigins : "http://localhost:8088",
                    methods: ["GET", "POST"],
                    credentials: true
                }
            });
            
            this.wsServer = io;
            
            // Import file controller for WebSocket handling
            const fileController = require('./controllers/file.controller');
            
            // Handle WebSocket connections
            io.on('connection', (socket) => {
                fileController.handleWebSocketConnection(socket, socket.request);
            });
            
            logger.info('WebSocket server initialized for collaborative editing');
        }
    }

    /**
     * Connect to MongoDB database
     * @returns {Promise<Object>} Mongoose connection object
     */
    async connectDatabase() {
        try {
            this.dbConnection = await connectDB();
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

            // Start the server
            const serverPort = port || this.config.port;
            return new Promise((resolve) => {
                this.server = this.app.listen(serverPort, async () => {
                    // Start cache cleanup service if caching is enabled and cleanup is enabled
                    if (this.config.cacheEnabled && process.env.CACHE_CLEANUP_ENABLED !== 'false') {
                        try {
                            // Use hours instead of minutes, with conservative default
                            const cleanupIntervalHours = parseInt(process.env.CACHE_CLEANUP_INTERVAL_HOURS) || 24;
                            cleanupService.start(cleanupIntervalHours);
                        } catch (err) {
                            logger.warn('⚠️ Failed to start cache cleanup service:', err.message);
                        }
                    } else if (process.env.CACHE_CLEANUP_ENABLED === 'false') {
                        logger.info('🧹 Cache cleanup service disabled via configuration');
                    }

                    // Log startup information about auto-save persistence
                    try {
                        const {cleanup} = require('./controllers/file.controller');
                        const status = cleanup.getAutosavePersistenceStatus();
                        logger.info('💾 Auto-save persistence service initialized', {
                            persistenceIntervalMinutes: status.persistenceIntervalMinutes,
                            activeTimers: status.activeTimers
                        });
                    } catch (error) {
                        logger.warn('⚠️ Failed to initialize auto-save persistence service:', error.message);
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

                    // Stop auto-save persistence timers
                    try {
                        const {cleanup} = require('./controllers/file.controller');
                        cleanup.stopAllAutosavePersistenceTimers();
                        logger.info('Auto-save persistence timers stopped');
                    } catch (error) {
                        logger.warn('Failed to stop auto-save persistence timers:', error.message);
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
