/**
 * Server Application Class
 * Provides a complete server instance with database connections, middleware and routes.
 */

import express from 'express';
import path from 'node:path';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import http from 'node:http';

// Load environment variables FIRST before importing other local modules
dotenv.config({path: path.resolve(process.cwd(), '.env')});

const {default: logger} = await import('./utils/app.logger.js');
const {connectDB} = await import('./config/db.js');
const {default: errorHandler} = await import('./middleware/error.middleware.js');

const appMiddleware = await import('./middleware/app.middleware.js');
const appController = await import('./controllers/app.controller.js');

const {noCacheResponse} = await import('./middleware/cache.middleware.js');
const {cleanupService} = await import('./controllers/cache.controller.js');

const {redisClient} = appMiddleware;

/**
 * Server class that encapsulates the Express application
 */
class Server {
    /**
     * Creates a new Server instance
     * @param {Object} options - Server configuration options
     * @param {string} options.envPath - Path to .env file
     */

    constructor(options = {}) {
        // Load environment variables
        this.loadEnvironment(options.envPath);

        // Create Express app
        this.app = express();
        this.app.set('trust proxy', 1);

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
            cacheEnabled: process.env.CACHE_ENABLED === 'true',
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

        this.validateEnvironment();
    }

    /**
     * Validate that all required environment variables are set
     */
    validateEnvironment() {
        const requiredEnvVars = [
            'ACCESS_TOKEN_EXPIRY',
            'ACCESS_TOKEN_SECRET',
            'ALLOWED_ORIGINS',
            'APP_NAME',
            'APP_URL',
            'BCRYPT_ROUNDS',
            'CACHE_CLEANUP_ENABLED',
            'CACHE_CLEANUP_INTERVAL_HOURS',
            'CACHE_CLEANUP_MAX_KEYS_PER_RUN',
            'CACHE_CLEANUP_MIN_AGE_HOURS',
            'CACHE_ENABLED',
            'EMAIL_ENABLED',
            'EMAIL_FROM',
            'EMAIL_HOST',
            'EMAIL_PASS',
            'EMAIL_PORT',
            'EMAIL_USER',
            'LOG_LEVEL',
            'MAX_REQUEST_SIZE',
            'MONGODB_URI',
            'NODE_ENV',
            'PORT',
            'RATE_LIMIT_AUTH_MAX_REQUESTS',
            'RATE_LIMIT_AUTH_WINDOW_MS',
            'RATE_LIMIT_MAX_REQUESTS',
            'RATE_LIMIT_WINDOW_MS',
            'REDIS_URL',
            'REFRESH_TOKEN_EXPIRY',
            'REFRESH_TOKEN_SECRET'
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
            logger.info('Server shutting down due to unhandled rejection.');
            this.shutdown(1);
        });

        // Add event listener for uncaught exceptions
        process.on('uncaughtException', (err) => {
            logger.error('Uncaught Exception:', {message: err.message, stack: err.stack, error: err});
            logger.info('Server shutting down due to uncaught exception.');
            this.shutdown(1);
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

        // Import auth middleware for CSRF protection
        const {csrfProtection, attachCsrfToken} = await import('./middleware/auth.middleware.js');

        // Apply CSRF token attachment to all API routes (sets cookie if missing)
        this.app.use('/api', attachCsrfToken);

        // Apply CSRF validation to state-changing requests on protected routes
        // Note: Exempt routes are handled within the middleware itself
        this.app.use('/api', csrfProtection);

        // Import route modules (lazy load to avoid circular dependencies).
        // Each routes module default-exports its router, which carries validRoutes.
        const [
            {default: authRouter},
            {default: userRouter},
            {default: appRouter},
            {default: cacheRouter}
        ] = await Promise.all([
            import('./routes/auth.routes.js'),
            import('./routes/user.routes.js'),
            import('./routes/app.routes.js'),
            import('./routes/cache.routes.js')
        ]);

        appMiddleware.registerRoutes([
            '/health',
            ...appRouter.validRoutes,
            ...authRouter.validRoutes,
            ...userRouter.validRoutes,
            ...cacheRouter.validRoutes
        ]);

        // Apply route validation middleware specifically to /api routes
        this.app.use('/api', appMiddleware.validateRoute);

        // API Routes
        this.app.use('/api/v1/auth', authRouter);
        this.app.use('/api/v1/users', userRouter);
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
            const {initializeEmailService} = appController;
            logger.info('📧 Initializing email service...');

            const transporter = await initializeEmailService?.();
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
            const {isEmailReady} = appController;
            return isEmailReady?.();
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
            const {getEmailTransporter} = appController;
            return getEmailTransporter?.();
        } catch (error) {
            logger.error('Failed to get email service:', error);
            return null;
        }
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
                    if (this.config.cacheEnabled && process.env.CACHE_CLEANUP_ENABLED === 'true') {
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
            process.exit(exitCode);
        } catch (error) {
            logger.error('Error during shutdown:', error);
            process.exit(1);
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

export const start = (port) => serverInstance.start(port);
export const stop = () => serverInstance.stop();
export const getApp = () => serverInstance.getApp();
export const getServer = () => serverInstance.getServer();
export const getConfig = () => serverInstance.getConfig();
export const isRedisConnected = () => serverInstance.isRedisConnected();
export const getRedisClient = () => serverInstance.getRedisClient();
export const getDbConnection = () => serverInstance.getDbConnection();
export const isEmailReady = () => appMiddleware.isEmailReady?.();
export const getEmailTransporter = () => appMiddleware.getEmailTransporter?.();

export {Server, serverInstance};
export default serverInstance;
