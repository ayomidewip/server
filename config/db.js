import mongoose from 'mongoose';
import logger from '../utils/app.logger.js';

const connectDB = async () => {
    try {
        let uri = process.env.MONGODB_URI;

        if (!uri) {
            throw new Error('MONGODB_URI is not defined in environment variables');
        }

        // Extract host info for logging (without credentials)
        const hostInfo = uri.split('@').pop();
        // Log connection attempt
        logger.info(`🔗 Connecting to MongoDB at: ${logger.safeColor(logger.colors.bold)}${hostInfo}${logger.safeColor(logger.colors.reset)}`);

        // Connect to MongoDB with explicit options - enhanced for replica set support
        const connection = await mongoose.connect(uri, {
            serverSelectionTimeoutMS: 30000,
            connectTimeoutMS: 30000,
            socketTimeoutMS: 45000,
            retryWrites: true,
            retryReads: true,
            readConcern: {level: 'majority'},
            writeConcern: {w: 'majority', j: true}
        });
        // Log successful connection with colors - keep emoji for startup success
        logger.info(`${logger.safeColor(logger.colors.green)}🌱 MongoDB connection established! ${logger.safeColor(logger.colors.bold)}${hostInfo}${logger.safeColor(logger.colors.reset)}`);

        // Test transaction support
        try {
            const session = await mongoose.startSession();
            await session.endSession();
            logger.info(`${logger.safeColor(logger.colors.green)}⚡ Transaction support confirmed${logger.safeColor(logger.colors.reset)}`);
        } catch (error) {
            logger.warn(`${logger.safeColor(logger.colors.yellow)}⚠️  Transaction support not available: ${error.message}${logger.safeColor(logger.colors.reset)}`);
        }

        // Add connection listeners for better error handling
        // Only add listeners if they haven't been added before
        if (mongoose.connection.listenerCount('error') === 0) {
            mongoose.connection.on('error', err => {
                logger.error(`${logger.safeColor(logger.colors.red)}[Database]${logger.safeColor(logger.colors.reset)} MongoDB connection error: ${err.message}`);
            });
        }

        if (mongoose.connection.listenerCount('disconnected') === 0) {
            mongoose.connection.on('disconnected', () => {
                logger.warn(`${logger.safeColor(logger.colors.yellow)}[Database]${logger.safeColor(logger.colors.reset)} MongoDB disconnected. Attempting to reconnect...`);
            });
        }

        return connection;
    } catch (err) {
        logger.error(`${logger.safeColor(logger.colors.red)}[Database]${logger.safeColor(logger.colors.reset)} MongoDB connection failed: ${err.message}`);
        logger.error('Connection error details:', {message: err.message, stack: err.stack});
        throw err;
    }
};

// Graceful shutdown - only register if not already registered
if (!process.listenerCount('SIGINT')) {
    process.on('SIGINT', async () => {
        logger.info(`${logger.safeColor(logger.colors.yellow)}[Database]${logger.safeColor(logger.colors.reset)} SIGINT received: Closing MongoDB connection`);
        try {
            await closeDB();
        } catch (err) {
            logger.error('Error closing MongoDB connection:', err.message);
        }
        process.exit(0);
    });
}

// Close database connections and cleanup
const closeDB = async () => {
    try {
        // Close mongoose connection
        if (mongoose.connection.readyState !== 0) {
            await mongoose.connection.close();
            logger.info('🔐 MongoDB connection closed');
        }
    } catch (error) {
        logger.error('Error closing database connections:', error);
        throw error;
    }
};

export {
    connectDB,
    closeDB
};
