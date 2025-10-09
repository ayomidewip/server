import mongoose from 'mongoose';
import logger from '../utils/app.logger.js';

// GridFS bucket instance
let gridFSBucket = null;

// MongoDB Memory Server instance for testing
let mongoMemoryServer = null;

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

        // Initialize GridFS bucket after connection is established
        gridFSBucket = new mongoose.mongo.GridFSBucket(mongoose.connection.db, {
            bucketName: 'fs'
        });
        logger.info(`${logger.safeColor(logger.colors.cyan)}🗄️ GridFS bucket initialized${logger.safeColor(logger.colors.reset)}`);

        // Add connection listeners for better error handling
        mongoose.connection.on('error', err => {
            logger.error(`${logger.safeColor(logger.colors.red)}[Database]${logger.safeColor(logger.colors.reset)} MongoDB connection error: ${err.message}`);
        });

        mongoose.connection.on('disconnected', () => {
            logger.warn(`${logger.safeColor(logger.colors.yellow)}[Database]${logger.safeColor(logger.colors.reset)} MongoDB disconnected. Attempting to reconnect...`);
        });

        return connection;
    } catch (err) {
        logger.error(`${logger.safeColor(logger.colors.red)}[Database]${logger.safeColor(logger.colors.reset)} MongoDB connection failed: ${err.message}`);
        logger.error('Connection error details:', {message: err.message, stack: err.stack});

        // Don't retry in test mode to avoid infinite loops
        if (process.env.NODE_ENV !== 'test') {
            // Retry logic for transient errors
            if (err.name === 'MongoNetworkError' || err.message.includes('ECONNREFUSED')) {
                logger.info(`${logger.safeColor(logger.colors.yellow)}[Database]${logger.safeColor(logger.colors.reset)} Retrying MongoDB connection in 5 seconds...`);
                setTimeout(connectDB, 5000);
            }
        }
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

// GridFS utility functions
const getGridFSBucket = () => {
    if (!gridFSBucket) {
        throw new Error('GridFS bucket not initialized. Ensure database connection is established first.');
    }
    return gridFSBucket;
};

// Store content in GridFS
const storeInGridFS = async (filePath, content, metadata = {}) => {
    try {
        const bucket = getGridFSBucket();

        // Check if file already exists and delete it
        const existingFiles = await bucket.find({filename: filePath}).toArray();
        for (const file of existingFiles) {
            await bucket.delete(file._id);
        }

        return new Promise((resolve, reject) => {
            const uploadStream = bucket.openUploadStream(filePath, {
                metadata: {
                    ...metadata, uploadDate: new Date(), originalPath: filePath
                }
            });

            uploadStream.on('error', reject);
            uploadStream.on('finish', () => {
                // The uploadStream.id contains the GridFS _id
                resolve({
                    _id: uploadStream.id,
                    filename: filePath,
                    metadata: uploadStream.options.metadata
                });
            });

            // Handle different content types - convert to buffer if needed
            if (Buffer.isBuffer(content)) {
                // Content is already a buffer, use as is
                uploadStream.end(content);
            } else if (typeof content === 'string') {
                // Content is assumed to be base64 string
                uploadStream.end(Buffer.from(content, 'base64'));
            } else {
                // Unknown content type
                reject(new Error(`Unsupported content type for GridFS storage: ${typeof content}`));
            }
        });
    } catch (error) {
        logger.error('GridFS store error:', error);
        throw error;
    }
};

// Retrieve content from GridFS
const retrieveFromGridFS = async (filePath, {asStream = false} = {}) => {
    try {
        const bucket = getGridFSBucket();

        // Find the file
        const files = await bucket.find({filename: filePath}).toArray();
        if (files.length === 0) {
            throw new Error(`File not found in GridFS: ${filePath}`);
        }

        // Get the most recent file if multiple exist
        const file = files[files.length - 1];

        // Extract compression information from metadata
        const compression = file.metadata?.compression || {};
        const isCompressed = compression.isCompressed === true;
        const compressionAlgorithm = compression.algorithm;

        logger.debug(`GridFS retrieval for ${filePath}:`, {
            fileId: file._id.toString(),
            isCompressed,
            algorithm: compressionAlgorithm,
            size: file.length,
            metadata: !!file.metadata,
            uploadDate: file.uploadDate
        });

        if (asStream) {
            // When streaming a compressed file, we need to note the compression
            // so the download handler can decide whether to stream directly or decompress first
            const downloadStream = bucket.openDownloadStream(file._id);
            return {
                stream: downloadStream,
                metadata: file.metadata || {},
                size: file.length,
                uploadDate: file.uploadDate,
                isCompressed,
                compressionAlgorithm,
                compressionMetadata: compression
            };
        }

        // Return content as before for backward compatibility
        return new Promise((resolve, reject) => {
            const chunks = [];
            const downloadStream = bucket.openDownloadStream(file._id);

            downloadStream.on('data', (chunk) => {
                chunks.push(chunk);
            });

            downloadStream.on('error', reject);

            downloadStream.on('end', async () => {
                try {
                    const buffer = Buffer.concat(chunks);

                    // For binary files, return buffer; for text files, convert to string
                    const mimeType = file.metadata?.mimeType || 'application/octet-stream';
                    const fileModelModule = await import('../models/file.model.js');
                    const FileModel = fileModelModule.default ?? fileModelModule.File ?? fileModelModule;
                    const isTextFile = FileModel.isTextBasedFile(mimeType);

                    // Extract compression information from file metadata
                    const compressionMeta = file.metadata?.compression || {};
                    const isCompressedFile = compressionMeta.isCompressed === true;
                    const compressionAlgorithm = compressionMeta.algorithm;

                    // Log the details to help with debugging
                    logger.debug(`GridFS file retrieval for ${filePath}:`, {
                        isTextFile,
                        mimeType,
                        isCompressed: isCompressedFile,
                        algorithm: compressionAlgorithm,
                        bufferLength: buffer.length
                    });

                    // Always encode as base64 string regardless of file type or compression
                    const content = buffer.toString('base64');

                    // Return all necessary metadata for proper decompression
                    resolve({
                        content, // Always base64 encoded
                        metadata: file.metadata || {},
                        size: file.length,
                        uploadDate: file.uploadDate,
                        isCompressed: isCompressedFile,
                        compressionAlgorithm,
                        compressionMetadata: compressionMeta
                    });
                } catch (innerError) {
                    reject(innerError);
                }
            });
        });
    } catch (error) {
        logger.error('GridFS retrieve error:', error);
        throw error;
    }
};

// Delete file from GridFS
const deleteFromGridFS = async (filePath) => {
    try {
        const bucket = getGridFSBucket();

        // Find and delete all files with this filename
        const files = await bucket.find({filename: filePath}).toArray();
        for (const file of files) {
            await bucket.delete(file._id);
        }

         logger.info(`GridFS file deleted: ${filePath}`, {fileCount: files.length});
    } catch (error) {
        logger.error('GridFS delete error:', error);
        throw error;
    }
};

// Rename file in GridFS
const renameInGridFS = async (oldPath, newPath) => {
    try {
        const bucket = getGridFSBucket();

        // Find files with the old filename
        const files = await bucket.find({filename: oldPath}).toArray();
        
        if (files.length === 0) {
            // No GridFS files to rename (might be inline storage)
            return;
        }

        // For each file, copy to new name and delete old one
        for (const file of files) {
            // Read content from old file
            const downloadStream = bucket.openDownloadStream(file._id);
            const chunks = [];
            
            await new Promise((resolve, reject) => {
                downloadStream.on('data', (chunk) => chunks.push(chunk));
                downloadStream.on('error', reject);
                downloadStream.on('end', resolve);
            });
            
            const content = Buffer.concat(chunks);
            
            // Create new file with updated filename
            await new Promise((resolve, reject) => {
                const uploadStream = bucket.openUploadStream(newPath, {
                    metadata: {
                        ...file.metadata,
                        originalPath: newPath,
                        renamedFrom: oldPath,
                        uploadDate: new Date()
                    }
                });

                uploadStream.on('error', reject);
                uploadStream.on('finish', resolve);
                uploadStream.end(content);
            });
            
            // Delete old file
            await bucket.delete(file._id);
        }

        logger.info(`GridFS file renamed: ${oldPath} → ${newPath}`, {fileCount: files.length});
    } catch (error) {
        logger.error('GridFS rename error:', error);
        throw error;
    }
};

// Close database connections and cleanup
const closeDB = async () => {
    try {
        // Close mongoose connection
        if (mongoose.connection.readyState !== 0) {
            await mongoose.connection.close();
            logger.info('🔐 MongoDB connection closed');
        }

        // Close MongoDB Memory Server if it was used
        if (mongoMemoryServer) {
            await mongoMemoryServer.stop();
            mongoMemoryServer = null;
            logger.info('🛑 MongoDB Memory Server stopped');
        }
    } catch (error) {
        logger.error('Error closing database connections:', error);
        throw error;
    }
};

export {
    connectDB,
    closeDB,
    getGridFSBucket,
    storeInGridFS,
    retrieveFromGridFS,
    deleteFromGridFS,
    renameInGridFS
};
