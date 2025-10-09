import multer from 'multer';
import path from 'node:path';
import zlib from 'node:zlib';
import {promisify} from 'node:util';
import File from '../models/file.model.js';
import logger from '../utils/app.logger.js';

// File Event Types for WebSocket Notifications
const FILE_EVENTS = {
    // File operations
    FILE_CREATED: 'file:created',
    FILE_DELETED: 'file:deleted',
    FILE_RENAMED: 'file:renamed',
    FILE_MOVED: 'file:moved',
    FILE_UPLOADED: 'file:uploaded',
    
    // Directory operations
    DIRECTORY_CREATED: 'directory:created',
    DIRECTORY_DELETED: 'directory:deleted',
    DIRECTORY_RENAMED: 'directory:renamed',
    
    // Sharing operations
    FILE_SHARED: 'file:shared',
    FILE_UNSHARED: 'file:unshared',
    PERMISSIONS_CHANGED: 'permissions:changed',
    
    // Version operations
    VERSION_PUBLISHED: 'version:published',
    VERSION_DELETED: 'version:deleted',
    VERSION_LOADED: 'version:loaded',
    
    // Presence events
    USER_JOINED_FILE: 'user:joined:file',
    USER_LEFT_FILE: 'user:left:file',
    USER_ONLINE: 'user:online',
    USER_OFFLINE: 'user:offline',
    
    // System events
    CONNECTION_ESTABLISHED: 'connection:established',
    PING: 'ping',
    PONG: 'pong'
};

// Yjs imports for collaborative editing
import * as Y from 'yjs';
import { MongodbPersistence } from 'y-mongodb-provider';
import { RedisPersistence } from 'y-redis';
import mongoose from 'mongoose';
import jwt from 'jsonwebtoken';
import WebSocket from 'ws';
import {redisClient} from './app.middleware.js';

// Promisify zlib functions for async/await usage
const gzip = promisify(zlib.gzip);
const gunzip = promisify(zlib.gunzip);
const deflate = promisify(zlib.deflate);
const inflate = promisify(zlib.inflate);
const brotliCompress = promisify(zlib.brotliCompress);
const brotliDecompress = promisify(zlib.brotliDecompress);

// Compression configuration
const COMPRESSION_CONFIG = {
    // Minimum file size to consider compression (1KB)
    minSizeForCompression: parseInt(process.env.COMPRESSION_MIN_SIZE),
    minCompressionRatio: parseFloat(process.env.COMPRESSION_MIN_RATIO),

    // Compression algorithms and their priorities
    algorithms: {
        brotli: {priority: 1, extension: '.br', contentEncoding: 'br'},
        gzip: {priority: 2, extension: '.gz', contentEncoding: 'gzip'},
        deflate: {priority: 3, extension: '.deflate', contentEncoding: 'deflate'}
    },

    // Compression options
    options: {
        gzip: {level: 6, windowBits: 15, memLevel: 8},
        deflate: {level: 6, windowBits: 15, memLevel: 8},
        brotli: {
            params: {
                [zlib.constants.BROTLI_PARAM_QUALITY]: 6,
                [zlib.constants.BROTLI_PARAM_SIZE_HINT]: 0
            }
        }
    },

    // File types that benefit from compression
    compressibleTypes: [
        'text/',
        'application/json',
        'application/javascript',
        'application/xml',
        'application/x-javascript',
        'application/xhtml+xml',
        'application/rss+xml',
        'application/atom+xml',
        'image/svg+xml',
        'image/bmp',           // Bitmap images (uncompressed)
        'image/tiff',          // TIFF images (often uncompressed)
        'image/x-tiff',        // Alternative TIFF MIME type
        'image/tga',           // Targa images (uncompressed)
        'image/x-tga',         // Alternative TGA MIME type
        'image/ppm',           // Portable Pixmap (uncompressed)
        'image/pgm',           // Portable Graymap (uncompressed)
        'image/pbm',           // Portable Bitmap (uncompressed)
        'image/x-portable-anymap', // Generic portable format
        'model/obj',           // Wavefront OBJ (text-based)
        'model/gltf+json',     // glTF JSON format
        'model/vnd.collada+xml', // COLLADA XML format
        'model/x3d+xml',       // X3D XML format
        'model/vrml'           // VRML (text-based)
    ],

    // File types that should not be compressed (already compressed)
    nonCompressibleTypes: [
        'image/jpeg',
        'image/jpg',
        'image/png',
        'image/gif',
        'image/webp',
        'image/avif',          // Modern compressed format
        'image/heic',          // Apple's compressed format
        'image/heif',          // High Efficiency Image Format
        'image/jxl',           // JPEG XL (modern compressed)
        'image/jp2',           // JPEG 2000
        'image/jpx',           // JPEG 2000 extended
        'video/',
        'audio/',
        'application/zip',
        'application/rar',
        'application/7z',
        'application/gzip',
        'application/x-rar-compressed',
        'application/x-zip-compressed'
    ]
};

// Configure multer for memory storage
const storage = multer.memoryStorage();

// Enhanced file filter with compression considerations
const fileFilter = (req, file, cb) => {
    try {
        // File type blocking can be configured via environment variable
        // BLOCKED_FILE_EXTENSIONS=".exe,.bat,.cmd,.scr,.vbs" (comma-separated)
        // Set to empty string to allow all file types
        const blockedExtensionsEnv = process.env.BLOCKED_FILE_EXTENSIONS;
        const blockedExtensions = blockedExtensionsEnv ?
            blockedExtensionsEnv.split(',').map(ext => ext.trim().toLowerCase()) :
            []; // Default: allow all file types

        const fileExt = path.extname(file.originalname).toLowerCase();

        if (blockedExtensions.length > 0 && blockedExtensions.includes(fileExt)) {
            logger.warn('Blocked file upload attempt', {
                originalname: file.originalname,
                mimetype: file.mimetype,
                extension: fileExt,
                blockedExtensions
            });
            return cb(new Error(`File type ${fileExt} is not allowed for security reasons`), false);
        }

        // Allow all other file types
        cb(null, true);
    } catch (error) {
        logger.error('File filter error:', error);
        cb(error, false);
    }
};

// Create enhanced multer instance
const upload = multer({
    storage,
    fileFilter,
    limits: {
        fileSize: 500 * 1024 * 1024, // 500MB limit (increased for compressed files)
        files: 20, // Max 20 files at once
        fieldNameSize: 200,
        fieldSize: 10 * 1024 * 1024, // 10MB for non-file fields
        fields: 50 // Max 50 non-file fields
    }
});

/**
 * Determine if a file should be compressed based on type and size
 * @param {string} mimeType - File MIME type
 * @param {number} size - File size in bytes
 * @returns {boolean} - Whether file should be compressed
 */
const shouldCompressFile = (mimeType, size) => {
    // Don't compress files smaller than threshold
    if (size < COMPRESSION_CONFIG.minSizeForCompression) {
        return false;
    }

    // Don't compress already compressed formats
    if (COMPRESSION_CONFIG.nonCompressibleTypes.some(type => mimeType.startsWith(type))) {
        return false;
    }

    // Compress compressible types
    return COMPRESSION_CONFIG.compressibleTypes.some(type => mimeType.startsWith(type));
};

/**
 * Compress file buffer using the best available algorithm
 * @param {Buffer} buffer - File buffer to compress
 * @param {string} mimeType - File MIME type
 * @param {string} fileName - Original file name
 * @returns {Object} - Compressed data with metadata
 */
const compressFileBuffer = async (buffer, mimeType, fileName) => {
    try {
        if (!shouldCompressFile(mimeType, buffer.length)) {
            return {
                compressed: false,
                buffer: buffer,
                originalSize: buffer.length,
                compressedSize: buffer.length,
                compressionRatio: 1,
                algorithm: 'none',
                contentEncoding: null
            };
        }

        const originalSize = buffer.length;
        let bestResult = null;
        let bestRatio = 1;

        // Try different compression algorithms and pick the best one
        const algorithms = ['brotli', 'gzip', 'deflate'];

        for (const algorithm of algorithms) {
            try {
                let compressed;
                const options = COMPRESSION_CONFIG.options[algorithm];

                switch (algorithm) {
                    case 'brotli':
                        compressed = await brotliCompress(buffer, options);
                        break;
                    case 'gzip':
                        compressed = await gzip(buffer, options);
                        break;
                    case 'deflate':
                        compressed = await deflate(buffer, options);
                        break;
                }

                const compressionRatio = compressed.length / originalSize;

                if (compressionRatio < bestRatio) {
                    bestRatio = compressionRatio;
                    bestResult = {
                        compressed: true,
                        buffer: compressed,
                        originalSize: originalSize,
                        compressedSize: compressed.length,
                        compressionRatio: compressionRatio,
                        algorithm: algorithm,
                        contentEncoding: COMPRESSION_CONFIG.algorithms[algorithm].contentEncoding
                    };
                }

            } catch (compressionError) {
                logger.warn(`Failed to compress with ${algorithm}:`, {
                    fileName,
                    error: compressionError.message
                });
            }
        }

        // If compression didn't improve size significantly (less than 5% reduction), don't compress
        if (bestRatio > 0.95) {

            return {
                compressed: false,
                buffer: buffer,
                originalSize: originalSize,
                compressedSize: originalSize,
                compressionRatio: 1,
                algorithm: 'none',
                contentEncoding: null
            };
        }

        logger.info('File compressed successfully', {
            fileName,
            algorithm: bestResult.algorithm,
            originalSize,
            compressedSize: bestResult.compressedSize,
            compressionRatio: bestRatio,
            spaceSaved: ((1 - bestRatio) * 100).toFixed(1) + '%'
        });

        return bestResult;

    } catch (error) {
        logger.error('Compression error:', {
            fileName,
            error: error.message,
            stack: error.stack
        });

        // Return uncompressed data on error
        return {
            compressed: false,
            buffer: buffer,
            originalSize: buffer.length,
            compressedSize: buffer.length,
            compressionRatio: 1,
            algorithm: 'none',
            contentEncoding: null,
            compressionError: error.message
        };
    }
};

/**
 * Decompress file buffer using the specified algorithm
 * @param {Buffer} buffer - Compressed buffer
 * @param {string} algorithm - Compression algorithm used
 * @param {string} fileName - File name for logging
 * @returns {Buffer} - Decompressed buffer
 */
const decompressFileBuffer = async (buffer, algorithm, fileName) => {
    try {
        if (!algorithm || algorithm === 'none') {
            return buffer;
        }

        // Ensure we have a proper buffer to decompress
        if (!Buffer.isBuffer(buffer)) {
            logger.warn('Non-buffer passed to decompressFileBuffer, converting', {
                fileName,
                algorithm,
                contentType: typeof buffer,
                length: buffer ? buffer.length : 0
            });

            // Always assume content is base64 encoded
            if (typeof buffer === 'string') {
                buffer = Buffer.from(buffer, 'base64');
            } else {
                // For any other type, convert to string and assume it's base64
                buffer = Buffer.from(String(buffer), 'base64');
            }
        }

        let decompressed;

        switch (algorithm) {
            case 'brotli':
                decompressed = await brotliDecompress(buffer);
                break;
            case 'gzip':
                decompressed = await gunzip(buffer);
                break;
            case 'deflate':
                decompressed = await inflate(buffer);
                break;
            default:
                throw new Error(`Unsupported compression algorithm: ${algorithm}`);
        }

        return decompressed;

    } catch (error) {
        logger.error('Decompression error:', {
            fileName,
            algorithm,
            error: error.message,
            stack: error.stack
        });
        throw new Error(`Failed to decompress file: ${error.message}`);
    }
};

/**
 * Enhanced error handling middleware for file operations
 */
const handleFileErrors = (err, req, res, next) => {
    if (err instanceof multer.MulterError) {
        let message = 'File upload error';
        let statusCode = 400;

        switch (err.code) {
            case 'LIMIT_FILE_SIZE':
                message = 'File too large. Maximum size is 500MB per file.';
                break;
            case 'LIMIT_FILE_COUNT':
                message = 'Too many files. Maximum 20 files allowed.';
                break;
            case 'LIMIT_UNEXPECTED_FILE':
                message = 'Unexpected file field.';
                break;
            case 'LIMIT_PART_COUNT':
                message = 'Too many parts in multipart form.';
                break;
            case 'LIMIT_FIELD_KEY':
                message = 'Field name too long.';
                break;
            case 'LIMIT_FIELD_VALUE':
                message = 'Field value too long.';
                break;
            case 'LIMIT_FIELD_COUNT':
                message = 'Too many fields.';
                break;
            default:
                message = `Upload error: ${err.message}`;
        }

        logger.warn('File upload error', {
            code: err.code,
            message: err.message,
            field: err.field
        });

        return res.status(statusCode).json({
            success: false,
            message: message,
            code: err.code
        });
    }

    // Handle compression/decompression errors
    if (err.message && err.message.includes('decompress')) {
        logger.error('File decompression error:', err);
        return res.status(500).json({
            success: false,
            message: 'Error processing compressed file',
            error: err.message
        });
    }

    // Pass other errors to the next error handler
    next(err);
};

/**
 * Get compression statistics for monitoring
 */
const getCompressionStats = (originalSize, compressedSize, algorithm) => {
    // If called with parameters, return individual file statistics
    if (typeof originalSize === 'number' && typeof compressedSize === 'number' && algorithm) {
        const compressionRatio = compressedSize / originalSize;
        const spaceSaved = originalSize - compressedSize;
        const compressionPercentage = Math.round((spaceSaved / originalSize) * 100);

        return {
            originalSize,
            compressedSize,
            algorithm,
            compressionRatio,
            spaceSaved,
            compressionPercentage
        };
    }

    // Otherwise return system configuration statistics
    return {
        config: {
            minSizeForCompression: COMPRESSION_CONFIG.minSizeForCompression,
            algorithms: Object.keys(COMPRESSION_CONFIG.algorithms),
            compressibleTypes: COMPRESSION_CONFIG.compressibleTypes.length,
            nonCompressibleTypes: COMPRESSION_CONFIG.nonCompressibleTypes.length
        },
        capabilities: {
            brotli: typeof zlib.brotliCompress === 'function',
            gzip: typeof zlib.gzip === 'function',
            deflate: typeof zlib.deflate === 'function'
        }
    };
};

// =============================================================================
// YJS REDIS ADAPTER FOR HORIZONTAL SCALING
// =============================================================================

/**
 * Redis Pub/Sub Adapter for Yjs Collaborative Editing
 * 
 * Provides horizontal scaling capabilities for Yjs documents across multiple server instances
 * using Redis pub/sub messaging. This enables real-time synchronization of document updates
 * between different server instances in a multi-server deployment.
 * 
 * Features:
 * - Redis pub/sub for cross-server document synchronization
 * - Integration with existing MongoDB persistence
 * - Connection management and error handling
 * - Document-specific channels for efficient message routing
 * - Graceful degradation when Redis is unavailable
 */
class YjsRedisAdapter {
    constructor(redisClient, options = {}) {
        this.redisClient = redisClient;
        this.persistence = null;
        this.documents = new Map(); // docName -> PersistenceDoc
        this.isEnabled = options.enabled !== false;
        this.prefix = options.prefix || 'yjs:';

        this.config = {
            channelPrefix: options.channelPrefix || 'yjs-doc:',
            redisOpts: options.redisOpts,
            ...options
        };

        this.isInitialized = false;
        this.isConnected = false;
    }

    getRedisOptions() {
        if (this.config.redisOpts) {
            return this.config.redisOpts;
        }

        const clientOptions = this.redisClient?.options ?? {};
        const {url, socket = {}, username, password, database} = clientOptions;

        if (url) {
            return {url};
        }

        const redisOpts = {};

        if (socket.host) {
            redisOpts.host = socket.host;
        }

        if (socket.port) {
            redisOpts.port = socket.port;
        }

        if (username) {
            redisOpts.username = username;
        }

        if (password) {
            redisOpts.password = password;
        }

        if (typeof database === 'number') {
            redisOpts.db = database;
        }

        return redisOpts;
    }

    async initialize() {
        if (this.isInitialized) {
            logger.warn('[YjsRedisAdapter] Already initialized');
            return;
        }

        if (!this.isEnabled) {
            logger.info('[YjsRedisAdapter] Redis pub/sub disabled');
            return;
        }

        try {
            const redisOpts = this.getRedisOptions();
            this.persistence = new RedisPersistence({redisOpts});
            this.isInitialized = true;
            this.isConnected = true;
            logger.info('[YjsRedisAdapter] Redis persistence initialized for Yjs scaling');
        } catch (error) {
            logger.error('[YjsRedisAdapter] Failed to initialize Redis persistence:', {
                error: error.message,
                stack: error.stack
            });
            await this.cleanup();
            throw error;
        }
    }

    async getAdapter(docName) {
        if (!this.isEnabled || !this.isInitialized || !this.persistence) {
            return null;
        }

        return this.documents.get(docName) ?? null;
    }

    async removeAdapter(docName) {
        const adapter = this.documents.get(docName);
        if (!adapter) {
            return;
        }

        try {
            if (typeof adapter.destroy === 'function') {
                await adapter.destroy();
            }
        } catch (error) {
            logger.error('[YjsRedisAdapter] Error removing adapter:', {
                docName,
                error: error.message
            });
        } finally {
            this.documents.delete(docName);
        }
    }

    async bindDocument(docName, ydoc) {
        if (!this.isEnabled || !this.isInitialized || !this.persistence) {
            return null;
        }

        try {
            const persistenceDoc = this.persistence.bindState(docName, ydoc);
            this.documents.set(docName, persistenceDoc);
            return persistenceDoc;
        } catch (error) {
            logger.error('[YjsRedisAdapter] Failed to bind document to Redis persistence:', {
                docName,
                error: error.message
            });
            return null;
        }
    }

    async unbindDocument(docName, ydoc) {
        if (!this.documents.has(docName)) {
            return;
        }

        try {
            await this.removeAdapter(docName);
            if (this.persistence && typeof this.persistence.closeDoc === 'function') {
                await this.persistence.closeDoc(docName);
            }
        } catch (error) {
            logger.error('[YjsRedisAdapter] Error unbinding document:', {
                docName,
                hasYDoc: !!ydoc,
                error: error.message
            });
        }
    }

    getStats() {
        return {
            isEnabled: this.isEnabled,
            isInitialized: this.isInitialized,
            isConnected: this.isConnected && !!this.persistence,
            activeAdapters: this.documents.size,
            reconnectAttempts: 0,
            maxReconnectAttempts: 0,
            documents: Array.from(this.documents.keys())
        };
    }

    async healthCheck() {
        if (!this.isEnabled) {
            return {status: 'disabled', message: 'Redis pub/sub is disabled'};
        }

        if (!this.isInitialized || !this.persistence) {
            return {status: 'not_initialized', message: 'Redis persistence not initialized'};
        }

        try {
            if (typeof this.redisClient?.ping === 'function') {
                await this.redisClient.ping();
            }

            return {
                status: 'healthy',
                message: 'Redis persistence is operational',
                stats: this.getStats()
            };
        } catch (error) {
            return {
                status: 'unhealthy',
                message: `Redis health check failed: ${error.message}`,
                error: error.message
            };
        }
    }

    async cleanup() {
        const adapters = Array.from(this.documents.entries());
        for (const [docName, adapter] of adapters) {
            try {
                if (adapter && typeof adapter.destroy === 'function') {
                    await adapter.destroy();
                }
            } catch (error) {
                logger.warn(`[YjsRedisAdapter] Error cleaning up adapter for ${docName}:`, error.message);
            }
        }

        this.documents.clear();

        if (this.persistence) {
            try {
                await this.persistence.destroy();
            } catch (error) {
                logger.warn('[YjsRedisAdapter] Error destroying Redis persistence:', error.message);
            }
        }

        this.persistence = null;
        this.isInitialized = false;
        this.isConnected = false;
    }

    async destroy() {
        await this.cleanup();
    }
}

// =============================================================================
// YJS SERVICE FOR COLLABORATIVE EDITING
// =============================================================================

/**
 * Yjs Service for collaborative text editing with MongoDB persistence and Redis scaling
 * Manages document lifecycle, content synchronization, and cross-server communication
 */
class YjsService {
    constructor() {
        this.persistence = null;
        this.redisAdapter = null;
        this.isInitialized = false;
        this.documents = new Map(); // Cache for persistent Yjs documents
        
        this.config = {
            collectionName: process.env.YJS_COLLECTION_NAME,
            flushSize: parseInt(process.env.YJS_FLUSH_SIZE),
            debounceDelay: parseInt(process.env.YJS_DEBOUNCE_DELAY),
            // Redis pub/sub configuration
            redisEnabled: process.env.YJS_REDIS_ENABLED === 'true',
            redisPrefix: process.env.YJS_REDIS_PREFIX,
            redisChannelPrefix: process.env.YJS_REDIS_CHANNEL_PREFIX
        };
    }

    /**
     * Validate required configuration values
     */
    validateConfig() {
        const requiredFields = [
            'collectionName',
            'flushSize',
            'debounceDelay',
            'redisPrefix',
            'redisChannelPrefix'
        ];

        const missingFields = [];
        
        for (const field of requiredFields) {
            if (!this.config[field] && this.config[field] !== 0) {
                missingFields.push(`YJS_${field.replace(/([A-Z])/g, '_$1').toUpperCase()}`);
            }
        }

        // Check for invalid numeric values
        if (isNaN(this.config.flushSize) || this.config.flushSize <= 0) {
            missingFields.push('YJS_FLUSH_SIZE (must be a positive integer)');
        }
        
        if (isNaN(this.config.debounceDelay) || this.config.debounceDelay < 0) {
            missingFields.push('YJS_DEBOUNCE_DELAY (must be a non-negative integer)');
        }

        if (missingFields.length > 0) {
            throw new Error(`Missing or invalid Yjs configuration environment variables: ${missingFields.join(', ')}. Please check your .env file.`);
        }
    }

    /**
     * Initialize the Yjs persistence layer with Redis pub/sub scaling
     */
    async initialize() {
        if (this.isInitialized) {
            return this.persistence;
        }

        try {
            // Validate configuration when initializing
            this.validateConfig();
            
            // Get existing Mongoose connection to reuse it
            if (mongoose.connection.readyState === 1) {
                // Use existing Mongoose connection for Y-MongoDB provider
                const mongoClient = mongoose.connection.getClient();
                const db = mongoose.connection.db;
                
                this.persistence = new MongodbPersistence({
                    client: mongoClient,
                    db: db
                }, {
                    collectionName: this.config.collectionName,
                    flushSize: this.config.flushSize,
                    multipleCollections: false
                });
                
                logger.info('YJS: Using existing Mongoose connection', {
                    database: db.databaseName,
                    collection: this.config.collectionName
                });
            } else {
                // Fallback to connection string if Mongoose not connected
                logger.info('YJS: Using connection string for MongoDB persistence');
                this.persistence = new MongodbPersistence(process.env.MONGODB_URI, {
                    collectionName: this.config.collectionName,
                    flushSize: this.config.flushSize,
                    multipleCollections: false
                });
            }

            // Initialize Redis pub/sub adapter for scaling
            if (this.config.redisEnabled) {
                try {
                    this.redisAdapter = new YjsRedisAdapter(redisClient, {
                        enabled: this.config.redisEnabled,
                        prefix: this.config.redisPrefix,
                        channelPrefix: this.config.redisChannelPrefix
                    });

                    await this.redisAdapter.initialize();
                    
                    logger.info('YjsService initialized with Redis pub/sub scaling', {
                        collectionName: this.config.collectionName,
                        flushSize: this.config.flushSize,
                        redisEnabled: true
                    });
                } catch (redisError) {
                    logger.warn('Redis pub/sub initialization failed, continuing with MongoDB-only persistence', {
                        error: redisError.message
                    });
                    this.redisAdapter = null;
                }
            } else {
                logger.info('Redis pub/sub scaling disabled');
            }

            this.isInitialized = true;
            
            logger.info('YjsService initialized', {
                collectionName: this.config.collectionName,
                flushSize: this.config.flushSize,
                redisEnabled: !!this.redisAdapter
            });

            return this.persistence;
        } catch (error) {
            logger.error('Failed to initialize YjsService', { error: error.message });
            throw error;
        }
    }

    /**
     * Get document name from file path (simple hash for Yjs document identification)
     * Must match client-side implementation AND WebSocket server naming convention
     */
    getDocumentName(filePath) {
        // Normalize the path
        let normalizedPath = filePath.replace(/\\/g, '/').replace(/\/+/g, '/');
        
        // Ensure path starts with /
        if (!normalizedPath.startsWith('/')) {
            normalizedPath = '/' + normalizedPath;
        }
        
        // WebSocket server uses the URL path but strips the leading slash
        // So for URL path "/yjs/base/file", the WebSocket document name is "yjs/base/file"
        if (normalizedPath.startsWith('/yjs/')) {
            // Already has the WebSocket prefix, remove leading slash to match WebSocket server
            return normalizedPath.slice(1);
        } else {
            // Add the WebSocket prefix and remove leading slash to match WebSocket server
            return 'yjs' + normalizedPath;
        }
    }



    /**
     * Get existing Yjs document (pure retrieval, no modification)
     * Standard pattern: documents should already exist from create/move/rename/copy operations
     */
    async getDocument(filePath) {
        if (!this.persistence) {
            throw new Error('YjsService not initialized');
        }

        const docName = this.getDocumentName(filePath);
        
        // Always get fresh document from persistence to ensure latest content
        // This is critical for version publishing to capture current collaborative edits
        const ydoc = await this.persistence.getYDoc(docName);
        
        // Update cache with fresh document
        this.documents.set(docName, ydoc);
        
        return ydoc;
    }

    /**
     * Get text content from a Yjs document (returns empty string if no content)
     */
    async getTextContent(filePath) {
        try {
            if (!filePath) {
                throw new Error('File path is required to get text content');
            }
            
            const ydoc = await this.getDocument(filePath);
            const content = ydoc.getText('content').toString();
            
            return content;
        } catch (error) {
            logger.error('Failed to get text content:', { filePath, error: error.message });
            throw error;
        }
    }

    /**
     * Get document metadata including last modified time from Yjs document
     * Enhanced to check MongoDB Yjs persistence for more accurate timestamps
     */
    async getDocumentMetadata(filePath) {
        try {
            if (!filePath) {
                throw new Error('File path is required to get document metadata');
            }

            const docName = this.getDocumentName(filePath);
            const ydoc = await this.getDocument(filePath);
            const ytext = ydoc.getText('content');
            const content = ytext.toString();
            const hasContent = content.length > 0;

            // Check MongoDB Yjs collection for last modified timestamp
            let lastModified = new Date();
            let hasPersistedData = false;

            if (this.persistence && hasContent) {
                try {
                    // Access MongoDB Yjs collection directly to get document metadata
                    if (mongoose.connection.readyState === 1) {
                        const db = mongoose.connection.db;
                        const yjsCollection = db.collection(this.config.collectionName);
                        
                        // Find the most recent document entry for this document
                        const latestEntry = await yjsCollection
                            .findOne(
                                { docName: docName },
                                { sort: { clock: -1 } }
                            );

                        if (latestEntry && latestEntry._id) {
                            // Use the MongoDB ObjectId timestamp as the last modified time
                            lastModified = latestEntry._id.getTimestamp();
                            hasPersistedData = true;
                        }
                    }
                } catch (persistenceError) {
                    logger.debug('Could not get Yjs persistence timestamp:', {
                        filePath,
                        docName,
                        error: persistenceError.message
                    });
                }
            }

            return {
                filePath,
                docName,
                hasContent,
                contentLength: content.length,
                lastModified,
                hasPersistedData,
                isActive: this.documents.has(docName)
            };

        } catch (error) {
            logger.error('Failed to get document metadata:', { filePath, error: error.message });
            return {
                filePath,
                hasContent: false,
                contentLength: 0,
                lastModified: new Date(),
                hasPersistedData: false,
                isActive: false
            };
        }
    }

    /**
     * Get bulk document metadata for statistics - simplified version
     * Returns which text files actually have content (were edited)
     */
    async getBulkDocumentMetadata(filePaths) {
        try {
            if (!Array.isArray(filePaths) || filePaths.length === 0) {
                return [];
            }

            const metadataResults = await Promise.allSettled(
                filePaths.map(filePath => this.getDocumentMetadata(filePath))
            );

            return metadataResults
                .filter(result => result.status === 'fulfilled')
                .map(result => result.value);

        } catch (error) {
            logger.error('Failed to get bulk document metadata:', { 
                fileCount: filePaths?.length || 0, 
                error: error.message 
            });
            return [];
        }
    }



    /**
     * Create and initialize a Yjs document with content (ONLY for file creation)
     * This is the standard way to create documents with initial content
     */
    async initializeTextContent(filePath, initialContent) {
        try {
            const docName = this.getDocumentName(filePath);
            
            // Get fresh document from persistence (may already exist if file was restored)
            const ydoc = await this.persistence.getYDoc(docName);
            const ytext = ydoc.getText('content');
            
            // Initialize with content if provided and document is empty
            if (initialContent && initialContent.trim() !== '' && ytext.toString().length === 0) {
                ytext.insert(0, initialContent);
                
                // Persist the initial content to database
                await this.persistence.storeUpdate(docName, Y.encodeStateAsUpdate(ydoc));
            }
            
            // Cache the document
            this.documents.set(docName, ydoc);
            
        } catch (error) {
            logger.error('Failed to initialize YJS document:', {
                filePath,
                error: error.message
            });
            throw error;
        }
    }

    /**
     * Copy Yjs document from one path to another
     * Creates a new document with the same content at the new path
     */
    async copyDocument(fromPath, toPath) {
        try {
            if (!fromPath || !toPath) {
                throw new Error('Both source and destination paths are required');
            }
            
            if (fromPath === toPath) {
                logger.warn('YJS DOCUMENT COPY: Source and destination are identical, skipping', {
                    path: fromPath
                });
                return;
            }
            
            // Get source document and create new target document
            const sourceDoc = await this.getDocument(fromPath);
            const targetDoc = await this.getDocument(toPath);
            
            // Copy content from source to target document
            const sourceText = sourceDoc.getText('content');
            const targetText = targetDoc.getText('content');
            const sourceContent = sourceText.toString();
            
            if (sourceContent && targetText.toString().length === 0) {
                targetText.insert(0, sourceContent);
                
                // Force persistence of the target document
                if (this.persistence) {
                    const targetDocName = this.getDocumentName(toPath);
                    await this.persistence.storeUpdate(targetDocName, Y.encodeStateAsUpdate(targetDoc));
                }
            }
        } catch (error) {
            logger.error('Failed to copy YJS document:', {
                fromPath,
                toPath,
                error: error.message
            });
            throw error;
        }
    }





    /**
     * Move Yjs document from one path to another
     * Updates the document path in the persistence layer
     */
    async moveDocument(fromPath, toPath) {
        try {
            if (!fromPath || !toPath) {
                throw new Error('Both source and destination paths are required');
            }
            
            const sourceDocName = this.getDocumentName(fromPath);
            const targetDocName = this.getDocumentName(toPath);
            
            // Skip if source and target are the same
            if (sourceDocName === targetDocName) {
                return;
            }
            
            // Ensure document is synchronized before move operation
            // Note: The WebSocket server handles persistence automatically
            // Add buffer to allow any pending operations and persistence to complete
            await new Promise(resolve => setTimeout(resolve, 250));
            
            // Get source document
            const sourceDoc = await this.getDocument(fromPath);
            const sourceText = sourceDoc.getText('content');
            const sourceContent = sourceText.toString();
            
            // Create target document
            const targetDoc = await this.getDocument(toPath);
            const targetText = targetDoc.getText('content');
            const existingTargetContent = targetText.toString();
            
            // Only copy content if target is empty to avoid overwriting
            if (sourceContent && existingTargetContent.length === 0) {
                targetText.insert(0, sourceContent);
                
                // Verify content was copied correctly
                const copiedContent = targetText.toString();
                if (copiedContent !== sourceContent) {
                    logger.error('Content copy verification failed during move:', {
                        fromPath,
                        toPath,
                        sourceLength: sourceContent.length,
                        targetLength: copiedContent.length
                    });
                }
                
                // Force persistence of the target document
                if (this.persistence) {
                    await this.persistence.storeUpdate(targetDocName, Y.encodeStateAsUpdate(targetDoc));
                }
            }
            
            // Clean up the source document from both cache and persistence
            this.documents.delete(sourceDocName);
            
            // Clean up source document from MongoDB persistence
            if (this.persistence) {
                try {
                    await this.persistence.clearDocument(sourceDocName);
                } catch (persistenceError) {
                    logger.warn('Failed to clear source document from persistence:', {
                        sourceDocName,
                        error: persistenceError.message
                    });
                }
            }
        } catch (error) {
            logger.error('Failed to move YJS document:', {
                fromPath,
                toPath,
                error: error.message
            });
            throw error;
        }
    }

    /**
     * Bind Redis adapter to a Yjs document for cross-server synchronization
     */
    async bindRedisAdapter(docName, ydoc) {
        if (!this.redisAdapter) {
            return null; // No Redis adapter available
        }

        try {
            return await this.redisAdapter.bindDocument(docName, ydoc);
        } catch (error) {
            logger.error('Failed to bind Redis adapter to document', {
                docName,
                error: error.message
            });
            return null;
        }
    }

    /**
     * Unbind Redis adapter from a Yjs document
     */
    async unbindRedisAdapter(docName, ydoc) {
        if (!this.redisAdapter) {
            return;
        }

        try {
            await this.redisAdapter.unbindDocument(docName, ydoc);
        } catch (error) {
            logger.error('Failed to unbind Redis adapter from document', {
                docName,
                error: error.message
            });
        }
    }

    /**
     * Get Redis adapter statistics
     */
    getRedisStats() {
        if (!this.redisAdapter) {
            return { enabled: false, message: 'Redis adapter not initialized' };
        }

        return this.redisAdapter.getStats();
    }

    /**
     * Health check for Redis adapter
     */
    async redisHealthCheck() {
        if (!this.redisAdapter) {
            return { status: 'disabled', message: 'Redis adapter not initialized' };
        }

        return await this.redisAdapter.healthCheck();
    }

    /**
     * Get persistence instance for WebSocket server setup
     */
    getPersistence() {
        return this.persistence;
    }

    /**
     * Get Redis adapter instance
     */
    getRedisAdapter() {
        return this.redisAdapter;
    }

    /**
     * Cleanup resources
     */
    async destroy() {
        // Clear document cache
        if (this.documents) {
            this.documents.clear();
            logger.debug('Yjs document cache cleared');
        }

        // Cleanup Redis adapter
        if (this.redisAdapter) {
            try {
                await this.redisAdapter.destroy();
                logger.info('Redis adapter cleaned up');
            } catch (error) {
                logger.warn('Error cleaning up Redis adapter:', error.message);
            }
            this.redisAdapter = null;
        }

        if (this.persistence) {
            // MongodbPersistence doesn't have explicit cleanup methods
            // Just clear the reference
            this.persistence = null;
        }
        
        this.isInitialized = false;
        logger.info('YjsService destroyed');
    }
}

/**
 * File Notification Service
 * Handles real-time notifications for file operations (separate from Yjs collaboration)
 * Integrated into file middleware for better architectural organization
 */
class FileNotificationService {
    constructor() {
        this.wss = null;
        this.connections = new Map(); // userId -> Set of WebSocket connections
        this.userSessions = new Map(); // userId -> user info
    }

    /**
     * Initialize notification service (without creating a separate server)
     * Connections will be routed from the main WebSocket server
     */
    initialize() {
        // No separate WebSocket server needed - connections routed from main server
        logger.info('🔔 File notification service initialized on /notifications path');
    }

    /**
     * Handle new WebSocket connection
     */
    async handleConnection(ws, req) {
        try {
            // JWT is available via top-level import

            // Extract token from query parameters or headers
            const url = new URL(req.url, `http://${req.headers.host}`);
            const token = url.searchParams.get('token') || req.headers.authorization?.replace('Bearer ', '');

            if (!token) {
                ws.close(1008, 'Authentication token required');
                return;
            }

            // Verify JWT token
            const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
            const userId = decoded.id;

            // Store connection
            if (!this.connections.has(userId)) {
                this.connections.set(userId, new Set());
            }
            this.connections.get(userId).add(ws);

            // Store user session info
            this.userSessions.set(userId, {
                id: userId,
                username: decoded.username,
                connectedAt: new Date()
            });

            logger.debug('📱 File notification WebSocket connected', { userId, username: decoded.username });

            // Handle connection close
            ws.on('close', () => {
                this.removeConnection(userId, ws);
            });

            // Handle incoming messages (for subscriptions, etc.)
            ws.on('message', (data) => {
                this.handleMessage(userId, ws, data);
            });

            // Send connection confirmation
            this.sendToConnection(ws, {
                type: 'connection:established',
                data: { userId, timestamp: new Date().toISOString() }
            });

        } catch (error) {
            if (error.name === 'JsonWebTokenError') {
                logger.warn('Invalid JWT token for file notification WebSocket', { error: error.message });
                ws.close(1008, 'Invalid authentication token');
            } else {
                logger.error('File notification WebSocket authentication failed:', error);
                ws.close(1008, 'Authentication failed');
            }
        }
    }

    /**
     * Handle incoming WebSocket messages
     */
    handleMessage(userId, ws, data) {
        try {
            const message = JSON.parse(data);
            
            switch (message.type) {
                case 'ping':
                    this.sendToConnection(ws, { type: 'pong', timestamp: new Date().toISOString() });
                    break;
                default:
                    logger.warn('Unknown message type:', message.type);
            }
        } catch (error) {
            logger.error('Error handling WebSocket message:', error);
        }
    }

    /**
     * Remove connection when client disconnects
     */
    removeConnection(userId, ws) {
        const userConnections = this.connections.get(userId);
        if (userConnections) {
            userConnections.delete(ws);
            if (userConnections.size === 0) {
                this.connections.delete(userId);
                this.userSessions.delete(userId);
            }
        }
        logger.debug('📱 File notification WebSocket disconnected', { userId });
    }



    /**
     * Send notification to specific user
     */
    sendToUser(userId, notification) {
        const userConnections = this.connections.get(userId);
        if (userConnections && userConnections.size > 0) {
            userConnections.forEach(ws => {
                if (ws.readyState === WebSocket.OPEN) {
                    this.sendToConnection(ws, notification);
                }
            });
            return true;
        }
        return false;
    }

    /**
     * Send notification to multiple users
     */
    sendToUsers(userIds, notification) {
        const sentCount = userIds.reduce((count, userId) => {
            return this.sendToUser(userId, notification) ? count + 1 : count;
        }, 0);
        
        logger.debug('📤 File notification sent', { 
            type: notification.type, 
            totalUsers: userIds.length, 
            connectedUsers: sentCount 
        });
        
        return sentCount;
    }

    /**
     * Send notification to specific WebSocket connection
     */
    sendToConnection(ws, notification) {
        try {
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({
                    ...notification,
                    timestamp: notification.timestamp || new Date().toISOString()
                }));
            }
        } catch (error) {
            logger.error('Error sending WebSocket notification:', error);
        }
    }

    /**
     * Broadcast file operation notification to all users with access
     * @param {string} eventType - The type of event (FILE_EVENTS constant)
     * @param {object} eventData - Event data to send
     * @param {string|array} filePathOrUsers - Either a filePath to look up users, or array of user IDs to notify directly
     */
    async broadcastFileEvent(eventType, eventData, filePathOrUsers) {
        try {
            let affectedUsers = [];
            let lookupPath = null;

            // Determine if we're given user IDs directly or need to look up the file
            if (Array.isArray(filePathOrUsers)) {
                // Direct user IDs provided (for delete/rename where file may not exist)
                affectedUsers = filePathOrUsers;
            } else {
                // File path provided - look up the file to get users
                lookupPath = filePathOrUsers;
                const file = await File.findOne({ filePath: lookupPath })
                    .populate('owner', '_id username')
                    .populate('permissions.read', '_id username')
                    .populate('permissions.write', '_id username');

                if (!file) {
                    logger.warn('File not found for notification broadcast:', lookupPath);
                    return 0;
                }

                // Collect all user IDs with access
                const userSet = new Set();
                userSet.add(file.owner._id.toString());
                
                file.permissions.read.forEach(user => userSet.add(user._id.toString()));
                file.permissions.write.forEach(user => userSet.add(user._id.toString()));
                
                affectedUsers = Array.from(userSet);
            }

            // Create notification payload
            const notification = {
                type: eventType,
                data: eventData
            };

            // Send to all affected users
            const sentCount = this.sendToUsers(affectedUsers, notification);
            
            logger.info('📢 File event broadcasted', {
                eventType,
                filePath: eventData.filePath || eventData.oldFilePath || lookupPath,
                affectedUsers: affectedUsers.length,
                connectedUsers: sentCount
            });

            return sentCount;

        } catch (error) {
            logger.error('Error broadcasting file event:', error);
            return 0;
        }
    }

    /**
     * Shutdown the notification service
     */
    shutdown() {
        this.connections.clear();
        this.userSessions.clear();
        logger.info('🔔 File notification service shut down');
    }
}

// Create singleton instance
let fileNotificationService = null;

const getFileNotificationService = () => {
    if (!fileNotificationService) {
        fileNotificationService = new FileNotificationService();
    }
    return fileNotificationService;
};

// Create singleton instance only when explicitly needed
let yjsService = null;

const getYjsService = () => {
    if (!yjsService) {
        yjsService = new YjsService();
    }
    return yjsService;
};

// Graceful shutdown handling
const gracefulShutdown = async () => {
    if (yjsService) {
        logger.info('Graceful shutdown initiated, cleaning up Yjs service...');
        await yjsService.destroy();
        yjsService = null;
    }
};

// Only register shutdown handlers once
if (!process.listenerCount('SIGTERM')) {
    process.on('SIGTERM', gracefulShutdown);
}

if (!process.listenerCount('SIGINT')) {
    process.on('SIGINT', gracefulShutdown);
}

export {
    // Core upload functionality
    upload,

    // Compression/decompression functionality (used by WebSocket operations)
    compressFileBuffer,
    decompressFileBuffer,
    shouldCompressFile,

    // Enhanced error handling
    handleFileErrors,

    // Monitoring and utilities
    getCompressionStats,
    COMPRESSION_CONFIG,

    // Yjs collaborative editing functionality
    YjsRedisAdapter,
    YjsService,
    getYjsService,

    // File notification functionality
    FileNotificationService,
    getFileNotificationService,
    
    // File event constants
    FILE_EVENTS
};
