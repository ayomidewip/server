const multer = require('multer');
const path = require('path');
const zlib = require('zlib');
const {promisify} = require('util');
const {storeInGridFS} = require('../config/db');
const File = require('../models/file.model');
const logger = require('../utils/app.logger');

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
    minSizeForCompression: parseInt(process.env.COMPRESSION_MIN_SIZE) || 1024,
    MIN_SIZE_THRESHOLD: parseInt(process.env.COMPRESSION_MIN_SIZE) || 1024,
    MIN_COMPRESSION_RATIO: parseFloat(process.env.COMPRESSION_MIN_RATIO) || 0.05,

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
        // Log incoming file for debugging

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

            // If it's a string, try to convert it to a buffer
            if (typeof buffer === 'string') {
                // Try to detect if it's base64 encoded
                try {
                    buffer = Buffer.from(buffer, 'base64');
                } catch (err) {
                    // If not base64, use utf8
                    buffer = Buffer.from(buffer, 'utf8');
                }
            } else {
                // Convert anything else to string then buffer
                buffer = Buffer.from(String(buffer), 'utf8');
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

// Middleware to handle single file upload
const uploadSingle = (fieldName = 'file') => upload.single(fieldName);

// Middleware to handle multiple file uploads
const uploadMultiple = (fieldName = 'files', maxCount = 20) =>
    upload.array(fieldName, maxCount);

/**
 * Enhanced middleware to process uploaded files with compression
 */
const processUploadedFiles = async (req, res, next) => {
    try {
        if (!req.file && !req.files) {
            return next();
        }

        const files = req.file ? [req.file] : req.files;
        const processedFiles = [];

        for (const file of files) {
            const fileName = file.originalname;
            const mimeType = file.mimetype;
            const originalBuffer = file.buffer;

            logger.info('Processing uploaded file', {
                fileName,
                mimeType,
                originalSize: originalBuffer.length
            });

            // Compress the file if beneficial
            const compressionResult = await compressFileBuffer(originalBuffer, mimeType, fileName);

            // Determine storage type based on compressed file characteristics
            const finalSize = compressionResult.compressedSize;
            const storageType = File.determineStorageType(fileName, finalSize, mimeType);

            // Get the target file path from request
            const basePath = req.body.basePath || '/uploads';
            const targetPath = path.posix.join(basePath, fileName).replace(/\\/g, '/');

            const processedFile = {
                originalName: fileName,
                fileName: fileName,
                filePath: targetPath,
                mimeType: mimeType,
                originalSize: compressionResult.originalSize,
                size: finalSize,
                buffer: compressionResult.buffer,
                storageType: storageType,
                content: null,

                // Compression metadata
                isCompressed: compressionResult.compressed,
                compressionAlgorithm: compressionResult.algorithm,
                compressionRatio: compressionResult.compressionRatio,
                contentEncoding: compressionResult.contentEncoding,
                compressionError: compressionResult.compressionError || null
            };

            // Process content based on storage type
            if (storageType === 'inline') {
                try {
                    if (compressionResult.compressed) {
                        // Store compressed binary data as base64 for inline storage
                        processedFile.content = compressionResult.buffer.toString('base64');
                    } else {
                        // For uncompressed text files, try to store as UTF-8
                        if (File.isTextBasedFile(mimeType)) {
                            processedFile.content = compressionResult.buffer.toString('utf8');
                        } else {
                            processedFile.content = compressionResult.buffer.toString('base64');
                        }
                    }
                } catch (error) {
                    logger.warn(`Failed to convert file content for ${fileName}:`, error.message);
                    processedFile.content = compressionResult.buffer.toString('base64');
                }
            } else {
                // For GridFS storage, pass the buffer directly (compressed or not)
                processedFile.content = compressionResult.buffer;
            }

            processedFiles.push(processedFile);

            logger.info('File processed successfully', {
                fileName,
                storageType,
                isCompressed: processedFile.isCompressed,
                compressionAlgorithm: processedFile.compressionAlgorithm,
                originalSize: processedFile.originalSize,
                finalSize: processedFile.size,
                spaceSaved: processedFile.isCompressed ?
                    ((1 - processedFile.compressionRatio) * 100).toFixed(1) + '%' : '0%'
            });
        }

        // Attach processed files to request
        req.processedFiles = processedFiles;
        next();

    } catch (error) {
        logger.error('File processing error:', {
            error: error.message,
            stack: error.stack,
            fileCount: req.files ? req.files.length : (req.file ? 1 : 0)
        });

        res.status(500).json({
            success: false,
            message: 'Error processing uploaded files',
            error: error.message
        });
    }
};

/**
 * Middleware to decompress file content for download
 */
const decompressFileContent = async (req, res, next) => {
    try {
        // This middleware is used when serving file content
        if (res.locals.fileData && res.locals.fileData.isCompressed) {
            const {content, compressionAlgorithm, fileName} = res.locals.fileData;

            let buffer;
            if (typeof content === 'string') {
                // Convert from base64 if stored as string
                buffer = Buffer.from(content, 'base64');
            } else {
                buffer = content;
            }

            const decompressedBuffer = await decompressFileBuffer(
                buffer,
                compressionAlgorithm,
                fileName
            );

            // Update the response data with decompressed content
            res.locals.fileData.content = decompressedBuffer;
            res.locals.fileData.isCompressed = false;

            // Remove compression-related headers for the client
            res.removeHeader('Content-Encoding');
            res.setHeader('Content-Length', decompressedBuffer.length);
        }

        next();
    } catch (error) {
        logger.error('File decompression error:', {
            error: error.message,
            fileName: res.locals.fileData?.fileName
        });

        res.status(500).json({
            success: false,
            message: 'Error decompressing file',
            error: error.message
        });
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

module.exports = {
    // Core upload functionality
    upload,
    uploadSingle,
    uploadMultiple,
    processUploadedFiles,

    // Compression/decompression functionality
    compressFileBuffer,
    decompressFileBuffer,
    decompressFileContent,
    shouldCompressFile,

    // Enhanced error handling
    handleFileErrors,

    // Monitoring and utilities
    getCompressionStats,
    COMPRESSION_CONFIG,

    // Legacy exports for backward compatibility
    handleUploadErrors: handleFileErrors
};
