const File = require('../models/file.model');
const {asyncHandler} = require('../middleware/app.middleware');
const {AppError} = require('../middleware/error.middleware');
const {hasRight, RIGHTS} = require('../config/rights');
const {cache} = require('../middleware/cache.middleware');
const logger = require('../utils/app.logger');
const {sanitizeHtmlInObject} = require('../utils/sanitize');
const crypto = require('crypto');
const mongoose = require('mongoose');
const path = require('path');
const {parseFilters} = require('./app.controller');
const {getCompressionStats, compressFileBuffer, decompressFileBuffer} = require('../middleware/file.middleware');

// Import Yjs service from middleware
const { getYjsService, getFileNotificationService, FILE_EVENTS } = require('../middleware/file.middleware');
const yjsService = getYjsService();

// Import notification service from file middleware
const notificationService = getFileNotificationService();

// Auto-save persistence tracking
// =============================================================================
// COMPRESSION HELPER
// =============================================================================

/**
 * Store content in file - binary files only (text files use Yjs collaborative editing)
 */
const compressAndStore = async (file, rawContent) => {
    try {
        if (file.type === 'text') {
            throw new AppError('Text files cannot be updated via HTTP API. Use collaborative editing instead.', 400);
        } else if (file.type === 'binary') {
            // For binary files, use GridFS storage
            await file.setContent(rawContent);
            return file;
        } else {
            throw new Error(`Unsupported file type for content storage: ${file.type}`);
        }
    } catch (error) {
        logger.error('❌ CONTENT STORAGE FAILED', {
            error: error.message,
            fileId: file._id,
            fileType: file.type,
            filePath: file.filePath
        });
        throw error;
    }
};

/**
 * Get content from file - handles text (Yjs read-only) and binary (GridFS) files
 */
const getAndDecompress = async (file) => {
    try {
        // Handle text files through Yjs (READ-ONLY)
        if (file.type === 'text') {
            if (!file.filePath) {
                logger.warn('Text file missing file path', {
                    fileId: file._id,
                    filePath: file.filePath
                });
                return '';
            }
            return await yjsService.getTextContent(file.filePath);
        }
        
        // Handle binary files through GridFS
        if (file.type === 'binary') {
            const base64Content = await file.getContent();
            
            // Return empty if no content
            if (!base64Content) {
                return Buffer.from('');
            }
            
            // Decode the base64 content and return as buffer
            return Buffer.from(base64Content, 'base64');
        }
        
        // Handle directories
        if (file.type === 'directory') {
            return '';
        }
        
        throw new Error(`Unsupported file type: ${file.type}`);
        
    } catch (error) {
        logger.error('Content retrieval failed', {
            error: error.message,
            fileId: file._id,
            fileType: file.type
        });
        throw error;
    }
};

// =============================================================================
// STANDARDIZED PERMISSION HELPERS
// =============================================================================

/**
 * Check if user has admin-level content management rights
 * @param {Array|String} userRoles - User roles
 * @returns {Boolean} - Whether user has admin content access
 */
const hasAdminContentAccess = (userRoles) => {
    return hasRight(userRoles, RIGHTS.MANAGE_ALL_CONTENT);
};

/**
 * Ensure parent directories exist for a file path
 * @param {String} filePath - Full file path
 * @param {String} userId - User ID who owns the file
 */
const ensureParentDirs = async (filePath, userId) => {
    const dirs = filePath.split('/').slice(0, -1); // Remove only filename, keep empty root element
    
    for (let i = 0; i < dirs.length; i++) {
        // Handle root directory case
        if (i === 0 && dirs[i] === '') {
            const rootExists = await File.findOne({ filePath: '/', type: 'directory', owner: userId });
            if (!rootExists) {
                await File.create({
                    filePath: '/',
                    fileName: 'root',
                    type: 'directory',
                    mimeType: 'inode/directory',
                    parentPath: null,
                    depth: 0,
                    description: 'Root directory',
                    owner: userId,
                    lastModifiedBy: userId,
                    permissions: { read: [], write: [] },
                    size: 0
                });
            }
            continue;
        }
        
        // Handle regular directories
        const dirPath = '/' + dirs.slice(1, i + 1).join('/');
        const exists = await File.findOne({ filePath: dirPath, type: 'directory', owner: userId });
        
        if (!exists) {
            await File.create({
                filePath: dirPath,
                fileName: dirs[i],
                type: 'directory',
                mimeType: 'application/x-directory',
                parentPath: i === 1 ? '/' : '/' + dirs.slice(1, i).join('/'),
                depth: i,
                description: `Directory: ${dirs[i]}`,
                owner: userId,
                lastModifiedBy: userId,
                permissions: { read: [], write: [] },
                size: 0
            });
        }
    }
};

const normalizeFilePath = (filePath = '') => {
    if (!filePath) {
        throw new Error('File path is required');
    }
    return filePath.startsWith('/') ? filePath : `/${filePath}`;
};

/**
 * Get user ID from request consistently
 * @param {Object} req - Express request object
 * @returns {string} - User ID
 * @throws {AppError} - If user ID not found
 */
const getUserId = (req) => {
    const userId = req.user?.id || req.user?._id;
    if (!userId) {
        throw new AppError('User ID not found in request', 401);
    }
    return userId.toString();
};

/**
 * Standardized path decoding utility
 * @param {string} encodedPath - URL encoded file path
 * @returns {string} - Decoded file path
 * @throws {AppError} - If path is invalid or not encoded
 */
const decodeFilePath = (encodedPath) => {
    try {
        // Validate input
        if (!encodedPath || typeof encodedPath !== 'string') {
            throw new AppError('Invalid file path parameter', 400);
        }

        // Decode from URL encoding
        const decoded = decodeURIComponent(encodedPath);

        // Validate the decoded path
        if (!File.validatePath(decoded)) {
            throw new AppError('Invalid file path format after decoding', 400);
        }

        // Additional security check - ensure it's an absolute path
        if (!decoded.startsWith('/')) {
            throw new AppError('File path must be absolute', 400);
        }

        return decoded;
    } catch (error) {
        if (error instanceof AppError) {
            throw error;
        }
        logger.error('Failed to decode file path:', {encodedPath, error: error.message});
        throw new AppError('Invalid file path encoding', 400);
    }
};

const respondWithOperation = (res, result, defaultStatus = 200) => {
    if (!result || result.success === false) {
        const status = result?.statusCode || 400;
        const message = result?.error || result?.message || 'Operation failed';
        throw new AppError(message, status);
    }

    const status = result.statusCode || defaultStatus;
    res.status(status).json(result);
};



/**
 * Simplified File Controller
 * Handles file operations with single-document-per-file approach
 */
module.exports = {
    /**
     * @desc    Get file system health status
     * @route   GET /api/v1/files/health
     * @access  Admin
     */
    getFileSystemHealth: asyncHandler(async (req, res) => {
        const userId = getUserId(req);
        const userRoles = req.user?.roles || [];

        // Check admin access using standardized helper
        if (!hasAdminContentAccess(userRoles)) {
            throw new AppError('Admin access required', 403);
        }

        try {
            // Check database connection
            const dbStatus = mongoose.connection.readyState === 1 ? 'connected' : 'disconnected';
            
            // Check cache status
            const cacheStatus = cache ? 
                await cache.set('health_check', 'ok', 1).then(() => 'connected').catch(() => 'disconnected') : 
                'not configured';
            
            // Get Yjs service status
            const collaborationStatus = {
                serviceInitialized: yjsService.isInitialized,
                persistenceAvailable: !!yjsService.getPersistence()
            };
            
            // Check file system statistics
            const totalFiles = await File.countDocuments({ type: { $in: ['binary', 'text'] } });
            const totalDirectories = await File.countDocuments({ type: 'directory' });
            const collaborativeFiles = await File.countDocuments({ type: 'text' });
            const binaryFiles = await File.countDocuments({ type: 'binary' });
            
            const healthStatus = {
                timestamp: new Date().toISOString(),
                status: 'healthy', // Will be updated based on checks
                components: {
                    database: {
                        status: dbStatus,
                        details: {
                            connectionState: mongoose.connection.readyState,
                            host: mongoose.connection.host,
                            name: mongoose.connection.name
                        }
                    },
                    cache: {
                        status: cacheStatus,
                        details: cacheStatus === 'connected' ? {
                            type: 'Redis'
                        } : {}
                    },
                    collaboration: {
                        status: 'healthy', // Yjs handles persistence automatically
                        details: collaborationStatus
                    },
                    persistence: {
                        status: 'active',
                        details: {
                            type: 'MongoDB + Yjs persistence'
                        }
                    }
                },
                statistics: {
                    files: {
                        total: totalFiles,
                        collaborative: collaborativeFiles,
                        binary: binaryFiles
                    },
                    directories: {
                        total: totalDirectories
                    }
                },
                issues: []
            };

            // Determine overall health status
            const componentStatuses = Object.values(healthStatus.components).map(c => c.status);
            
            if (componentStatuses.includes('disconnected') || componentStatuses.includes('error')) {
                healthStatus.status = 'unhealthy';
            } else if (componentStatuses.includes('warning')) {
                healthStatus.status = 'warning';
            }

            // Add issues based on component status
            if (dbStatus !== 'connected') {
                healthStatus.issues.push('Database connection issue');
            }
            if (cacheStatus !== 'connected') {
                healthStatus.issues.push('Cache connection issue');
            }
            // Yjs handles persistence automatically - no manual initialization needed

            res.json({
                success: true,
                message: 'File system health retrieved successfully',
                ...healthStatus
            });

        } catch (error) {
            logger.error('Health check failed:', error);
            res.status(500).json({
                success: false,
                message: 'Health check failed',
                error: error.message,
                timestamp: new Date().toISOString(),
                components: {},
                statistics: {},
                issues: [error.message]
            });
        }
    }),

    /**
     * @desc    Get supported file types
     * @route   GET /api/v1/files/types
     * @access  Public
     */
    getSupportedTypes: asyncHandler(async (req, res) => {
        const supportedTypes = File.getSupportedTypes();

        logger.info('Supported file types retrieved successfully', {
            typesCount: Object.keys(supportedTypes).length
        });

        const response = {
            success: true,
            message: 'Supported file types retrieved successfully',
            types: supportedTypes,
            meta: {
                typesCount: Object.keys(supportedTypes).length,
                timestamp: new Date().toISOString()
            }
        };

        res.status(200).json(response);
    }),



    /**
     * @desc    Get user's files or all files (admin) with filtering and pagination
     * @route   GET /api/v1/files
     * @route   GET /api/v1/files/access/:accessType
     * @access  Private (requires authentication)
     */
    getFiles: asyncHandler(async (req, res) => {
        const userId = getUserId(req);
        const userRoles = req.user?.roles || [];
        
        // Standardized query parsing
        const {
            page = 1,
            limit = 50,
            type,
            search,
            sortBy = 'createdAt',
            sortOrder = 'desc',
            parentPath
        } = req.query;

        // Build standardized filter
        const filter = {};
        if (type) filter.type = type;
        if (parentPath) filter.parentPath = parentPath;
        if (search) {
            filter.$or = [
                { fileName: { $regex: search, $options: 'i' } },
                { description: { $regex: search, $options: 'i' } },
                { tags: { $in: [new RegExp(search, 'i')] } }
            ];
        }

        // Standardized pagination and sorting
        const skip = (parseInt(page) - 1) * parseInt(limit);
        const sort = { [sortBy]: sortOrder === 'desc' ? -1 : 1 };

        // Execute standardized query with permission checking
        const [files, total] = await Promise.all([
            File.findWithReadPermission(filter, userId, userRoles)
                .select({ versionHistory: 0 }) // Exclude large fields
                .populate('owner', 'firstName lastName username email')
                .populate('lastModifiedBy', 'firstName lastName username email')
                .sort(sort)
                .skip(skip)
                .limit(parseInt(limit))
                .lean(),
            File.findWithReadPermission(filter, userId, userRoles).countDocuments()
        ]);

        // Standardized response format
        res.status(200).json({
            success: true,
            message: 'Files retrieved successfully',
            files,
            pagination: {
                current: parseInt(page),
                total: Math.ceil(total / parseInt(limit)),
                count: files.length,
                totalFiles: total,
                page: parseInt(page),
                limit: parseInt(limit),
                pages: Math.ceil(total / parseInt(limit))
            },
            meta: {
                timestamp: new Date().toISOString(),
                hasMore: skip + files.length < total
            }
        });
    }),

    /**
     * @desc    Update file metadata (excluding content)
     * @route   PUT /api/v1/files/:filePath
     * @access  Private (requires write permission or admin role)
     */
    updateFileMetadata: asyncHandler(async (req, res) => {
        const {filePath} = req.params;
        const decodedFilePath = decodeFilePath(filePath);
        const {fileName, description, tags, permissions} = req.body;
        const userId = getUserId(req);
        const userRoles = req.user?.roles || [];

        // Standardized permission checking
        const hasAdminAccess = hasAdminContentAccess(userRoles);
        let file;
        
        if (hasAdminAccess) {
            file = await File.findOne({filePath: decodedFilePath});
        } else {
            file = await File.findOneWithWritePermission(
                {filePath: decodedFilePath},
                userId,
                userRoles
            );
        }

        if (!file) {
            logger.warn('File metadata update failed - not found or access denied', {
                userId,
                filePath: decodedFilePath,
                hasAdminAccess
            });
            throw new AppError('File not found or access denied', 404);
        }

        let hasChanges = false;
        const updates = {};

        // Handle fileName update (rename operation)
        if (fileName !== undefined && fileName !== file.fileName) {
            // Preserve file extension if not provided
            const originalExtension = path.extname(file.fileName);
            const newNameExtension = path.extname(fileName);
            
            let finalFileName = fileName;
            if (originalExtension && !newNameExtension) {
                finalFileName = fileName + originalExtension;
                logger.debug('Auto-appended file extension during rename', {
                    userId,
                    originalName: file.fileName,
                    requestedName: fileName,
                    finalName: finalFileName
                });
            }
            
            // Create new full path
            const parentPath = path.dirname(decodedFilePath);
            const newPath = path.join(parentPath, finalFileName).replace(/\\/g, '/');
            
            // Check if destination already exists
            const existingFile = await File.findOne({
                filePath: newPath,
                owner: file.owner
            });

            if (existingFile) {
                throw new AppError('A file with that name already exists', 409);
            }

            updates.fileName = finalFileName;
            updates.filePath = newPath;
            hasChanges = true;
        }

        // Handle other metadata updates
        if (description !== undefined && description !== file.description) {
            updates.description = description;
            hasChanges = true;
        }

        if (tags !== undefined && JSON.stringify(tags) !== JSON.stringify(file.tags)) {
            updates.tags = tags;
            hasChanges = true;
        }

        // Handle permissions (only file owners or admins can update)
        if (permissions !== undefined) {
            const canUpdatePermissions = file.owner.toString() === userId || hasAdminAccess;

            if (canUpdatePermissions) {
                updates.permissions = permissions;
                hasChanges = true;
            } else {
                logger.warn('Permission update denied - insufficient privileges', {
                    userId,
                    fileId: file._id,
                    fileOwner: file.owner.toString()
                });
                throw new AppError('Insufficient privileges to update permissions', 403);
            }
        }

        if (!hasChanges) {
            return res.status(200).json({
                success: true,
                message: 'No changes detected',
                file: {
                    _id: file._id,
                    filePath: file.filePath,
                    fileName: file.fileName,
                    description: file.description,
                    tags: file.tags
                }
            });
        }

        // Apply updates
        Object.assign(file, updates);
        file.lastModifiedBy = userId;
        await file.save();

        logger.info('File metadata updated successfully', {
            userId,
            fileId: file._id,
            updates: Object.keys(updates),
            filePath: file.filePath
        });

        res.status(200).json({
            success: true,
            message: 'File metadata updated successfully',
            file: {
                _id: file._id,
                filePath: file.filePath,
                fileName: file.fileName,
                description: file.description,
                tags: file.tags,
                permissions: file.permissions,
                lastModifiedBy: file.lastModifiedBy,
                updatedAt: file.updatedAt
            }
        });
    }),


    /**
     * @desc    Get demo files (placeholder)
     * @route   GET /api/v1/files/demo
     * @access  Public
     */
    getDemoFiles: asyncHandler(async (req, res) => {
        res.status(200).json({
            success: true,
            message: 'Demo files feature not implemented',
            files: [],
            meta: {
                timestamp: new Date().toISOString()
            }
        });
    }),

    /**
     * @desc    Get file metadata
     * @route   GET /api/v1/files/:filePath/metadata
     * @access  Private (requires read permission)
     */
    getFileMetadata: asyncHandler(async (req, res) => {
        const {filePath} = req.params;
        const decodedFilePath = decodeFilePath(filePath);
        const userId = getUserId(req);
        const userRoles = req.user?.roles || [];

        const result = await executeFileOperation('getMetadata', {filePath: decodedFilePath}, userId, userRoles);
        respondWithOperation(res, result);
    }),

    /**
     * @desc    Get file content
     * @route   GET /api/v1/files/:filePath/content
     * @access  Private (requires read permission)
     */
    getFileContent: asyncHandler(async (req, res) => {
        const {filePath} = req.params;
        const decodedFilePath = decodeFilePath(filePath);
        const userId = getUserId(req);
        const userRoles = req.user?.roles || [];

        const result = await executeFileOperation('getContent', {filePath: decodedFilePath}, userId, userRoles);
        respondWithOperation(res, result);
    }),

    /**
     * @desc    Save file content
     * @route   PUT /api/v1/files/:filePath/content
     * @access  Private (requires write permission)
     */
    saveFileContent: asyncHandler(async (req, res) => {
        const {filePath} = req.params;
        const decodedFilePath = decodeFilePath(filePath);
        const userId = getUserId(req);
        const userRoles = req.user?.roles || [];
        const {content} = req.body;

        const result = await executeFileOperation('save', {
            filePath: decodedFilePath,
            content
        }, userId, userRoles);

        respondWithOperation(res, result);
    }),

    /**
     * @desc    Publish current file content as a version
     * @route   POST /api/v1/files/:filePath/publish
     * @access  Private (requires write permission)
     */
    publishFileVersion: asyncHandler(async (req, res) => {
        const {filePath} = req.params;
        const decodedFilePath = decodeFilePath(filePath);
        const userId = getUserId(req);
        const userRoles = req.user?.roles || [];
        const {message} = req.body || {};

        const result = await executeFileOperation('publish', {
            filePath: decodedFilePath,
            message
        }, userId, userRoles);

        respondWithOperation(res, result, 201);
    }),

    /**
     * @desc    Get version history for a file
     * @route   GET /api/v1/files/:filePath/versions
     * @access  Private (requires read permission)
     */
    getFileVersions: asyncHandler(async (req, res) => {
        const {filePath} = req.params;
        const decodedFilePath = decodeFilePath(filePath);
        const userId = getUserId(req);
        const userRoles = req.user?.roles || [];

        const result = await executeFileOperation('getVersions', {filePath: decodedFilePath}, userId, userRoles);
        respondWithOperation(res, result);
    }),

    /**
     * @desc    Load a specific file version (read-only)
     * @route   GET /api/v1/files/:filePath/versions/:versionNumber
     * @access  Private (requires read permission)
     */
    loadFileVersion: asyncHandler(async (req, res) => {
        const {filePath, versionNumber} = req.params;
        const decodedFilePath = decodeFilePath(filePath);
        const userId = getUserId(req);
        const userRoles = req.user?.roles || [];

        const result = await executeFileOperation('loadVersion', {
            filePath: decodedFilePath,
            versionNumber
        }, userId, userRoles);

        respondWithOperation(res, result);
    }),

    /**
     * @desc    Download a specific file version
     * @route   GET /api/v1/files/:filePath/versions/:versionNumber/download
     * @access  Private (requires read permission)
     */
    downloadFileVersion: asyncHandler(async (req, res) => {
        const {filePath, versionNumber} = req.params;
        const decodedFilePath = decodeFilePath(filePath);
        const userId = getUserId(req);
        const userRoles = req.user?.roles || [];

        const result = await executeFileOperation('downloadVersion', {
            filePath: decodedFilePath,
            versionNumber
        }, userId, userRoles);

        // Set appropriate headers for download
        const fileName = result.fileName || `version_${versionNumber}`;
        res.setHeader('Content-Type', result.mimeType || 'application/octet-stream');
        res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
        
        // Send the content as buffer
        res.send(result.content);
    }),

    /**
     * @desc    Delete a specific file version
     * @route   DELETE /api/v1/files/:filePath/versions/:versionNumber
     * @access  Private (requires write permission)
     */
    deleteFileVersion: asyncHandler(async (req, res) => {
        const {filePath, versionNumber} = req.params;
        const decodedFilePath = decodeFilePath(filePath);
        const userId = getUserId(req);
        const userRoles = req.user?.roles || [];

        const result = await executeFileOperation('deleteVersion', {
            filePath: decodedFilePath,
            versionNumber
        }, userId, userRoles);

        respondWithOperation(res, result);
    }),

    /**
     * @desc    Create a new file
     * @route   POST /api/v1/files
     * @access  Private (requires authentication)
     */
    createFile: asyncHandler(async (req, res) => {
        const {filePath, content = '', description = ''} = req.body;
        if (!filePath) {
            throw new AppError('filePath is required', 400);
        }

        const normalizedPath = decodeFilePath(filePath);
        const userId = getUserId(req);
        const userRoles = req.user?.roles || [];

        const result = await executeFileOperation('create', {
            filePath: normalizedPath,
            content,
            message: description
        }, userId, userRoles);

        respondWithOperation(res, result, 201);
    }),

    /**
     * @desc    Create a new directory
     * @route   POST /api/v1/files/directory
     * @access  Private (requires authentication)
     */
    createDirectory: asyncHandler(async (req, res) => {
        const {dirPath, description = ''} = req.body;
        if (!dirPath) {
            throw new AppError('dirPath is required', 400);
        }

        const decodedDirPath = decodeFilePath(dirPath);
        const normalizedDirPath = decodedDirPath === '/' ? '/' : decodedDirPath.replace(/\/$/, '');
        const userId = getUserId(req);
        const userRoles = req.user?.roles || [];

        const result = await executeFileOperation('createDir', {
            dirPath: normalizedDirPath,
            description
        }, userId, userRoles);

        respondWithOperation(res, result, 201);
    }),

    /**
     * @desc    Delete a file or directory
     * @route   DELETE /api/v1/files/:filePath
     * @access  Private (requires write permission)
     */
    deleteFile: asyncHandler(async (req, res) => {
        const {filePath} = req.params;
        const decodedFilePath = decodeFilePath(filePath);
        const userId = getUserId(req);
        const userRoles = req.user?.roles || [];
        const forceParam = req.query.force;
        const operationData = { filePath: decodedFilePath };
        if (forceParam !== undefined) {
            operationData.force = forceParam === 'true';
        }

        const result = await executeFileOperation('delete', operationData, userId, userRoles);

        respondWithOperation(res, result);
    }),

    /**
     * @desc    Move a file or directory
     * @route   POST /api/v1/files/move
     * @access  Private (requires write permission)
     */
    moveFile: asyncHandler(async (req, res) => {
        const {sourcePath, destinationPath} = req.body;
        if (!sourcePath || !destinationPath) {
            throw new AppError('sourcePath and destinationPath are required', 400);
        }

        const normalizedSource = decodeFilePath(sourcePath);
        const normalizedDestination = decodeFilePath(destinationPath);
        const userId = getUserId(req);
        const userRoles = req.user?.roles || [];

        const result = await executeFileOperation('move', {
            sourcePath: normalizedSource,
            destinationPath: normalizedDestination
        }, userId, userRoles);

        respondWithOperation(res, result);
    }),

    /**
     * @desc    Copy a file or directory
     * @route   POST /api/v1/files/copy
     * @access  Private (requires read permission on source)
     */
    copyFile: asyncHandler(async (req, res) => {
        const {sourcePath, destinationPath} = req.body;
        if (!sourcePath || !destinationPath) {
            throw new AppError('sourcePath and destinationPath are required', 400);
        }

        const normalizedSource = decodeFilePath(sourcePath);
        const normalizedDestination = decodeFilePath(destinationPath);
        const userId = getUserId(req);
        const userRoles = req.user?.roles || [];

        const result = await executeFileOperation('copy', {
            sourcePath: normalizedSource,
            destinationPath: normalizedDestination
        }, userId, userRoles);

        respondWithOperation(res, result, 201);
    }),

    /**
     * @desc    Rename a file or directory
     * @route   POST /api/v1/files/:filePath/rename
     * @access  Private (requires write permission)
     */
    renameFile: asyncHandler(async (req, res) => {
        const {filePath} = req.params;
        const {newName} = req.body;
        if (!newName) {
            throw new AppError('newName is required', 400);
        }

        const decodedFilePath = decodeFilePath(filePath);
        const userId = getUserId(req);
        const userRoles = req.user?.roles || [];

        const result = await executeFileOperation('rename', {
            filePath: decodedFilePath,
            newName
        }, userId, userRoles);

        respondWithOperation(res, result);
    }),

    /**
     * @desc    Download file
     * @route   GET /api/v1/files/:filePath/download
     * @access  Private (requires authentication)
     */
    downloadFile: asyncHandler(async (req, res) => {
        const { filePath } = req.params;
        const userId = getUserId(req);
        const userRoles = req.user?.roles || [];

        // Standardized parameter validation
        if (!filePath) {
            throw new AppError('File path is required', 400);
        }

        const decodedFilePath = decodeFilePath(filePath);

        // Find file with read permission check
        const file = await File.findOneWithReadPermission(
            { filePath: decodedFilePath },
            userId,
            userRoles
        );

        if (!file) {
            logger.warn('File download failed - file not found or access denied', {
                filePath: decodedFilePath,
                userId
            });
            throw new AppError('File not found or access denied', 404);
        }

        if (file.type === 'directory') {
            logger.warn('Download attempt on directory', {
                filePath: decodedFilePath,
                userId
            });
            throw new AppError('Cannot download a directory', 400);
        }

        try {
            // Set standardized response headers for file download
            const escapedFileName = file.fileName.replace(/["\\]/g, '\\$&');
            res.setHeader('Content-Disposition', `attachment; filename="${escapedFileName}"`);
            res.setHeader('Content-Type', file.mimeType || 'application/octet-stream');
            res.setHeader('Cache-Control', 'no-cache');

            // Get file content and send it (decompressed for download)
            const fileContent = await getAndDecompress(file);
            
            // Handle different content types appropriately
            if (Buffer.isBuffer(fileContent)) {
                // For binary files, send buffer directly
                res.setHeader('Content-Length', fileContent.length);
                res.send(fileContent);
            } else {
                // For text files returned as strings, convert to buffer for download
                const contentBuffer = Buffer.from(fileContent, 'utf8');
                res.setHeader('Content-Length', contentBuffer.length);
                res.send(contentBuffer);
            }

            logger.info('File downloaded successfully', {
                filePath: decodedFilePath,
                fileName: file.fileName,
                fileSize: file.size,
                userId,
                fileId: file._id
            });

        } catch (error) {
            logger.error('Download file error', {
                message: error.message,
                filePath: decodedFilePath,
                userId,
                fileId: file._id
            });
            
            if (!res.headersSent) {
                throw new AppError('Error downloading file', 500);
            }
        }
    }),
    /**
     * @desc    Get directory tree structure
     * @route   GET /api/v1/files/tree
     * @access  Private (requires read permission for files/directories or admin role)
     */
    getDirectoryTree: asyncHandler(async (req, res) => {
        const userId = getUserId(req);
        const userRoles = req.user?.roles || [];

        const {rootPath = '/', includeFiles = true, format = 'object'} = req.query;

        // Build basic tree structure from database - include owned and shared files
        const files = await File.find({
            $or: [
                { owner: userId },
                { 'permissions.read': userId },
                { 'permissions.write': userId }
            ]
        })
            .select('filePath fileName type size createdAt parentPath')
            .sort({ filePath: 1 })
            .lean();

        // Build tree structure with array-based children (original format)
        const buildArrayTree = (parentPath = rootPath) => {
            const children = files.filter(file => file.parentPath === parentPath);
            return children.map(file => ({
                filePath: file.filePath,
                fileName: file.fileName,
                type: file.type,
                size: file.size || 0,
                createdAt: file.createdAt,
                children: file.type === 'directory' ? buildArrayTree(file.filePath) : undefined
            }));
        };

        // Build tree structure with object-based children (frontend-friendly format)
        const buildObjectTree = (parentPath = rootPath) => {
            const children = files.filter(file => file.parentPath === parentPath);
            const childrenObj = {};
            
            children.forEach(file => {
                const key = file.fileName || file.filePath.split('/').pop();
                childrenObj[key] = {
                    filePath: file.filePath,
                    fileName: file.fileName,
                    type: file.type,
                    size: file.size || 0,
                    createdAt: file.createdAt,
                    children: file.type === 'directory' ? buildObjectTree(file.filePath) : {}
                };
            });
            
            return childrenObj;
        };

        // Choose format based on query parameter
        const useObjectFormat = format === 'object';
        const treeChildren = useObjectFormat ? buildObjectTree(rootPath) : buildArrayTree(rootPath);

        const tree = useObjectFormat ? 
            // Object format: return children directly as object
            treeChildren :
            // Array format: wrap in root node structure (backward compatibility)
            {
                filePath: rootPath,
                fileName: rootPath === '/' ? 'root' : rootPath.split('/').pop(),
                type: 'directory',
                size: 0,
                children: treeChildren
            };

        // Filter out files if requested
        if (includeFiles === 'false') {
            if (useObjectFormat) {
                const filterDirectoriesOnlyObj = (obj) => {
                    const filtered = {};
                    Object.entries(obj).forEach(([key, node]) => {
                        if (node.type === 'directory') {
                            filtered[key] = {
                                ...node,
                                children: filterDirectoriesOnlyObj(node.children || {})
                            };
                        }
                    });
                    return filtered;
                };
                
                tree = filterDirectoriesOnlyObj(tree);
            } else {
                const filterDirectoriesOnly = (node) => {
                    if (node.type !== 'directory') return null;
                    if (node.children) {
                        node.children = node.children
                            .map(filterDirectoriesOnly)
                            .filter(Boolean);
                    }
                    return node;
                };
                
                if (tree.children) {
                    tree.children = tree.children
                        .map(filterDirectoriesOnly)
                        .filter(Boolean);
                }
            }
        }

        // Calculate statistics
        let totalFiles = 0;
        let totalDirectories = 0;
        let totalSize = 0;

        const calculateStatsArray = (node) => {
            if (node.type === 'directory') {
                totalDirectories++;
            } else {
                totalFiles++;
                totalSize += node.size || 0;
            }
            
            if (node.children && Array.isArray(node.children)) {
                node.children.forEach(calculateStatsArray);
            }
        };

        const calculateStatsObject = (obj) => {
            Object.values(obj).forEach(node => {
                if (node.type === 'directory') {
                    totalDirectories++;
                    if (node.children) {
                        calculateStatsObject(node.children);
                    }
                } else {
                    totalFiles++;
                    totalSize += node.size || 0;
                }
            });
        };

        if (useObjectFormat) {
            calculateStatsObject(tree);
        } else {
            calculateStatsArray(tree);
        }

        res.status(200).json({
            success: true,
            message: 'Directory tree retrieved successfully',
            tree,
            statistics: {
                totalFiles,
                totalDirectories,
                totalSize,
                rootPath
            },
            meta: {
                timestamp: new Date().toISOString(),
                includeFiles: includeFiles !== 'false',
                format: useObjectFormat ? 'object' : 'array'
            }
        });
    }),

    /**
     * @desc    Get directory contents (immediate children only)
     * @route   GET /api/v1/files/directory/contents
     * @access  Private (requires authentication)
     */
    getDirectoryContents: asyncHandler(async (req, res) => {
        try {
            const userId = getUserId(req);
            if (!userId) {
                return res.status(401).json({
                    success: false,
                    message: 'User authentication required'
                });
            }

            const dirPath = req.query.filePath;

            // Check if directory exists (either owned or shared)
            const directory = await File.findOne({
                $and: [
                    { filePath: dirPath || '/' },
                    { type: 'directory' },
                    {
                        $or: [
                            { owner: userId },
                            { 'permissions.read': userId },
                            { 'permissions.write': userId }
                        ]
                    }
                ]
            });

            if (!directory) {
                return res.status(404).json({
                    success: false,
                    message: 'Directory not found or access denied'
                });
            }

            // Get immediate children - include owned and shared files
            const {sortBy = 'fileName', sortOrder = 'asc', fileType} = req.query;

            const query = {
                $and: [
                    { parentPath: dirPath },
                    {
                        $or: [
                            { owner: userId },
                            { 'permissions.read': userId },
                            { 'permissions.write': userId }
                        ]
                    }
                ]
            };

            if (fileType) {
                query.$and.push({ type: fileType });
            }

            const sort = {};
            // Sort directories first, then files
            sort.type = -1;
            sort[sortBy] = sortOrder === 'desc' ? -1 : 1;

            const contents = await File.find(query)
                .sort(sort)
                .select('filePath fileName type size createdAt updatedAt description')
                .lean();

            res.status(200).json({
                success: true,
                message: 'Directory contents retrieved successfully',
                contents,
                directory: {
                    filePath: directory.filePath,
                    description: directory.description,
                    createdAt: directory.createdAt,
                    updatedAt: directory.updatedAt
                },
                statistics: {
                    directories: contents.filter(item => item.type === 'directory').length,
                    files: contents.filter(item => item.type === 'file').length,
                    totalSize: contents.reduce((sum, item) => sum + (item.size || 0), 0)
                },
                meta: {
                    count: contents.length,
                    timestamp: new Date().toISOString()
                }
            });
        } catch (error) {
            const userId = req.user?.id || 'unknown';
            logger.error('Get directory contents error:', {message: error.message, userId});
            throw new AppError('Error retrieving directory contents', 500);
        }
    }),


    /**
     * @desc    Get directory size and statistics (recursive)
     * @route   GET /api/v1/files/directory/stats
     * @access  Private (requires authentication)
     */
    getDirectoryStats: asyncHandler(async (req, res) => {
        try {
            const userId = getUserId(req);
            if (!userId) {
                return res.status(401).json({
                    success: false,
                    message: 'User authentication required'
                });
            }

            const dirPath = req.query.filePath;

            // Check if directory exists
            const directory = await File.findOne({
                filePath: dirPath || '/',
                owner: userId,
                type: 'directory'
            });

            if (!directory) {
                return res.status(404).json({
                    success: false,
                    message: 'Directory not found'
                });
            }

            // Use optimized aggregation pipeline for efficient statistics
            const stats = await File.aggregate([
                {
                    $match: {
                        owner: new mongoose.Types.ObjectId(userId),
                        $or: [
                            { filePath: dirPath },
                            { filePath: new RegExp(`^${dirPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}/`) }
                        ]
                    }
                },
                {
                    $facet: {
                        // File type statistics including binary files
                        typeStats: [
                            {
                                $group: {
                                    _id: '$type',
                                    count: { $sum: 1 },
                                    totalSize: { $sum: '$size' },
                                    avgSize: { $avg: '$size' },
                                    maxSize: { $max: '$size' },
                                    minSize: { $min: '$size' }
                                }
                            }
                        ],
                        // Timestamp statistics
                        timeStats: [
                            {
                                $group: {
                                    _id: null,
                                    newestFile: { $max: '$updatedAt' },
                                    oldestFile: { $min: '$createdAt' }
                                }
                            }
                        ]
                    }
                }
            ]);

            const result = stats[0];
            
            // Process type statistics correctly including binary files
            const typeData = result.typeStats.reduce((acc, stat) => {
                acc[stat._id] = {
                    count: stat.count,
                    totalSize: stat.totalSize,
                    avgSize: Math.round(stat.avgSize || 0),
                    maxSize: stat.maxSize || 0,
                    minSize: stat.minSize || 0
                };
                return acc;
            }, { directory: {}, text: {}, binary: {} });

            const timeData = result.timeStats[0] || {};
            
            // Calculate totals correctly
            const fileCount = (typeData.text?.count || 0) + (typeData.binary?.count || 0);
            const directoryCount = typeData.directory?.count || 0;
            const totalSize = (typeData.text?.totalSize || 0) + (typeData.binary?.totalSize || 0);

            res.status(200).json({
                success: true,
                message: 'Directory statistics retrieved successfully',
                totalSize,
                fileCount,
                directoryCount,
                totalItems: fileCount + directoryCount,
                files: {
                    count: fileCount,
                    totalSize,
                    averageSize: fileCount > 0 ? Math.round(totalSize / fileCount) : 0,
                    largestFile: Math.max(
                        typeData.text?.maxSize || 0,
                        typeData.binary?.maxSize || 0
                    ),
                    smallestFile: Math.min(
                        typeData.text?.minSize || Number.MAX_SAFE_INTEGER,
                        typeData.binary?.minSize || Number.MAX_SAFE_INTEGER
                    ) === Number.MAX_SAFE_INTEGER ? 0 : Math.min(
                        typeData.text?.minSize || Number.MAX_SAFE_INTEGER,
                        typeData.binary?.minSize || Number.MAX_SAFE_INTEGER
                    )
                },
                directories: {
                    count: directoryCount
                },
                fileTypes: {
                    text: typeData.text?.count || 0,
                    binary: typeData.binary?.count || 0
                },
                directory: {
                    filePath: directory.filePath,
                    createdAt: directory.createdAt,
                    updatedAt: directory.updatedAt
                },
                meta: {
                    timestamps: {
                        newestFile: timeData.newestFile,
                        oldestFile: timeData.oldestFile
                    },
                    timestamp: new Date().toISOString(),
                    optimized: true
                }
            });
        } catch (error) {
            const userId = req.user?.id || 'unknown';
            logger.error('Get directory stats error:', {message: error.message, userId});
            throw new AppError('Error retrieving directory statistics', 500);
        }
    }),

    /**
     * @desc    Bulk operations on multiple files/directories
     * @route   POST /api/v1/files/bulk
     * @access  Private (requires CREATOR role or higher)
     */
    bulkOperations: asyncHandler(async (req, res) => {
        const userId = getUserId(req);
        const userRoles = req.user?.roles || [];

        // Standardized parameter validation
        const { operation, filePaths, options = {} } = req.body;

        if (!operation || !filePaths || !Array.isArray(filePaths)) {
            logger.warn('Bulk operations failed - invalid parameters', {
                userId,
                hasOperation: !!operation,
                hasFilePaths: !!filePaths,
                isFilePathsArray: Array.isArray(filePaths)
            });
            throw new AppError('Operation and filePaths array are required', 400);
        }

        if (filePaths.length === 0) {
            throw new AppError('At least one file path must be provided', 400);
        }

        // Rate limiting for bulk operations
        if (filePaths.length > 100) {
            logger.warn('Bulk operations failed - too many files', {
                userId,
                filePathsCount: filePaths.length,
                limit: 100
            });
            throw new AppError('Maximum 100 files allowed per bulk operation', 400);
        }

        // Validate operation type
        const validOperations = ['delete', 'addTags', 'updatePermissions'];
        if (!validOperations.includes(operation)) {
            throw new AppError(`Unsupported operation: ${operation}. Supported: ${validOperations.join(', ')}`, 400);
        }

        // Check admin privileges
        const hasAdminRole = hasRight(userRoles, RIGHTS.MANAGE_ALL_CONTENT);

        // Initialize results tracking
        const results = [];
        let successCount = 0;
        let errorCount = 0;

        // Process each file individually for better security and error handling
        for (let i = 0; i < filePaths.length; i++) {
            const filePath = filePaths[i];
            
            try {
                const operationResult = { filePath, success: false };
                let file;

                switch (operation) {
                    case 'delete':
                        file = await File.findOneWithWritePermission(
                            { filePath },
                            userId,
                            userRoles
                        );

                        if (!file) {
                            operationResult.error = 'File not found or access denied';
                        } else {
                            if (options.force === true && file.type === 'directory') {
                                await file.deleteWithTransaction();
                            } else {
                                await file.deleteOne();
                            }
                            operationResult.success = true;
                            operationResult.deletedCount = 1;
                        }
                        break;

                    case 'addTags':
                        if (!options.tags || !Array.isArray(options.tags)) {
                            operationResult.error = 'Tags array is required for addTags operation';
                            break;
                        }

                        file = await File.findOneWithWritePermission(
                            { filePath },
                            userId,
                            userRoles
                        );

                        if (!file) {
                            operationResult.error = 'File not found or access denied';
                        } else {
                            // Add tags without duplicates
                            const newTags = options.tags.filter(tag => !file.tags.includes(tag));
                            if (newTags.length > 0) {
                                file.tags.push(...newTags);
                                await file.save();
                                operationResult.success = true;
                                operationResult.addedTags = newTags;
                            } else {
                                operationResult.success = true;
                                operationResult.message = 'No new tags to add';
                            }
                        }
                        break;

                    case 'updatePermissions':
                        if (!options.permissions) {
                            operationResult.error = 'Permissions object is required for updatePermissions operation';
                            break;
                        }

                        // Only file owners can update permissions
                        file = await File.findOne({ filePath, owner: userId });

                        if (!file) {
                            operationResult.error = 'File not found or not owned by user';
                        } else {
                            if (options.permissions.read) {
                                file.permissions.read = [...new Set(options.permissions.read)];
                            }
                            if (options.permissions.write) {
                                file.permissions.write = [...new Set(options.permissions.write)];
                            }
                            await file.save();
                            operationResult.success = true;
                            
                            // Invalidate cache for this file
                            await cache.invalidateAllRelatedCaches('file', file.filePath, userId);
                        }
                        break;
                }

                results.push(operationResult);
                if (operationResult.success) {
                    successCount++;
                } else {
                    errorCount++;
                }

            } catch (fileError) {
                logger.error('Bulk operation error for individual file', {
                    userId,
                    operation,
                    filePath,
                    error: fileError.message
                });

                results.push({
                    filePath,
                    success: false,
                    error: fileError.message
                });
                errorCount++;
            }
        }

        // Log bulk operation for security audit
        logger.info('Bulk operation completed', {
            userId,
            operation,
            totalFiles: filePaths.length,
            successCount,
            errorCount,
            hasAdminRole,
            successRate: ((successCount / filePaths.length) * 100).toFixed(1) + '%'
        });

        // Standardized response
        res.status(200).json({
            success: true,
            message: `Bulk ${operation} completed: ${successCount} successful, ${errorCount} failed`,
            data: {
                results,
                summary: {
                    total: filePaths.length,
                    successful: successCount,
                    failed: errorCount
                }
            },
            meta: {
                operation,
                timestamp: new Date().toISOString()
            }
        });
    }),

    /**
     * @desc    Get comprehensive file statistics (Admin only)
     * @route   GET /api/v1/files/admin/stats
     * @access  Private (Admin/Owner only)
     */
    getFileStats: asyncHandler(async (req, res) => {
        try {
            const userId = req.user.id;
            const userRoles = req.user.roles || [];

            // Check if user has admin privileges for comprehensive stats
            const isAdmin = hasRight(userRoles, RIGHTS.MANAGE_ALL_CONTENT);
            
            if (!isAdmin) {
                // Return user-specific statistics for non-admin users
                const userStats = await File.aggregate([
                    {
                        $match: { owner: new mongoose.Types.ObjectId(userId) }
                    },
                    {
                        $facet: {
                            // Count files by type
                            typeCounts: [
                                {
                                    $group: {
                                        _id: '$type',
                                        count: { $sum: 1 }
                                    }
                                }
                            ],
                            // Size statistics for files only
                            sizeStats: [
                                {
                                    $match: { type: { $ne: 'directory' } }
                                },
                                {
                                    $group: {
                                        _id: null,
                                        totalSize: { $sum: '$size' },
                                        avgSize: { $avg: '$size' },
                                        maxSize: { $max: '$size' },
                                        minSize: { $min: '$size' }
                                    }
                                }
                            ]
                        }
                    }
                ]);

                const typeStats = userStats[0].typeCounts.reduce((acc, stat) => {
                    acc[stat._id] = stat.count;
                    return acc;
                }, { directory: 0, text: 0, binary: 0 });

                const sizeData = userStats[0].sizeStats[0] || {
                    totalSize: 0, avgSize: 0, maxSize: 0, minSize: 0
                };

                return res.status(200).json({
                    success: true,
                    message: 'User file statistics retrieved successfully',
                    totalFiles: typeStats.directory + typeStats.text + typeStats.binary,
                    totalSize: sizeData.totalSize,
                    filesByType: {
                        directories: typeStats.directory,
                        textFiles: typeStats.text,
                        binaryFiles: typeStats.binary,
                        totalRegularFiles: typeStats.text + typeStats.binary
                    },
                    sizeStats: {
                        avgSize: Math.round(sizeData.avgSize || 0),
                        maxSize: sizeData.maxSize || 0,
                        minSize: sizeData.minSize || 0
                    },
                    meta: {
                        isAdmin: false,
                        generatedAt: new Date().toISOString()
                    }
                });
            }

            // Admin comprehensive statistics with consolidated aggregation
            const adminStats = await File.aggregate([
                {
                    $facet: {
                        // Overall counts and size stats
                        overview: [
                            {
                                $group: {
                                    _id: '$type',
                                    count: { $sum: 1 },
                                    totalSize: { $sum: '$size' },
                                    avgSize: { $avg: '$size' },
                                    maxSize: { $max: '$size' },
                                    minSize: { $min: '$size' }
                                }
                            }
                        ],
                        // MIME type distribution for files only
                        mimeTypes: [
                            {
                                $match: { type: { $ne: 'directory' } }
                            },
                            {
                                $group: {
                                    _id: '$mimeType',
                                    count: { $sum: 1 },
                                    totalSize: { $sum: '$size' }
                                }
                            },
                            { $sort: { count: -1 } },
                            { $limit: 10 }
                        ],
                        // User activity stats
                        userStats: [
                            {
                                $group: {
                                    _id: '$owner',
                                    fileCount: { $sum: 1 },
                                    totalSize: { $sum: '$size' }
                                }
                            },
                            { $sort: { fileCount: -1 } },
                            { $limit: 10 }
                        ],
                        // Recent activity (last 7 days)
                        recentActivity: [
                            {
                                $match: {
                                    createdAt: {
                                        $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)
                                    }
                                }
                            },
                            {
                                $group: {
                                    _id: '$type',
                                    count: { $sum: 1 }
                                }
                            }
                        ],
                        // Comprehensive compression statistics
                        compressionStats: [
                            {
                                $match: { type: { $ne: 'directory' } }
                            },
                            {
                                $addFields: {
                                    isCompressed: { $ifNull: ['$compression.isCompressed', false] },
                                    compressionAlgorithm: { $ifNull: ['$compression.algorithm', 'none'] },
                                    originalSize: { $ifNull: ['$compression.originalSize', '$size'] },
                                    compressionRatio: { $ifNull: ['$compression.compressionRatio', 1] }
                                }
                            },
                            {
                                $group: {
                                    _id: {
                                        isCompressed: '$isCompressed',
                                        algorithm: '$compressionAlgorithm'
                                    },
                                    count: { $sum: 1 },
                                    totalSize: { $sum: '$size' },
                                    totalOriginalSize: { $sum: '$originalSize' },
                                    avgCompressionRatio: { $avg: '$compressionRatio' }
                                }
                            },
                            { $sort: { '_id.isCompressed': -1, '_id.algorithm': 1 } }
                        ],
                        // Overall compression summary
                        compressionSummary: [
                            {
                                $match: { type: { $ne: 'directory' } }
                            },
                            {
                                $addFields: {
                                    isCompressed: { $ifNull: ['$compression.isCompressed', false] },
                                    originalSize: { $ifNull: ['$compression.originalSize', '$size'] }
                                }
                            },
                            {
                                $group: {
                                    _id: null,
                                    totalFiles: { $sum: 1 },
                                    compressedFiles: {
                                        $sum: { $cond: ['$isCompressed', 1, 0] }
                                    },
                                    totalStorageUsed: { $sum: '$size' },
                                    totalOriginalSize: { $sum: '$originalSize' },
                                    totalSpaceSaved: {
                                        $sum: { $subtract: ['$originalSize', '$size'] }
                                    }
                                }
                            }
                        ]
                    }
                }
            ]);

            const stats = adminStats[0];
            
            // Process overview stats
            const overviewStats = stats.overview.reduce((acc, stat) => {
                acc[stat._id] = {
                    count: stat.count,
                    totalSize: stat.totalSize,
                    avgSize: Math.round(stat.avgSize || 0),
                    maxSize: stat.maxSize || 0,
                    minSize: stat.minSize || 0
                };
                return acc;
            }, { directory: {}, text: {}, binary: {} });

            // Calculate totals
            const totalFiles = Object.values(overviewStats).reduce((sum, type) => sum + (type.count || 0), 0);
            const totalSize = Object.values(overviewStats).reduce((sum, type) => sum + (type.totalSize || 0), 0);
            const regularFiles = (overviewStats.text?.count || 0) + (overviewStats.binary?.count || 0);

            // Process compression stats - enhanced with algorithm breakdown
            const compressionData = stats.compressionStats.reduce((acc, stat) => {
                if (stat._id.isCompressed) {
                    acc.compressed += stat.count;
                    acc.compressedSize += stat.totalSize;
                    acc.byAlgorithm.push({
                        algorithm: stat._id.algorithm || 'unknown',
                        fileCount: stat.count,
                        totalSize: stat.totalSize,
                        totalOriginalSize: stat.totalOriginalSize || stat.totalSize,
                        avgCompressionRatio: stat.avgCompressionRatio || 1,
                        avgSpaceSaved: stat.avgCompressionRatio ? 
                            ((1 - stat.avgCompressionRatio) * 100).toFixed(1) + '%' : '0.0%'
                    });
                } else {
                    acc.uncompressed += stat.count;
                    acc.uncompressedSize += stat.totalSize;
                }
                return acc;
            }, { 
                compressed: 0, 
                uncompressed: 0, 
                compressedSize: 0, 
                uncompressedSize: 0, 
                byAlgorithm: [] 
            });

            // Get compression summary data
            const compressionSummary = stats.compressionSummary[0] || {
                totalFiles: 0,
                compressedFiles: 0,
                totalStorageUsed: 0,
                totalOriginalSize: 0,
                totalSpaceSaved: 0
            };

            // Calculate compression efficiency
            const compressionEfficiency = compressionSummary.totalOriginalSize > 0 ?
                (compressionSummary.totalSpaceSaved / compressionSummary.totalOriginalSize * 100) : 0;

            // Calculate recent activity - simple MongoDB-based stats only
            const recentFiles = stats.recentActivity.reduce((sum, activity) => sum + activity.count, 0);

            res.status(200).json({
                success: true,
                message: 'Admin file statistics retrieved successfully',
                totalFiles,
                totalSize,
                filesByType: {
                    directories: overviewStats.directory?.count || 0,
                    textFiles: overviewStats.text?.count || 0,
                    binaryFiles: overviewStats.binary?.count || 0,
                    totalRegularFiles: regularFiles,
                    typeDistribution: stats.mimeTypes
                },
                sizeStats: {
                    totalSize,
                    avgSize: totalSize > 0 ? Math.round(totalSize / regularFiles) : 0,
                    maxSize: Math.max(
                        overviewStats.text?.maxSize || 0,
                        overviewStats.binary?.maxSize || 0
                    ),
                    minSize: Math.min(
                        overviewStats.text?.minSize || Number.MAX_SAFE_INTEGER,
                        overviewStats.binary?.minSize || Number.MAX_SAFE_INTEGER
                    ) === Number.MAX_SAFE_INTEGER ? 0 : Math.min(
                        overviewStats.text?.minSize || Number.MAX_SAFE_INTEGER,
                        overviewStats.binary?.minSize || Number.MAX_SAFE_INTEGER
                    )
                },
                compressionStats: {
                    enabled: true,
                    totalFiles: compressionSummary.totalFiles,
                    compressedFiles: compressionData.compressed,
                    uncompressedFiles: compressionData.uncompressed,
                    compressionRatio: regularFiles > 0 ? 
                        ((compressionData.compressed / regularFiles) * 100).toFixed(1) + '%' : '0.0%',
                    spaceSaved: compressionSummary.totalSpaceSaved,
                    storageEfficiency: compressionEfficiency.toFixed(1) + '%',
                    totalStorageUsed: compressionSummary.totalStorageUsed,
                    totalOriginalSize: compressionSummary.totalOriginalSize,
                    byAlgorithm: compressionData.byAlgorithm,
                    systemConfig: {
                        defaultAlgorithm: process.env.COMPRESSION_ALGORITHM || 'gzip',
                        compressionLevel: parseInt(process.env.COMPRESSION_LEVEL) || 6,
                        autoCompress: process.env.AUTO_COMPRESS !== 'false'
                    }
                },
                recentActivity: {
                    recentFiles,
                    timeframe: '7 days',
                    topUsers: stats.userStats.slice(0, 5)
                },
                meta: {
                    isAdmin: true,
                    generatedAt: new Date().toISOString()
                }
            });

        } catch (error) {
            logger.error('Get file stats error:', {message: error.message, userId: req.user?.id});
            throw new AppError('Error retrieving file statistics', 500);
        }
    }),

    /**
     * @desc    Share file with users (add to read/write permissions)
     * @route   POST /api/v1/files/:filePath/share
     * @access  Private (file owners only)
     */
    shareFile: asyncHandler(async (req, res) => {
        try {
            const {filePath} = req.params;
            const {userIds, permission = 'read'} = req.body;
            const decodedFilePath = decodeFilePath(filePath);
            const userId = getUserId(req);

            // Validate input
            if (!userIds || (!Array.isArray(userIds) && typeof userIds !== 'string')) {
                return res.status(400).json({
                    success: false,
                    message: 'userIds is required and must be an array or string'
                });
            }

            if (!['read', 'write'].includes(permission)) {
                return res.status(400).json({
                    success: false,
                    message: 'Permission must be either "read" or "write"'
                });
            }

            // Find the file
            const file = await File.findOne({filePath: decodedFilePath});

            if (!file) {
                return res.status(404).json({
                    success: false,
                    message: 'File not found'
                });
            }

            // Check if user is the file owner or has write permissions
            const isOwner = file.owner.toString() === userId;
            const hasWritePermission = file.permissions.write.some(writeUserId => writeUserId.toString() === userId);
            
            if (!isOwner && !hasWritePermission) {
                return res.status(403).json({
                    success: false,
                    message: 'Only file owners and users with write permissions can share files'
                });
            }

            // Share the file with permission propagation
            try {
                await file.shareWithUsers(userIds, permission);
                await file.save();

                // Invalidate related caches after file sharing for owner and recipients
                const userIdsArray = Array.isArray(userIds) ? userIds : [userIds];
                await cache.invalidateAllRelatedCaches('file', decodedFilePath, userId);
                await Promise.all(userIdsArray.map(async (sharedUserId) => {
                    if (!sharedUserId) return;
                    try {
                        await cache.invalidateAllRelatedCaches('file', decodedFilePath, sharedUserId.toString());
                    } catch (cacheError) {
                        logger.warn('Failed to invalidate cache for shared user:', {
                            sharedUserId,
                            filePath: decodedFilePath,
                            error: cacheError.message
                        });
                    }
                }));

                // Populate shared users for response
                await file.populate('permissions.read permissions.write', 'firstName lastName username email');

                // Broadcast file sharing notification
                try {
                    await notificationService.broadcastFileEvent(
                        FILE_EVENTS.FILE_SHARED,
                        {
                            sharedBy: userId,
                            sharedWith: userIdsArray,
                            permission,
                            fileName: file.fileName,
                            fileType: file.type
                        },
                        decodedFilePath
                    );
                } catch (notificationError) {
                    logger.warn('Failed to send sharing notification:', notificationError.message);
                    // Don't fail the request if notification fails
                }

                res.status(200).json({
                    success: true,
                    message: `File shared with ${permission} permission successfully`,
                    file: {
                        _id: file._id,
                        filePath: file.filePath,
                        owner: file.owner,
                        permissions: file.permissions,
                        sharedUsers: file.getSharedUsers()
                    },
                    meta: {
                        timestamp: new Date().toISOString(),
                        permissionsPropagated: true
                    }
                });
            } catch (shareError) {
                logger.error('File sharing error:', {
                    userId,
                    filePath: decodedFilePath,
                    error: shareError.message
                });
                
                return res.status(400).json({
                    success: false,
                    message: shareError.message
                });
            }
        } catch (error) {
            const userId = req.user?.id || 'unknown';
            logger.error('Share file error:', {message: error.message, userId});
            throw new AppError('Error sharing file', 500);
        }
    }),

    /**
     * @desc    Remove users from file permissions
     * @route   DELETE /api/v1/files/:filePath/share
     * @access  Private (file owners only)
     */
    unshareFile: asyncHandler(async (req, res) => {
        try {
            const {filePath} = req.params;
            const {userIds, permission = 'both'} = req.body;
            const decodedFilePath = decodeFilePath(filePath);
            const userId = getUserId(req);

            // Validate input
            if (!userIds || (!Array.isArray(userIds) && typeof userIds !== 'string')) {
                return res.status(400).json({
                    success: false,
                    message: 'userIds is required and must be an array or string'
                });
            }

            if (!['read', 'write', 'both'].includes(permission)) {
                return res.status(400).json({
                    success: false,
                    message: 'Permission must be either "read", "write", or "both"'
                });
            }

            // Find the file
            const file = await File.findOne({filePath: decodedFilePath});

            if (!file) {
                return res.status(404).json({
                    success: false,
                    message: 'File not found'
                });
            }

            // Check if user is the file owner
            if (file.owner.toString() !== userId) {
                return res.status(403).json({
                    success: false,
                    message: 'Only file owners can modify file permissions'
                });
            }

            // Remove users from permissions
            try {
                const userIdsArray = Array.isArray(userIds) ? userIds : [userIds];
                
                // Notify users being removed BEFORE removing them from permissions
                // This ensures they receive the notification while still having access
                try {
                    await notificationService.broadcastFileEvent(
                        FILE_EVENTS.FILE_UNSHARED,
                        {
                            unsharedBy: userId,
                            unsharedFrom: userIdsArray,
                            permission,
                            fileName: file.fileName,
                            fileType: file.type
                        },
                        userIdsArray  // Send directly to removed users
                    );
                } catch (notificationError) {
                    logger.warn('Failed to send unsharing notification to removed users:', notificationError.message);
                    // Don't fail the request if notification fails
                }
                
                // Now remove users from permissions
                file.removeUsersFromPermissions(userIds, permission, userId);
                await file.save();

                // Invalidate related caches for owner and affected users
                await cache.invalidateAllRelatedCaches('file', decodedFilePath, userId);
                await Promise.all(userIdsArray.map(async (affectedUserId) => {
                    if (!affectedUserId) return;
                    try {
                        await cache.invalidateAllRelatedCaches('file', decodedFilePath, affectedUserId.toString());
                    } catch (cacheError) {
                        logger.warn('Failed to invalidate cache for unshared user:', {
                            affectedUserId,
                            filePath: decodedFilePath,
                            error: cacheError.message
                        });
                    }
                }));

                // Populate shared users for response
                await file.populate('permissions.read permissions.write', 'firstName lastName username email');

                // Also notify remaining users with access about the unshare event
                try {
                    await notificationService.broadcastFileEvent(
                        FILE_EVENTS.FILE_UNSHARED,
                        {
                            unsharedBy: userId,
                            unsharedFrom: userIdsArray,
                            permission,
                            fileName: file.fileName,
                            fileType: file.type
                        },
                        decodedFilePath  // Send to current owner/collaborators
                    );
                } catch (notificationError) {
                    logger.warn('Failed to send unsharing notification to remaining users:', notificationError.message);
                    // Don't fail the request if notification fails
                }

                res.status(200).json({
                    success: true,
                    message: `Users removed from file permissions successfully`,
                    file: {
                        _id: file._id,
                        filePath: file.filePath,
                        owner: file.owner,
                        permissions: file.permissions,
                        sharedUsers: file.getSharedUsers()
                    },
                    meta: {
                        timestamp: new Date().toISOString()
                    }
                });
            } catch (unshareError) {
                return res.status(400).json({
                    success: false,
                    message: unshareError.message
                });
            }
        } catch (error) {
            const userId = req.user?.id || 'unknown';
            logger.error('Unshare file error:', {message: error.message, userId});
            throw new AppError('Error removing file permissions', 500);
        }
    }),

    /**
     * @desc    Get file sharing information
     * @route   GET /api/v1/files/:filePath/share
     * @access  Private (file owners only)
     */
    getFileSharing: asyncHandler(async (req, res) => {
        try {
            const {filePath} = req.params;
            const decodedFilePath = decodeFilePath(filePath);
            const userId = getUserId(req);

            // Find the file
            const file = await File.findOne({filePath: decodedFilePath})
                .populate('owner', 'firstName lastName username email')
                .populate('permissions.read', 'firstName lastName username email')
                .populate('permissions.write', 'firstName lastName username email');

            if (!file) {
                return res.status(404).json({
                    success: false,
                    message: 'File not found'
                });
            }

            // Check if user has any access to the file (owner, read, or write permissions)
            const isOwner = file.owner._id.toString() === userId;
            const hasWritePermission = file.permissions.write.some(writeUser => writeUser._id.toString() === userId);
            const hasReadPermission = file.permissions.read.some(readUser => readUser._id.toString() === userId);
            
            if (!isOwner && !hasWritePermission && !hasReadPermission) {
                return res.status(403).json({
                    success: false,
                    message: 'You do not have access to view this file\'s sharing information'
                });
            }

            const sharedUsers = file.getSharedUsers();

            res.status(200).json({
                success: true,
                message: 'File sharing information retrieved successfully',
                sharing: {
                    permissions: {
                        read: file.permissions.read,
                        write: file.permissions.write
                    },
                    sharedUsers,
                    totalSharedUsers: sharedUsers.length
                },
                file: {
                    _id: file._id,
                    filePath: file.filePath,
                    fileName: file.fileName,
                    owner: file.owner,
                    permissions: {
                        read: file.permissions.read,
                        write: file.permissions.write
                    },
                    sharedUsers,
                    totalSharedUsers: sharedUsers.length
                },
                meta: {
                    timestamp: new Date().toISOString()
                }
            });
        } catch (error) {
            const userId = req.user?.id || 'unknown';
            logger.error('Get file sharing error:', {message: error.message, userId});
            throw new AppError('Error retrieving file sharing information', 500);
        }
    }),

    /**
     * @desc    Upload single file with automatic storage handling
     * @route   POST /api/v1/files/upload
     * @access  Private (requires authentication)
     */
    uploadFile: asyncHandler(async (req, res) => {
        const userId = getUserId(req);
        const userRoles = req.user?.roles || [];

        // Validate file upload
        if (!req.files || req.files.length === 0) {
            logger.warn('File upload failed - no files provided', { userId });
            throw new AppError('No files were uploaded', 400);
        }

        // Parse and validate request body
        const {
            description = '',
            tags = [],
            permissions = {},
            basePath = '/uploads',
            overwrite = false
        } = req.body;

        // Standardized input parsing
        const parsedTags = Array.isArray(tags) ? tags : 
            (typeof tags === 'string' ? tags.split(',').map(t => t.trim()).filter(Boolean) : []);

        let parsedPermissions = {};
        if (permissions) {
            try {
                parsedPermissions = typeof permissions === 'string' ? 
                    JSON.parse(permissions) : permissions;
            } catch (error) {
                logger.warn('Invalid permissions format in upload', { userId, permissions });
                throw new AppError('Invalid permissions format', 400);
            }
        }

        // Process files
        const uploadedFiles = [];
        const errors = [];

        for (const uploadedFile of req.files) {
            try {
                // Standardized path construction
                const filePath = path.posix.join(basePath, uploadedFile.originalname);
                const fileType = File.getFileType(uploadedFile.originalname);

                // Check if file already exists
                const existingFile = await File.findOne({
                    filePath,
                    owner: userId
                });

                if (existingFile && !overwrite) {
                    errors.push({
                        fileName: uploadedFile.originalname,
                        error: 'File already exists'
                    });
                    continue;
                }

                let file;
                if (existingFile && overwrite) {
                    // Update existing file based on type
                    if (existingFile.type === 'text') {
                        // For text files, NEVER overwrite existing Yjs collaborative content
                        logger.warn('Upload with overwrite attempted on text file - preserving collaborative content', {
                            filePath,
                            userId,
                            uploadSize: uploadedFile.buffer.length
                        });
                        
                        // Only update metadata, not content
                        existingFile.description = description || existingFile.description;
                        existingFile.tags = parsedTags || existingFile.tags;
                        existingFile.lastModifiedBy = userId;
                        // Don't update size - keep actual collaborative content size
                        file = await existingFile.save();
                        
                        // Do NOT attempt to overwrite Yjs document - it preserves its own content
                    } else {
                        // For binary files, use GridFS storage
                        const content = uploadedFile.buffer.toString('base64');
                        await compressAndStore(existingFile, content);
                        existingFile.description = description || existingFile.description;
                        existingFile.tags = parsedTags || existingFile.tags;
                        existingFile.lastModifiedBy = userId;
                        file = await existingFile.save();
                    }
                } else {
                    // Ensure parent directories exist
                    await ensureParentDirs(filePath, userId);
                    
                    // Create new file
                    file = await File.create({
                        filePath,
                        fileName: uploadedFile.originalname,
                        type: fileType,
                        mimeType: uploadedFile.mimetype,
                        description: description || `Uploaded file: ${uploadedFile.originalname}`,
                        tags: parsedTags || [],
                        permissions: parsedPermissions || { read: [], write: [] },
                        owner: userId,
                        lastModifiedBy: userId,
                        size: uploadedFile.buffer.length
                    });
                    
                    // Set content based on file type
                    if (file.type === 'text') {
                        // For text files, just store the content in GridFS as backup
                        // Yjs document will be created when content is first accessed
                        const textContent = uploadedFile.buffer.toString('utf8');
                        await file.setContent(uploadedFile.buffer);
                    } else {
                        // For binary files, use GridFS storage
                        await file.setContent(uploadedFile.buffer);
                    }
                }

                await file.populate('owner lastModifiedBy', 'firstName lastName username email');
                uploadedFiles.push(file);

                logger.info('File uploaded successfully', {
                    fileName: uploadedFile.originalname,
                    size: uploadedFile.size,
                    storageType: file.storageType,
                    userId,
                    fileId: file._id,
                    filePath,
                    type: fileType
                });

            } catch (fileError) {
                logger.error('Failed to upload file', {
                    error: fileError.message,
                    fileName: uploadedFile.originalname,
                    userId
                });
                errors.push({
                    fileName: uploadedFile.originalname,
                    error: fileError.message
                });
            }
        }

        // Standardized response
        const response = {
            success: true,
            message: uploadedFiles.length === 1 ? 
                'File uploaded successfully' : 
                `${uploadedFiles.length} files uploaded successfully`,
            files: uploadedFiles,
            meta: {
                totalFiles: req.files.length,
                successfulUploads: uploadedFiles.length,
                failedUploads: errors.length,
                timestamp: new Date().toISOString()
            }
        };

        // Include errors in message if any files failed
        if (errors.length > 0) {
            response.message += ` (${errors.length} failed)`;
            response.errors = errors;
        }

        res.status(201).json(response);
    }),



};

async function executeFileOperation(operation, data, userId, userRoles = []) {
    
    // Extract common data properties once
    const { filePath, sourcePath, content, message, destinationPath, dirPath } = data;
    
    // Determine the effective file path based on operation type (declare outside try block for error logging)
    let effectiveFilePath;
    if (operation === 'copy' || operation === 'move') {
        effectiveFilePath = sourcePath;
    } else if (operation === 'createDir') {
        effectiveFilePath = dirPath || filePath;
    } else {
        effectiveFilePath = filePath;
    }
    
    try {
        // Validate input parameters
        if (!operation || !effectiveFilePath) {
            return {
                success: false,
                error: 'Operation and file path are required',
                statusCode: 400
            };
        }
        
        // For operations that require a destination path
        if ((operation === 'copy' || operation === 'move') && !destinationPath) {
            return {
                success: false,
                error: 'Destination path is required for copy/move operations',
                statusCode: 400
            };
        }
        
        switch (operation) {
            case 'save':
                // Implement save logic directly since HTTP endpoint was removed
                const file = await File.findOneWithWritePermission(
                    {filePath: effectiveFilePath},
                    userId,
                    userRoles
                );
                
                if (!file) {
                    throw new Error('File not found or insufficient permissions');
                }

                // Validate content is provided for save operation
                if (content === undefined || content === null) {
                    throw new Error('Content is required for save operation');
                }
                
                if (file.type === 'text') {
                    logger.error('TEXT FILE HTTP SAVE REJECTED', {
                        userId,
                        filePath: effectiveFilePath,
                        fileType: file.type
                    });
                    throw new AppError('Text files cannot be saved via HTTP API. Use WebSocket collaborative editing instead.', 400);
                } else {
                    // For binary files, pass raw content directly - compressAndStore will handle encoding
                    await compressAndStore(file, content);
                }
                
                // Clear cache using comprehensive cache invalidation
                await cache.invalidateAllRelatedCaches('file', effectiveFilePath, userId);
                
                const saveResult = { 
                    success: true, 
                    operation: 'save',
                    message: 'File content saved successfully',
                    version: file.version,
                    filePath: effectiveFilePath,
                    fileType: file.type,
                    size: file.size,
                    timestamp: new Date().toISOString()
                };
                
                return saveResult;
                
            case 'getContent':
                // Implement getContent logic directly since HTTP endpoint was removed
                const getFile = await File.findOneWithReadPermission(
                    {filePath: effectiveFilePath},
                    userId,
                    userRoles
                );
                
                if (!getFile) {
                    throw new Error('File not found or access denied');
                }
                
                const fileContent = await getAndDecompress(getFile);
                
                const contentResult = { 
                    success: true, 
                    operation: 'getContent',
                    content: fileContent,
                    fileType: getFile.type,
                    size: getFile.size,
                    mimeType: getFile.mimeType,
                    lastModified: getFile.updatedAt,
                    owner: getFile.owner.toString(),
                    version: getFile.version,
                    filePath: effectiveFilePath,
                    timestamp: new Date().toISOString()
                };
                
                return contentResult;
                
            case 'getMetadata':
                // Implement getMetadata logic directly since HTTP endpoint was removed
                const metaFile = await File.findOneWithReadPermission(
                    {filePath: effectiveFilePath},
                    userId,
                    userRoles
                );
                
                if (!metaFile) {
                    throw new Error('File not found or access denied');
                }

                // Use MongoDB timestamp only - avoid Yjs metadata calls that can affect timestamps
                // Only use metaFile.updatedAt for consistent, non-interfering metadata display
                const effectiveUpdatedAt = metaFile.updatedAt;
                
                // Calculate real-time size for text files from Yjs document
                let size = metaFile.size;
                if (metaFile.type === 'text') {
                    try {
                        const yjsContent = await yjsService.getTextContent(effectiveFilePath);
                        if (yjsContent) {
                            size = Buffer.byteLength(yjsContent, 'utf8');
                        }
                    } catch (error) {
                        // If Yjs content not available, fall back to stored size
                        logger.warn(`Could not get Yjs content size for ${effectiveFilePath}:`, error.message);
                    }
                }
                
                const metadataResult = {
                    success: true,
                    operation: 'getMetadata',
                    _id: metaFile._id,
                    filePath: metaFile.filePath,
                    fileName: metaFile.fileName,
                    type: metaFile.type,
                    mimeType: metaFile.mimeType,
                    size,
                    owner: metaFile.owner,
                    tags: metaFile.tags,
                    description: metaFile.description,
                    permissions: metaFile.permissions,
                    version: metaFile.version,
                    versionHistory: metaFile.versionHistory || [],
                    createdAt: metaFile.createdAt,
                    updatedAt: effectiveUpdatedAt, // Use enhanced last modified time
                    lastModifiedBy: metaFile.lastModifiedBy,
                    timestamp: new Date().toISOString()
                };
                
                return metadataResult;
                
            case 'updateMetadata':
                // Implement updateMetadata logic directly since HTTP endpoint was removed
                const updateFile = await File.findOneWithWritePermission(
                    {filePath: effectiveFilePath},
                    userId,
                    userRoles
                );
                
                if (!updateFile) {
                    throw new Error('File not found or access denied');
                }
                
                const updateMetadata = data.updateMetadata || {};
                let hasChanges = false;
                const updates = {};
                
                // Handle description update
                if (updateMetadata.description !== undefined && updateMetadata.description !== updateFile.description) {
                    updates.description = updateMetadata.description;
                    hasChanges = true;
                }
                
                // Handle tags update
                if (updateMetadata.tags !== undefined && JSON.stringify(updateMetadata.tags) !== JSON.stringify(updateFile.tags)) {
                    updates.tags = updateMetadata.tags;
                    hasChanges = true;
                }
                
                // Handle permissions update (admin only for now)
                if (updateMetadata.permissions !== undefined && userRoles.includes('admin')) {
                    updates.permissions = updateMetadata.permissions;
                    hasChanges = true;
                }
                
                if (hasChanges) {
                    updates.updatedAt = new Date();
                    updates.lastModifiedBy = userId;
                    
                    await File.updateOne({_id: updateFile._id}, updates);
                    
                    // Refresh the file to get updated data
                    const updatedFile = await File.findById(updateFile._id);
                    
                    return {
                        success: true,
                        operation: 'updateMetadata',
                        metadata: {
                            _id: updatedFile._id,
                            filePath: updatedFile.filePath,
                            fileName: updatedFile.fileName,
                            type: updatedFile.type,
                            mimeType: updatedFile.mimeType,
                            size: updatedFile.size,
                            owner: updatedFile.owner,
                            tags: updatedFile.tags,
                            description: updatedFile.description,
                            permissions: updatedFile.permissions,
                            version: updatedFile.version,
                            versionHistory: updatedFile.versionHistory || [],
                            createdAt: updatedFile.createdAt,
                            updatedAt: updatedFile.updatedAt,
                            lastModifiedBy: updatedFile.lastModifiedBy
                        },
                        timestamp: new Date().toISOString()
                    };
                } else {
                    return {
                        success: true,
                        operation: 'updateMetadata',
                        message: 'No changes to apply',
                        metadata: {
                            _id: updateFile._id,
                            filePath: updateFile.filePath,
                            fileName: updateFile.fileName,
                            type: updateFile.type,
                            mimeType: updateFile.mimeType,
                            size: updateFile.size,
                            owner: updateFile.owner,
                            tags: updateFile.tags,
                            description: updateFile.description,
                            permissions: updateFile.permissions,
                            version: updateFile.version,
                            versionHistory: updateFile.versionHistory || [],
                            createdAt: updateFile.createdAt,
                            updatedAt: updateFile.updatedAt,
                            lastModifiedBy: updateFile.lastModifiedBy
                        },
                        timestamp: new Date().toISOString()
                    };
                }
                
            case 'publish':
                // Create a version snapshot directly from existing file content
                // Publish should work independently without requiring a save operation
                const pubFile = await File.findOneWithWritePermission(
                    {filePath: effectiveFilePath},
                    userId,
                    userRoles
                );
                
                if (!pubFile) {
                    throw new Error('File not found or insufficient permissions');
                }
                
                const publishMessage = message || `Published at ${new Date().toLocaleString()}`;
                const updatedFile = await pubFile.createVersionSnapshot(userId, publishMessage, (path) => yjsService.getTextContent(path));
                
                const totalVersions = updatedFile.versionHistory.length;
                // Latest version number is last index + 1 (sequential numbering)
                const versionNumber = totalVersions;
                
                return { 
                    success: true, 
                    operation: 'publish',
                    message: `Version ${versionNumber} published successfully`,
                    versionNumber: versionNumber, // Latest version is always 1
                    versionCount: totalVersions,
                    filePath: effectiveFilePath,
                    timestamp: new Date().toISOString()
                };
                
            case 'getVersions':
                // Get file versions via WebSocket
                const versionsFile = await File.findOneWithReadPermission(
                    {filePath: effectiveFilePath},
                    userId,
                    userRoles
                );
                
                if (!versionsFile) {
                    throw new Error('File not found or insufficient permissions');
                }
                
                // Transform version history to include computed version numbers (sequential)
                const transformedVersions = versionsFile.versionHistory.map((version, index) => ({
                    ...version.toObject(),
                    version: index + 1, // Sequential version numbering
                    isCurrent: index === versionsFile.versionHistory.length - 1, // Latest version is at end
                    createdAt: version.timestamp,
                    size: version.size || 0
                }));
                
                return { 
                    success: true, 
                    operation: 'getVersions',
                    message: 'File versions retrieved successfully',
                    versions: transformedVersions,
                    totalVersions: versionsFile.versionHistory.length,
                    filePath: effectiveFilePath,
                    timestamp: new Date().toISOString()
                };
                
            case 'create':
                // Create new file (content is optional - empty files are allowed)
                const createFileData = {
                    filePath: effectiveFilePath,
                    type: 'text', // Use correct field name and proper type for text files
                    description: message || 'Created via API request',
                    owner: userId
                };
                
                // Ensure parent directories exist
                await ensureParentDirs(effectiveFilePath, userId);
                
                const newFile = await File.create(createFileData);
                
                // Handle content initialization
                if (newFile.type === 'text') {
                    if (content && content.trim() !== '') {
                        // Initialize Yjs document with content (ONLY legitimate HTTP-to-Yjs write)
                        await yjsService.initializeTextContent(effectiveFilePath, content);
                        newFile.size = Buffer.byteLength(content, 'utf8');
                    } else {
                        // Text files created empty - content added via WebSocket collaborative editing
                        newFile.size = 0;
                    }
                    await newFile.save();
                } else if (content) {
                    // For binary files, only store if content is provided
                    await compressAndStore(newFile, content);
                }
                
                // Clear all related caches using comprehensive cache invalidation
                await cache.invalidateAllRelatedCaches('file', effectiveFilePath, userId);
                
                return {
                    success: true,
                    operation: 'create',
                    message: 'File created successfully',
                    file: {
                        id: newFile._id,
                        filePath: effectiveFilePath,
                        type: newFile.type
                    },
                    timestamp: new Date().toISOString()
                };
                
            case 'createDir':
                // Create new directory (use consistent filePath parameter)
                const dirPath = data.dirPath || data.filePath; // Accept both for compatibility
                if (!dirPath) {
                    throw new Error('Directory path is required');
                }
                
                // Use directory path directly (no decoding needed for WebSocket)
                const normalizedDirPath = dirPath.replace(/\/$/, '') || '/';
                
                // Ensure parent directories exist
                await ensureParentDirs(normalizedDirPath, userId);
                
                const createDirData = {
                    filePath: normalizedDirPath,
                    type: 'directory',
                    description: data.description || 'Created via API request',
                    owner: userId
                };
                
                const newDir = await File.create(createDirData);
                
                // Clear all related caches using comprehensive cache invalidation
                await cache.invalidateAllRelatedCaches('file', normalizedDirPath, userId);
                
                return {
                    success: true,
                    operation: 'createDir',
                    message: 'Directory created successfully',
                    directory: {
                        id: newDir._id,
                        filePath: dirPath,
                        type: newDir.type
                    },
                    timestamp: new Date().toISOString()
                };
                
            case 'delete':
                // Delete file or directory with cascading support
                const deleteFile = await File.findOneWithWritePermission(
                    {filePath: effectiveFilePath},
                    userId,
                    userRoles
                );
                
                if (!deleteFile) {
                    throw new Error('File not found or insufficient permissions');
                }

                // If it's a directory, handle cascading deletion
                if (deleteFile.type === 'directory') {
                    // Get force flag from data (default to true for WebSocket since it's explicit user action)
                    const force = data.force !== false; // Default to true unless explicitly false
                    
                    if (force) {
                        // Recursive deletion - delete all children first
                        const childQuery = {
                            $or: [
                                {parentPath: effectiveFilePath},
                                {filePath: new RegExp(`^${effectiveFilePath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}/`)}
                            ],
                            $and: [{
                                $or: [
                                    {owner: userId}, // Owner can delete
                                    {'permissions.write': userId} // User has explicit write permission
                                ]
                            }]
                        };

                        // Get all children for cache cleanup
                        const children = await File.find(childQuery, 'filePath').lean();

                        // Delete all children in one operation
                        await File.deleteMany(childQuery);

                        // Clear caches for all deleted files
                        for (const child of children) {
                            await cache.invalidateAllRelatedCaches('file', child.filePath, userId);
                        }
                    } else {
                        // Check if directory is empty
                        const childCount = await File.countDocuments({
                            parentPath: effectiveFilePath,
                            $or: [
                                {owner: userId},
                                {'permissions.read': userId}
                            ]
                        });

                        if (childCount > 0) {
                            throw new Error('Directory is not empty. Use force option to delete with contents.');
                        }
                    }
                }
                
                // Get shared users before deletion for cache invalidation and notifications
                const sharedUsers = deleteFile.getSharedUsers();
                const affectedUsersDelete = [userId.toString(), ...sharedUsers];
                
                // Delete the file/directory itself
                await deleteFile.deleteOne();
                
                // Clear all related caches for owner
                await cache.invalidateAllRelatedCaches('file', effectiveFilePath, userId);
                
                // Clear caches for all shared users (collaborators)
                await Promise.all(sharedUsers.map(async (sharedUserId) => {
                    if (sharedUserId === userId.toString()) return; // Skip owner, already done
                    try {
                        await cache.invalidateAllRelatedCaches('file', effectiveFilePath, sharedUserId);
                    } catch (cacheError) {
                        logger.warn('Failed to invalidate cache for shared user during delete:', {
                            sharedUserId,
                            filePath: effectiveFilePath,
                            error: cacheError.message
                        });
                    }
                }));
                
                // Broadcast notification to all affected users (file already deleted, pass users directly)
                notificationService.broadcastFileEvent(
                    FILE_EVENTS.FILE_DELETED,
                    {
                        filePath: effectiveFilePath,
                        fileName: deleteFile.fileName,
                        fileType: deleteFile.type,
                        userId
                    },
                    affectedUsersDelete
                );
                
                return {
                    success: true,
                    operation: 'delete',
                    message: `${deleteFile.type === 'directory' ? 'Directory' : 'File'} deleted successfully`,
                    filePath: effectiveFilePath,
                    timestamp: new Date().toISOString()
                };
                
            case 'move':
                // Move file or directory
                const moveFile = await File.findOneWithWritePermission(
                    {filePath: sourcePath},
                    userId,
                    userRoles
                );
                
                if (!moveFile) {
                    throw new Error('Source file not found or insufficient permissions');
                }
                
                // Destination is always a directory - combine with source filename
                const sourceFileName = moveFile.fileName;
                const newFilePath = `${destinationPath}/${sourceFileName}`;
                
                // For text files, capture Yjs snapshot before path change
                let yjsBeforeMove = null;
                if (moveFile.type === 'text') {
                    try {
                        const beforeContent = await yjsService.getTextContent(sourcePath);
                        yjsBeforeMove = { length: beforeContent.length, preview: beforeContent.slice(0, 80) };
                    } catch (e) {
                        // Failed to read before snapshot - continue anyway
                        logger.warn('Failed to capture Yjs snapshot before move:', e.message);
                    }
                }

                // Ensure parent directories exist for the new path
                await ensureParentDirs(newFilePath, userId);
                
                // For binary files, rename in GridFS before updating the database record
                if (moveFile.type === 'binary' && moveFile.gridFSId) {
                    try {
                        const { renameInGridFS } = require('../config/db');
                        await renameInGridFS(sourcePath, newFilePath);
                    } catch (error) {
                        // Don't fail the operation, but log the issue
                        logger.error('Failed to rename file in GridFS during move:', error.message);
                    }
                }
                
                // Update the file path - fileName and parentPath will be auto-calculated by the model
                moveFile.filePath = newFilePath;
                await moveFile.save();

                // For text files, migrate Yjs doc and active sessions from old path to new path
                if (moveFile.type === 'text') {
                    try {
                        await yjsService.moveDocument(sourcePath, newFilePath);
                        
                        // Verify migration succeeded
                        const afterContent = await yjsService.getTextContent(newFilePath);
                        
                        // Verify content integrity
                        if (yjsBeforeMove && afterContent.length !== yjsBeforeMove.length) {
                            logger.warn('YJS move: Content length mismatch after migration', {
                                beforeLength: yjsBeforeMove.length,
                                afterLength: afterContent.length,
                                filePath: newFilePath
                            });
                        }
                    } catch (migrationError) {
                        // Rollback file metadata changes if Yjs migration failed
                        logger.error('YJS move migration failed, rolling back:', migrationError.message);
                        
                        moveFile.filePath = sourcePath;
                        await moveFile.save();
                        
                        throw new Error(`Failed to migrate collaborative document: ${migrationError.message}`);
                    }
                }
                
                // Get shared users for cache invalidation and notifications
                const sharedUsersMove = moveFile.getSharedUsers();
                const affectedUsersMove = [userId.toString(), ...sharedUsersMove];
                
                // Clear all related caches for both source and destination paths (owner)
                await cache.invalidateAllRelatedCaches('file', sourcePath, userId);
                await cache.invalidateAllRelatedCaches('file', newFilePath, userId);
                
                // Clear caches for all shared users (collaborators)
                await Promise.all(sharedUsersMove.map(async (sharedUserId) => {
                    if (sharedUserId === userId.toString()) return; // Skip owner, already done
                    try {
                        await cache.invalidateAllRelatedCaches('file', sourcePath, sharedUserId);
                        await cache.invalidateAllRelatedCaches('file', newFilePath, sharedUserId);
                    } catch (cacheError) {
                        logger.warn('Failed to invalidate cache for shared user during move:', {
                            sharedUserId,
                            oldPath: sourcePath,
                            newPath: newFilePath,
                            error: cacheError.message
                        });
                    }
                }));
                
                // Broadcast notification to all affected users (pass users directly)
                notificationService.broadcastFileEvent(
                    FILE_EVENTS.FILE_MOVED,
                    {
                        oldFilePath: sourcePath,
                        newFilePath: newFilePath,
                        fileName: moveFile.fileName,
                        fileType: moveFile.type,
                        userId
                    },
                    affectedUsersMove
                );
                
                return {
                    success: true,
                    operation: 'move',
                    message: 'File moved successfully',
                    oldPath: sourcePath,
                    newPath: newFilePath,
                    timestamp: new Date().toISOString()
                };
                
            case 'copy':
                // Copy file or directory
                
                const copyFile = await File.findOneWithReadPermission(
                    {filePath: sourcePath},
                    userId,
                    userRoles
                );
                
                if (!copyFile) {
                    throw new Error('Source file not found or insufficient permissions');
                }
                
                // Destination is always a directory - combine with source filename
                const copySourceFileName = copyFile.fileName;
                const copyNewFilePath = `${destinationPath}/${copySourceFileName}`;
                
                const copyData = {
                    ...copyFile.toObject(),
                    _id: undefined,
                    filePath: copyNewFilePath,
                    // Remove these so pre-save middleware can calculate them from filePath
                    fileName: undefined,
                    parentPath: undefined,
                    owner: userId,
                    createdAt: new Date(),
                    updatedAt: new Date(),
                    versionHistory: []
                };
                
                // Ensure parent directories exist for the new path
                await ensureParentDirs(copyNewFilePath, userId);
                
                const copiedFile = await File.create(copyData);
                
                if (copyFile.type === 'text') {
                    // For text files, copy Yjs document content if it exists
                    await yjsService.copyDocument(sourcePath, copyNewFilePath);
                    const textContent = await yjsService.getTextContent(copyNewFilePath);
                    
                    // Update file size to match content
                    copiedFile.size = Buffer.byteLength(textContent, 'utf8');
                    await copiedFile.save();
                } else if (copyFile.type === 'binary') {
                    // For binary files, get raw content and compress/store
                    const rawContent = await getAndDecompress(copyFile);
                    await compressAndStore(copiedFile, rawContent);
                }
                // Directories don't need content handling
                
                // Get shared users from source file for cache invalidation and notifications
                const sharedUsersCopy = copyFile.getSharedUsers();
                const affectedUsersCopy = [userId.toString(), ...sharedUsersCopy];
                
                // Clear all related caches for the destination path (owner)
                await cache.invalidateAllRelatedCaches('file', copyNewFilePath, userId);
                
                // Clear caches for all shared users of the source file (collaborators)
                await Promise.all(sharedUsersCopy.map(async (sharedUserId) => {
                    if (sharedUserId === userId.toString()) return; // Skip owner, already done
                    try {
                        await cache.invalidateAllRelatedCaches('file', copyNewFilePath, sharedUserId);
                    } catch (cacheError) {
                        logger.warn('Failed to invalidate cache for shared user during copy:', {
                            sharedUserId,
                            sourcePath: sourcePath,
                            newPath: copyNewFilePath,
                            error: cacheError.message
                        });
                    }
                }));
                
                // Broadcast notification to all affected users (copy creates a new file, pass users directly)
                notificationService.broadcastFileEvent(
                    FILE_EVENTS.FILE_CREATED,
                    {
                        filePath: copyNewFilePath,
                        fileName: copiedFile.fileName,
                        fileType: copiedFile.type,
                        userId
                    },
                    affectedUsersCopy
                );
                
                return {
                    success: true,
                    operation: 'copy',
                    message: 'File copied successfully',
                    oldPath: sourcePath,
                    newPath: copyNewFilePath,
                    timestamp: new Date().toISOString()
                };
                
            case 'loadVersion':
                // Load a specific version for read-only viewing (does NOT overwrite current content)
                const { versionNumber: loadVersionNum } = data;
                if (!loadVersionNum) {
                    throw new Error('Version number is required');
                }
                
                const loadVersionFile = await File.findOneWithReadPermission(
                    {filePath: effectiveFilePath},
                    userId,
                    userRoles
                );
                
                if (!loadVersionFile) {
                    throw new Error('File not found or insufficient permissions');
                }
                
                // Convert version number to array index (sequential numbering)
                const loadVersionNumber = parseInt(loadVersionNum);
                const loadVersionIndex = loadVersionNumber - 1;
                
                // Check if version exists at the computed index
                if (loadVersionIndex < 0 || loadVersionIndex >= loadVersionFile.versionHistory.length) {
                    throw new Error(`Version ${loadVersionNum} not found`);
                }
                
                const versionToLoad = loadVersionFile.versionHistory[loadVersionIndex];
                
                // Get version content using the model method (which now only uses GridFS)
                const versionContent = await loadVersionFile.getVersionContent(loadVersionNumber);
                
                // Decode content for client (since version content is stored as base64)
                const clientContent = versionContent ? Buffer.from(versionContent, 'base64').toString('utf8') : '';
                
                // Return version content WITHOUT modifying current working version
                return {
                    success: true,
                    operation: 'loadVersion',
                    message: `Version ${loadVersionNum} loaded for viewing (current version unchanged)`,
                    content: clientContent,
                    versionNumber: loadVersionNumber,
                    versionTimestamp: versionToLoad.timestamp,
                    versionMessage: versionToLoad.message,
                    currentVersion: loadVersionFile.version, // Show current version is unchanged
                    filePath: effectiveFilePath,
                    timestamp: new Date().toISOString(),
                    readOnly: true // Indicate this is read-only content
                };
                
            case 'downloadVersion':
                // Download a specific version as a file
                const { versionNumber: downloadVersionNum } = data;
                if (!downloadVersionNum) {
                    throw new Error('Version number is required');
                }
                
                const downloadVersionFile = await File.findOneWithReadPermission(
                    {filePath: effectiveFilePath},
                    userId,
                    userRoles
                );
                
                if (!downloadVersionFile) {
                    throw new Error('File not found or insufficient permissions');
                }
                
                // Convert version number to array index (sequential numbering)
                const downloadVersionNumber = parseInt(downloadVersionNum);
                const downloadVersionIndex = downloadVersionNumber - 1;
                
                // Check if version exists at the computed index
                if (downloadVersionIndex < 0 || downloadVersionIndex >= downloadVersionFile.versionHistory.length) {
                    throw new Error(`Version ${downloadVersionNum} not found`);
                }
                
                const versionToDownload = downloadVersionFile.versionHistory[downloadVersionIndex];
                
                // Get version content from GridFS
                const downloadVersionContent = await downloadVersionFile.getVersionContent(downloadVersionNumber);
                
                // Convert base64 to buffer for download
                const contentBuffer = Buffer.from(downloadVersionContent, 'base64');
                
                // Return buffer with metadata for download
                return {
                    success: true,
                    operation: 'downloadVersion',
                    content: contentBuffer,
                    fileName: downloadVersionFile.fileName,
                    mimeType: downloadVersionFile.mimeType || 'application/octet-stream',
                    filePath: effectiveFilePath,
                    versionNumber: downloadVersionNumber
                };
                
            case 'deleteVersion':
                // Delete a specific version
                const { versionNumber: deleteVersionNum } = data;
                if (!deleteVersionNum) {
                    throw new Error('Version number is required');
                }
                
                const deleteVersionFile = await File.findOneWithWritePermission(
                    {filePath: effectiveFilePath},
                    userId,
                    userRoles
                );
                
                if (!deleteVersionFile) {
                    throw new Error('File not found or insufficient permissions');
                }
                
                // Use the model's deleteVersion method
                const deleteResult = await deleteVersionFile.deleteVersion(parseInt(deleteVersionNum), userId);
                
                // Clear related caches
                await cache.invalidateAllRelatedCaches('file', effectiveFilePath, userId);
                
                return {
                    success: true,
                    operation: 'deleteVersion',
                    message: deleteResult.message,
                    remainingVersions: deleteResult.remainingVersions,
                    filePath: effectiveFilePath,
                    timestamp: new Date().toISOString()
                };
                
            case 'rename':
                // Rename file or directory (only changes filename within same directory)
                const { newName } = data;
                if (!newName || !newName.trim()) {
                    throw new Error('New name is required for rename operation');
                }
                
                // Validate new name for security and path restrictions
                const sanitizedNewName = newName.trim();
                if (sanitizedNewName.includes('/') || sanitizedNewName.includes('\\')) {
                    throw new Error('File name cannot contain path separators');
                }
                if (sanitizedNewName.includes('..')) {
                    throw new Error('File name cannot contain path traversal characters');
                }
                if (sanitizedNewName.match(/[<>:"|?*]/)) {
                    throw new Error('File name contains invalid characters');
                }
                if (sanitizedNewName.length > 255) {
                    throw new Error('File name too long (maximum 255 characters)');
                }
                
                const renameFile = await File.findOneWithWritePermission(
                    {filePath: effectiveFilePath},
                    userId,
                    userRoles
                );
                
                if (!renameFile) {
                    throw new Error('File not found or insufficient permissions');
                }
                
                // Preserve file extension if not provided for files
                let finalFileName = sanitizedNewName;
                if (renameFile.type !== 'directory') {
                    const originalExtension = path.extname(renameFile.fileName);
                    const newNameExtension = path.extname(finalFileName);
                    
                    if (originalExtension && !newNameExtension) {
                        finalFileName = finalFileName + originalExtension;
                    }
                }
                
                // Check if name is actually different
                if (finalFileName === renameFile.fileName) {
                    throw new Error('New name must be different from current name');
                }
                
                // Extract parent directory and create new path
                const parentPath = effectiveFilePath.substring(0, effectiveFilePath.lastIndexOf('/')) || '/';
                const renamedFilePath = parentPath === '/' ? `/${finalFileName}` : `${parentPath}/${finalFileName}`;
                
                // Check if destination already exists
                const existingFile = await File.findOne({
                    filePath: renamedFilePath,
                    owner: userId
                });
                
                if (existingFile) {
                    throw new Error('A file with that name already exists');
                }
                
                // For binary files, rename in GridFS before updating the database record
                if (renameFile.type === 'binary' && renameFile.gridFSId) {
                    try {
                        const { renameInGridFS } = require('../config/db');
                        await renameInGridFS(effectiveFilePath, renamedFilePath);
                    } catch (error) {
                        logger.error('Failed to rename file in GridFS during rename:', {
                            error: error.message,
                            effectiveFilePath,
                            renamedFilePath,
                            userId
                        });
                        // Don't fail the operation, but log the issue
                    }
                }
                
                // Update the file path - fileName and parentPath will be auto-calculated by the model
                renameFile.filePath = renamedFilePath;
                await renameFile.save();

                // For text files, migrate Yjs doc and active sessions from old path to new path
                if (renameFile.type === 'text') {
                    try {
                        await yjsService.moveDocument(effectiveFilePath, renamedFilePath);
                    } catch (migrationError) {
                        logger.error('YJS rename migration failed:', {
                            oldPath: effectiveFilePath, 
                            newPath: renamedFilePath, 
                            error: migrationError.message
                        });
                        // Continue despite migration error - file rename still succeeded
                    }
                }
                
                // Get shared users for cache invalidation and notifications
                const sharedUsersRename = renameFile.getSharedUsers();
                const affectedUsersRename = [userId.toString(), ...sharedUsersRename];
                
                // Clear all related caches for both old and new paths (owner)
                await cache.invalidateAllRelatedCaches('file', effectiveFilePath, userId);
                await cache.invalidateAllRelatedCaches('file', renamedFilePath, userId);
                
                // Clear caches for all shared users (collaborators)
                await Promise.all(sharedUsersRename.map(async (sharedUserId) => {
                    if (sharedUserId === userId.toString()) return; // Skip owner, already done
                    try {
                        await cache.invalidateAllRelatedCaches('file', effectiveFilePath, sharedUserId);
                        await cache.invalidateAllRelatedCaches('file', renamedFilePath, sharedUserId);
                    } catch (cacheError) {
                        logger.warn('Failed to invalidate cache for shared user during rename:', {
                            sharedUserId,
                            oldPath: effectiveFilePath,
                            newPath: renamedFilePath,
                            error: cacheError.message
                        });
                    }
                }));
                
                // Broadcast notification to all affected users (old path doesn't exist in DB, pass users directly)
                notificationService.broadcastFileEvent(
                    FILE_EVENTS.FILE_RENAMED,
                    {
                        oldFilePath: effectiveFilePath,
                        newFilePath: renamedFilePath,
                        oldFileName: data.name || data.newName, // Original name before rename
                        newFileName: finalFileName,
                        fileType: renameFile.type,
                        userId
                    },
                    affectedUsersRename
                );
                
                return {
                    success: true,
                    operation: 'rename',
                    message: 'File renamed successfully',
                    oldPath: effectiveFilePath,
                    newPath: renamedFilePath,
                    newName: finalFileName,
                    timestamp: new Date().toISOString()
                };
                
            case 'getCollaborators':
                // Get a list of users currently collaborating on this file
                const collabFile = await File.findOneWithReadPermission(
                    {filePath: effectiveFilePath},
                    userId,
                    userRoles
                );
                
                if (!collabFile) {
                    throw new Error('File not found or insufficient permissions');
                }
                
                // Get active collaborators from the collaboration system
                let activeCollaborators = [];
                if (collabFile.type === 'text') {
                    // If there's a collaboration tracking mechanism, use it
                    // Use file path as document name for consistent identification
                    const docId = yjsService.getDocumentName(collabFile.filePath);
                    
                    // Get from active sessions if available
                    // Active collaborators now tracked by WebSocket server
                    activeCollaborators = [];
                }
                
                return {
                    success: true,
                    operation: 'getCollaborators',
                    collaborators: activeCollaborators,
                    filePath: effectiveFilePath,
                    timestamp: new Date().toISOString()
                };
                
            case 'getSharing':
                // Get sharing information for this file
                const sharingFile = await File.findOneWithReadPermission(
                    {filePath: effectiveFilePath},
                    userId,
                    userRoles
                );
                
                if (!sharingFile) {
                    throw new Error('File not found or insufficient permissions');
                }
                
                // Extract permissions and convert to sharing info
                const permissionsMap = {
                    read: sharingFile.permissions?.read || [],
                    write: sharingFile.permissions?.write || [],
                    admin: sharingFile.permissions?.admin || []
                };
                
                // Add information about public sharing if available
                const sharingInfo = {
                    owner: sharingFile.owner,
                    isOwner: sharingFile.owner.toString() === userId,
                    permissions: permissionsMap,
                    isPublic: sharingFile.isPublic || false,
                    publicLink: sharingFile.publicLink || null,
                    publicExpiresAt: sharingFile.publicExpiresAt || null
                };
                
                return {
                    success: true,
                    operation: 'getSharing',
                    sharing: sharingInfo,
                    filePath: effectiveFilePath,
                    timestamp: new Date().toISOString()
                };
                
            default:
                throw new Error(`Unsupported operation: ${operation}`);
        }
    } catch (error) {
        // Ensure we have a filePath for logging, fallback to the original inputs if effectiveFilePath failed to be set
        const logFilePath = effectiveFilePath || sourcePath || filePath || 'unknown';
        logger.error('File operation error:', { operation, filePath: logFilePath, userId, error: error.message });
        return { 
            success: false, 
            error: error.message || 'Operation failed',
            filePath: logFilePath 
        };
    }
};

module.exports.executeFileOperation = executeFileOperation;
module.exports.yjsService = yjsService;
module.exports.normalizeFilePath = normalizeFilePath;
