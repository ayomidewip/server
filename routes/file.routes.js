const router = require('express').Router();
const fileController = require('../controllers/file.controller');
const authMiddleware = require('../middleware/auth.middleware');
const {validateRequest} = require('../middleware/validation.middleware');
const {fileSchemas, fileParamSchemas} = require('../models/schemas');
const {cacheResponse, clearCache, autoInvalidateCache} = require('../middleware/cache.middleware');
const {RIGHTS} = require('../config/rights');

// Define file routes for validation
router.validRoutes = [
    '/api/v1/files',
    '/api/v1/files/types',
    '/api/v1/files/stats',
    '/api/v1/files/compression/stats',
    '/api/v1/files/admin/stats',
    '/api/v1/files/bulk',
    '/api/v1/files/directory',
    '/api/v1/files/tree',
    '/api/v1/files/access/:accessType',
    '/api/v1/files/upload',
    '/api/v1/files/upload-multiple',
    '/api/v1/files/directory/:dirPath/contents',
    '/api/v1/files/directory/:dirPath/stats',
    '/api/v1/files/:filePath',
    '/api/v1/files/:filePath/content',
    '/api/v1/files/:filePath/autosave',
    '/api/v1/files/:filePath/save',
    '/api/v1/files/:filePath/move',
    '/api/v1/files/:filePath/copy',
    '/api/v1/files/:filePath/collaborators',
    '/api/v1/files/:fileId/sync',
    '/api/v1/files/:filePath/versions',
    '/api/v1/files/:filePath/versions/:versionNumber'
];

// Get supported file types (public route)
router.get('/types', fileController.getSupportedTypes);

/**
 * @route   GET /api/v1/files/supported-types
 * @desc    Get supported file types and their MIME types
 * @access  Public
 */
router.get('/supported-types',
    cacheResponse(3600, 'file:types:supported'), // Cache for 1 hour
    fileController.getSupportedTypes
);

/**
 * @route   GET /api/v1/files/stats
 * @desc    Get comprehensive file storage statistics
 * @access  Private (requires MANAGE_ALL_CONTENT permission - Admin/Super Admin only)
 */
router.get('/stats',
    authMiddleware.verifyToken(),
    authMiddleware.checkPermission(RIGHTS.MANAGE_ALL_CONTENT),
    cacheResponse(60, 'file:stats:storage'), // Cache for 1 minute
    fileController.getFileStorageStats
);

/**
 * @route   GET /api/v1/files/compression/stats
 * @desc    Get compression statistics and efficiency metrics
 * @access  Private (requires MANAGE_ALL_CONTENT permission - Admin only)
 */
router.get('/compression/stats',
    authMiddleware.verifyToken(),
    authMiddleware.checkPermission(RIGHTS.MANAGE_ALL_CONTENT),
    cacheResponse(300, 'file:stats:compression'), // Cache for 5 minutes
    fileController.getCompressionStats
);

/**
 * @route   GET /api/v1/files/admin/stats
 * @desc    Get comprehensive file statistics for admin dashboard
 * @access  Private (Admin/Owner only)
 */
router.get('/admin/stats',
    authMiddleware.verifyToken(),
    cacheResponse(60), // Cache for 1 minute with user-specific key
    fileController.getFileStats
);

// Public route: Get demo files (read-only, no authentication required)
router.get('/demo', fileController.getDemoFiles);

// Protect all other file routes
router.use(authMiddleware.verifyToken());

/**
 * @route   POST /api/v1/files/bulk
 * @desc    Perform bulk operations on multiple files/directories
 * @access  Private (requires authentication - permissions checked per file)
 */
router.post('/bulk',
    validateRequest(fileSchemas.bulkOperations),
    fileController.bulkOperations
);

/**
 * @route   POST /api/v1/files/directory
 * @desc    Create a new directory
 * @access  Private (requires authentication)
 */
router.post('/directory',
    validateRequest(fileSchemas.createDirectory),
    clearCache((req) => [
        `user:files:${req.user.id}:all`,
        `directory:tree:${req.user.id}`
    ]),
    fileController.createDirectory
);

/**
 * @route   GET /api/v1/files/tree
 * @desc    Get directory tree structure
 * @access  Private (requires authentication)
 */
router.get('/tree',
    validateRequest(fileSchemas.getDirectoryTree, 'query'),
    cacheResponse(60, (req) => {
        const params = req.query ? new URLSearchParams(req.query).toString() : '';
        return `directory:tree:${req.user.id}${params ? `?${params}` : ''}`;
    }), // Cache for 1 minute
    fileController.getDirectoryTree
);

/**
 * @route   GET /api/v1/files/access/:accessType
 * @desc    Get files by access type (owned, shared-read, shared-write, all)
 * @access  Private (requires authentication)
 */
router.get('/access/:accessType',
    validateRequest(fileSchemas.getFiles, 'query'),
    cacheResponse(300, (req) => {
        const params = req.query ? new URLSearchParams(req.query).toString() : '';
        return `user:files:by:access:${req.user.id}:${req.params.accessType}${params ? `:${Buffer.from(params).toString('base64')}` : ''}`;
    }), // Cache for 5 minutes
    fileController.getFiles // Now using the consolidated getFiles method
);

/**
 * @route   GET /api/v1/files/directory/:dirPath/contents
 * @desc    Get directory contents (immediate children only)
 * @access  Private (requires authentication)
 */
router.get('/directory/:dirPath/contents',
    validateRequest(fileParamSchemas.filePath, 'params'),
    validateRequest(fileSchemas.getDirectoryContents, 'query'),
    cacheResponse(60, (req) => {
        const params = req.query ? new URLSearchParams(req.query).toString() : '';
        return `directory:contents:${req.user.id}:${req.params.dirPath}${params ? `?${params}` : ''}`;
    }), // Cache for 1 minute
    fileController.getDirectoryContents
);

/**
 * @route   GET /api/v1/files/directory/:dirPath/stats
 * @desc    Get directory statistics (recursive size and file counts)
 * @access  Private (requires authentication)
 */
router.get('/directory/:dirPath/stats',
    validateRequest(fileParamSchemas.filePath, 'params'),
    cacheResponse(300, (req) => {
        return `directory:stats:${req.user.id}:${req.params.dirPath}`;
    }), // Cache for 5 minutes
    fileController.getDirectoryStats
);

/**
 * @route   GET /api/v1/files
 * @desc    Get list of user's files with filtering and pagination (permission-based access)
 * @access  Private (requires authentication - admin sees all files, regular users see accessible files)
 */
router.get('/',
    validateRequest(fileSchemas.getFiles, 'query'),
    cacheResponse(300, (req) => {
        // Create cache key based on user ID and query params for permission-based access
        const params = req.query ? new URLSearchParams(req.query).toString() : '';
        return `user:files:${req.user.id}:${params ? Buffer.from(params).toString('base64') : 'all'}`;
    }), // Cache for 5 minutes
    fileController.getFiles
);

/**
 * @route   POST /api/v1/files
 * @desc    Create a new file
 * @access  Private (requires authentication)
 */
router.post('/',
    validateRequest(fileSchemas.createFile),
    authMiddleware.checkPermission(RIGHTS.CREATE_CONTENT),
    clearCache((req) => [`user:files:${req.user.id}:all`]),
    autoInvalidateCache('file', (req) => req.body.filePath, (req) => req.user.id),
    fileController.createFile
);

/**
 * @route   GET /api/v1/files/:filePath
 * @desc    Get file metadata
 * @access  Private (requires authentication)
 */
router.get('/:filePath',
    validateRequest(fileParamSchemas.filePath, 'params'),
    validateRequest(fileSchemas.getFileById, 'query'),
    cacheResponse(600, (req) => `file:metadata:${Buffer.from(req.params.filePath).toString('base64')}:${req.query.version || 'latest'}`), // Cache for 10 minutes
    fileController.getFileById
);

/**
 * @route   PUT /api/v1/files/:filePath
 * @desc    Update file metadata
 * @access  Private (requires write permission or higher)
 */
router.put('/:filePath',
    validateRequest(fileParamSchemas.filePath, 'params'),
    validateRequest(fileSchemas.updateFile),
    clearCache((req) => [
        `file:metadata:${Buffer.from(req.params.filePath).toString('base64')}:latest`,
        `file:content:${Buffer.from(req.params.filePath).toString('base64')}:latest`,
        `user:files:${req.user.id}:all`
    ]),
    autoInvalidateCache('file'),
    fileController.updateFileMetadata
);

/**
 * @route   PATCH /api/v1/files/:filePath
 * @desc    Update specific file version properties (isPermanent, etc.)
 * @access  Private (requires write permission)
 */
router.patch('/:filePath',
    validateRequest(fileParamSchemas.filePath, 'params'),
    validateRequest(fileSchemas.patchFile),
    clearCache((req) => [
        `file:metadata:${Buffer.from(req.params.filePath).toString('base64')}:latest`,
        `file:versions:${Buffer.from(req.params.filePath).toString('base64')}`
    ]),
    fileController.patchFileVersion
);

/**
 * @route   DELETE /api/v1/files/:filePath
 * @desc    Delete file (specific version or all versions)
 * @access  Private (requires write permission)
 */
router.delete('/:filePath',
    validateRequest(fileParamSchemas.filePath, 'params'),
    validateRequest(fileSchemas.deleteFile, 'query'),
    clearCache((req) => [
        `file:metadata:${Buffer.from(req.params.filePath).toString('base64')}:latest`,
        `file:content:${Buffer.from(req.params.filePath).toString('base64')}:latest`,
        `file:versions:${Buffer.from(req.params.filePath).toString('base64')}`,
        `user:files:${req.user.id}:all`
    ]),
    fileController.deleteFile
);

/**
 * @route   PUT /api/v1/files/:filePath/move
 * @desc    Move file or directory to new location
 * @access  Private (requires write permission)
 */
router.put('/:filePath/move',
    validateRequest(fileParamSchemas.filePath, 'params'),
    validateRequest(fileSchemas.moveFile),
    clearCache((req) => [
        `file:metadata:${Buffer.from(req.params.filePath).toString('base64')}:latest`,
        `file:content:${Buffer.from(req.params.filePath).toString('base64')}:latest`,
        `user:files:${req.user.id}:all`,
        `directory:tree:${req.user.id}`,
        `directory:contents:${req.user.id}:${req.params.filePath}`,
        `directory:contents:${req.user.id}:${req.body.newPath}`
    ]),
    fileController.moveFileOrDirectory
);

/**
 * @route   POST /api/v1/files/:filePath/copy
 * @desc    Copy directory tree to new location
 * @access  Private (requires read permission on source)
 */
router.post('/:filePath/copy',
    validateRequest(fileParamSchemas.filePath, 'params'),
    validateRequest(fileSchemas.copyFile),
    clearCache((req) => [
        `user:files:${req.user.id}:all`,
        `directory:tree:${req.user.id}`
    ]),
    fileController.copyDirectoryTree
);

/**
 * @route   GET /api/v1/files/:filePath/content
 * @desc    Get file content (latest version or specific version)
 * @access  Private (requires authentication)
 */
router.get('/:filePath/content',
    validateRequest(fileParamSchemas.filePath, 'params'),
    validateRequest(fileSchemas.getFileContent, 'query'),
    cacheResponse(600, (req) => {
        if (req.query.includeAutosave === 'true') {
            return null; // Don't cache autosave requests
        }
        return `file:content:${Buffer.from(req.params.filePath).toString('base64')}:${req.query.version || 'latest'}`;
    }), // Cache for 10 minutes (except autosave)
    fileController.getFileContent
);

/**
 * @route   PUT /api/v1/files/:filePath/autosave
 * @desc    Auto-save file content to Redis cache
 * @access  Private (requires write permission or higher)
 */
router.put('/:filePath/autosave',
    validateRequest(fileParamSchemas.filePath, 'params'),
    validateRequest(fileSchemas.autoSave),
    // No caching middleware - autosave is temporary
    fileController.autoSaveFile
);

/**
 * @route   POST /api/v1/files/:filePath/save
 * @desc    Save file content as new version
 * @access  Private (requires write permission or higher)
 */
router.post('/:filePath/save',
    validateRequest(fileParamSchemas.filePath, 'params'),
    validateRequest(fileSchemas.saveFile),
    clearCache((req) => [
        `file:metadata:${Buffer.from(req.params.filePath).toString('base64')}:latest`,
        `file:content:${Buffer.from(req.params.filePath).toString('base64')}:latest`,
        `file:versions:${Buffer.from(req.params.filePath).toString('base64')}`,
        `user:files:${req.user.id}:all`
    ]),
    autoInvalidateCache('file'),
    fileController.saveFileVersion
);

/**
 * @route   POST /api/v1/files/:filePath/publish
 * @desc    Publish current content as new version
 * @access  Private (requires write permission or higher)
 */
router.post('/:filePath/publish',
    validateRequest(fileParamSchemas.filePath, 'params'),
    validateRequest(fileSchemas.publishFile),
    clearCache((req) => [
        `file:metadata:${Buffer.from(req.params.filePath).toString('base64')}:latest`,
        `file:content:${Buffer.from(req.params.filePath).toString('base64')}:latest`,
        `file:versions:${Buffer.from(req.params.filePath).toString('base64')}`,
        `user:files:${req.user.id}:all`
    ]),
    autoInvalidateCache('file'),
    fileController.publishFileVersion
);

/**
 * @route   GET /api/v1/files/:filePath/versions
 * @desc    Get all versions of a file
 * @access  Private (requires authentication)
 */
router.get('/:filePath/versions',
    validateRequest(fileParamSchemas.filePath, 'params'),
    cacheResponse(300, (req) => `file:versions:${Buffer.from(req.params.filePath).toString('base64')}`), // Cache for 5 minutes
    fileController.getFileVersions
);

/**
 * @route   DELETE /api/v1/files/:filePath/versions/:versionNumber
 * @desc    Delete a specific version of a file
 * @access  Private (requires write permission)
 */
router.delete('/:filePath/versions/:versionNumber',
    validateRequest(fileParamSchemas.filePathWithVersion, 'params'),
    clearCache((req) => [
        `file:versions:${Buffer.from(req.params.filePath).toString('base64')}`,
        `file:version:content:${Buffer.from(req.params.filePath).toString('base64')}:${req.params.versionNumber}`,
        `file:metadata:${Buffer.from(req.params.filePath).toString('base64')}:latest`
    ]),
    fileController.deleteVersion
);

/**
 * @route   GET /api/v1/files/:filePath/download
 * @desc    Download file with proper headers and MIME type
 * @access  Private (requires authentication)
 */
router.get('/:filePath/download',
    fileController.downloadFile
);

/**
 * @route   GET /api/v1/files/:filePath/mime-info
 * @desc    Get file MIME type information
 * @access  Private (requires authentication)
 */
router.get('/:filePath/mime-info',
    cacheResponse(1800, (req) => `file:mime:info:${Buffer.from(req.params.filePath).toString('base64')}`), // Cache for 30 minutes
    fileController.getFileMimeInfo
);

/**
 * @route   POST /api/v1/files/:filePath/share
 * @desc    Share file with users (add users to read/write permissions)
 * @access  Private (file owners only)
 */
router.post('/:filePath/share',
    validateRequest(fileParamSchemas.filePath, 'params'),
    validateRequest(fileSchemas.shareFile),
    clearCache((req) => [
        `file:metadata:${Buffer.from(req.params.filePath).toString('base64')}:latest`,
        `user:files:${req.user.id}:all`
    ]),
    fileController.shareFile
);

/**
 * @route   GET /api/v1/files/:filePath/collaborators
 * @desc    Get active collaborators for a file
 * @access  Private (requires read permission on the specific file)
 */
router.get('/:filePath/collaborators',
    validateRequest(fileParamSchemas.filePath, 'params'),
    fileController.getActiveCollaborators
);

/**
 * @route   POST /api/v1/files/:fileId/sync
 * @desc    Sync collaborative document to file system
 * @access  Private (requires write permission on the specific file)
 */
router.post('/:fileId/sync',
    validateRequest(fileParamSchemas.fileId, 'params'),
    fileController.syncCollaborativeDocument
);

/**
 * @route   GET /api/v1/files/:filePath/share
 * @desc    Get file sharing information
 * @access  Private (file owners only)
 */
router.get('/:filePath/share',
    validateRequest(fileParamSchemas.filePath, 'params'),
    cacheResponse(300, (req) => `file:sharing:${Buffer.from(req.params.filePath).toString('base64')}:${req.user.id}`), // Cache for 5 minutes
    fileController.getFileSharing
);

/**
 * @route   DELETE /api/v1/files/:filePath/share
 * @desc    Remove users from file permissions
 * @access  Private (file owners only)
 */
router.delete('/:filePath/share',
    validateRequest(fileParamSchemas.filePath, 'params'),
    validateRequest(fileSchemas.unshareFile),
    clearCache((req) => [
        `file:metadata:${Buffer.from(req.params.filePath).toString('base64')}:latest`,
        `file:sharing:${Buffer.from(req.params.filePath).toString('base64')}:${req.user.id}`,
        `user:files:${req.user.id}:all`
    ]),
    fileController.unshareFile
);

/**
 * @route   GET /api/v1/files/autosave/status
 * @desc    Get auto-save persistence service status (Admin only)
 * @access  Private (Admin only)
 */
router.get('/autosave/status',
    authMiddleware.checkPermission(RIGHTS.MANAGE_ALL_CONTENT),
    fileController.getAutosavePersistenceStatus
);

/**
 * @route   POST /api/v1/files/upload
 * @desc    Upload a single file with automatic storage handling and compression
 * @access  Private (requires authentication)
 */
router.post('/upload',
    authMiddleware.verifyToken(),
    require('../middleware/file.middleware').uploadSingle('file'),
    require('../middleware/file.middleware').processUploadedFiles,
    autoInvalidateCache([
        'file:system:stats',
        'file:storage:stats',
        'directory:contents'
    ]),
    fileController.uploadFile
);

/**
 * @route   POST /api/v1/files/upload-multiple
 * @desc    Upload multiple files with automatic storage handling and compression
 * @access  Private (requires authentication)
 */
router.post('/upload-multiple',
    authMiddleware.verifyToken(),
    require('../middleware/file.middleware').uploadMultiple('files', 20),
    require('../middleware/file.middleware').processUploadedFiles,
    autoInvalidateCache([
        'file:system:stats',
        'file:storage:stats',
        'directory:contents'
    ]),
    fileController.uploadMultipleFiles
);

// Add file handling error middleware (includes upload error handling)
router.use(require('../middleware/file.middleware').handleFileErrors);

module.exports = router;
