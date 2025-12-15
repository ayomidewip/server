import {Router} from 'express';
import fileController from '../controllers/file.controller.js';
import * as authMiddleware from '../middleware/auth.middleware.js';
import {validateRequest} from '../middleware/validation.middleware.js';
import {fileSchemas, fileParamSchemas} from '../models/schemas.js';
import {cacheResponse, clearCache, autoInvalidateCache} from '../middleware/cache.middleware.js';
import {RIGHTS} from '../config/rights.js';
import {upload, handleFileErrors} from '../middleware/file.middleware.js';

const router = Router();

// Define file routes for validation (HTTP operations for content, metadata, versions, etc.)
router.validRoutes = [
    '/api/v1/files',                          // List files (HTTP - pagination/filtering)
    '/api/v1/files/health',                   // System health (HTTP - admin only)
    '/api/v1/files/types',                    // Supported types (HTTP - public)
    '/api/v1/files/stats',                    // File statistics with compression data (HTTP - admin only)
    '/api/v1/files/admin/stats',              // Admin stats alias (HTTP - admin only)
    '/api/v1/files/demo',                     // Demo files (HTTP - public)
    '/api/v1/files/bulk',                     // Bulk operations (HTTP - complex operations)
    '/api/v1/files/tree',                     // Directory tree (HTTP - complex structure)
    '/api/v1/files/upload',                   // File uploads (HTTP - multipart required)
    '/api/v1/files/directory/contents',       // Directory contents (HTTP - listing)
    '/api/v1/files/directory/stats',          // Directory stats (HTTP - aggregation)
    '/api/v1/files/directory',                // Directory creation
    '/api/v1/files/move',                     // Move operations
    '/api/v1/files/copy',                     // Copy operations
    '/api/v1/files/:filePath/content',        // File content retrieval and save
    '/api/v1/files/:filePath/metadata',       // File metadata retrieval
    '/api/v1/files/:filePath/publish',        // Publish versions
    '/api/v1/files/:filePath/versions',       // Version listing
    '/api/v1/files/:filePath/versions/:versionNumber', // Version load/delete
    '/api/v1/files/:filePath/rename',         // Rename files or directories
    '/api/v1/files/:filePath',                // File deletion
    '/api/v1/files/:filePath/download',       // File downloads (HTTP - streaming required)
    '/api/v1/files/:filePath/collaborators',  // Active collaborators (HTTP - session info)
    '/api/v1/files/:filePath/share',          // File sharing (HTTP - permission management)
];

// Health check endpoint (admin only)
router.get('/health', 
    authMiddleware.verifyToken(),
    authMiddleware.checkPermission(RIGHTS.MANAGE_ALL_CONTENT),
    fileController.getFileSystemHealth
);

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
    cacheResponse(60, (req) => {
        const userRoles = req.user?.roles || [];
        const isAdmin = userRoles.includes('ADMIN') || userRoles.includes('OWNER') || userRoles.includes('SUPER_ADMIN');
        return `file:stats:${isAdmin ? 'admin' : `user:${req.user.id}`}`;
    }), // Cache for 1 minute with user-specific key
    fileController.getFileStats
);

/**
 * @route   GET /api/v1/files/admin/stats
 * @desc    Alias for /stats endpoint for backward compatibility
 * @access  Private (Admin/Owner only)
 */
router.get('/admin/stats',
    authMiddleware.verifyToken(),
    cacheResponse(60, (req) => {
        const userRoles = req.user?.roles || [];
        const isAdmin = userRoles.includes('ADMIN') || userRoles.includes('OWNER') || userRoles.includes('SUPER_ADMIN');
        return `file:stats:${isAdmin ? 'admin' : `user:${req.user.id}`}`;
    }), // Cache for 1 minute with user-specific key
    fileController.getFileStats
);

// Public route: Get demo files (read-only, no authentication required)
router.get('/demo', fileController.getDemoFiles);

/**
 * @route   POST /api/v1/files/upload
 * @desc    Upload single or multiple files with simplified storage handling
 * @access  Private (requires authentication)
 */
router.post('/upload',
    authMiddleware.verifyToken(), // Explicit auth middleware before multer
    upload.any(20),
    autoInvalidateCache('file'),
    fileController.uploadFile
);

// Protect all other file routes
router.use(authMiddleware.verifyToken());

/**
 * @route   POST /api/v1/files/bulk
 * @desc    Perform bulk operations on multiple files/directories
 * @access  Private (requires authentication - permissions checked per file)
 */
router.post('/bulk',
    validateRequest(fileSchemas.bulkOperations),
    clearCache((req) => [
        `user:files:${req.user.id}:all`,
        `directory:tree:${req.user.id}`
    ]),
    autoInvalidateCache('file'),
    fileController.bulkOperations
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
    }),
    fileController.getDirectoryTree
);

/**
 * @route   GET /api/v1/files/directory/contents
 * @desc    Get directory contents (immediate children only)
 * @access  Private (requires authentication)
 */
router.get('/directory/contents',
    validateRequest(fileParamSchemas.filePath, 'query'),
    validateRequest(fileSchemas.getDirectoryContents, 'query'),
    cacheResponse(60, (req) => {
        const params = req.query ? new URLSearchParams(req.query).toString() : '';
        return `directory:contents:${req.user.id}:${req.query.filePath}${params ? `?${params}` : ''}`;
    }),
    fileController.getDirectoryContents
);

/**
 * @route   GET /api/v1/files/directory/stats
 * @desc    Get directory statistics (recursive size and file counts)
 * @access  Private (requires authentication)
 */
router.get('/directory/stats',
    validateRequest(fileParamSchemas.filePath, 'query'),
    cacheResponse(300, (req) => {
        return `directory:stats:${req.user.id}:${req.query.filePath}`;
    }),
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
        return `user:files:${req.user.id}:${params ? encodeURIComponent(params) : 'all'}`;
    }), // Cache for 5 minutes
    fileController.getFiles
);



// PUT /files/:filePath removed - use WebSocket 'getMetadata' + 'save' operations instead

// PATCH route removed - isPermanent functionality was non-functional and has been removed







// GET /files/:filePath/versions removed - use WebSocket 'getVersions' operation instead

/**
 * @route   GET /api/v1/files/:filePath/download
 * @desc    Download a file by file path
 * @access  Private (requires authentication)
 */
router.get('/:filePath/download',
    validateRequest(fileParamSchemas.filePath, 'params'),
    fileController.downloadFile
);

/**
 * @route   GET /api/v1/files/:filePath/cover
 * @desc    Get cover art for audio file
 * @access  Private (requires authentication)
 */
router.get('/:filePath/cover',
    validateRequest(fileParamSchemas.filePath, 'params'),
    fileController.getMediaImage
);

/**
 * @route   GET /api/v1/files/:filePath/thumbnail
 * @desc    Get thumbnail for video file
 * @access  Private (requires authentication)
 */
router.get('/:filePath/thumbnail',
    validateRequest(fileParamSchemas.filePath, 'params'),
    fileController.getMediaImage
);

// GET /files/:filePath/mime-info removed - use WebSocket 'getMetadata' operation instead

/**
 * @route   POST /api/v1/files/:filePath/share
 * @desc    Share file with users (add users to read/write permissions)
 * @access  Private (file owners only)
 */
router.post('/:filePath/share',
    authMiddleware.verifyToken(),
    validateRequest(fileParamSchemas.filePath, 'params'),
    validateRequest(fileSchemas.shareFile),
    clearCache((req) => [
        `file:metadata:${encodeURIComponent(req.params.filePath)}:latest`,
        `file:sharing:${encodeURIComponent(req.params.filePath)}:${req.user.id}`,
        `user:files:${req.user.id}:all`
    ]),
    fileController.shareFile
);

router.post('/',
    validateRequest(fileSchemas.createFile),
    autoInvalidateCache('file', (req) => req.body.filePath, (req) => req.user.id),
    fileController.createFile
);

router.post('/directory',
    validateRequest(fileSchemas.createDirectory),
    autoInvalidateCache('file', (req) => req.body.dirPath, (req) => req.user.id),
    fileController.createDirectory
);

router.post('/move',
    validateRequest(fileSchemas.moveFile),
    autoInvalidateCache('file', (req) => req.body.sourcePath, (req) => req.user.id),
    fileController.moveFile
);

router.post('/copy',
    validateRequest(fileSchemas.copyFile),
    autoInvalidateCache('file', (req) => req.body.destinationPath, (req) => req.user.id),
    fileController.copyFile
);

router.get('/:filePath/metadata',
    validateRequest(fileParamSchemas.filePath, 'params'),
    fileController.getFileMetadata
);

router.get('/:filePath/content',
    validateRequest(fileParamSchemas.filePath, 'params'),
    fileController.getFileContent
);

router.put('/:filePath/content',
    validateRequest(fileParamSchemas.filePath, 'params'),
    validateRequest(fileSchemas.saveFile),
    autoInvalidateCache('file', (req) => req.params.filePath, (req) => req.user.id),
    fileController.saveFileContent
);

router.post('/:filePath/publish',
    validateRequest(fileParamSchemas.filePath, 'params'),
    validateRequest(fileSchemas.publishFile),
    autoInvalidateCache('file', (req) => req.params.filePath, (req) => req.user.id),
    fileController.publishFileVersion
);

router.get('/:filePath/versions/:versionNumber',
    validateRequest(fileParamSchemas.filePathWithVersion, 'params'),
    fileController.loadFileVersion
);

router.get('/:filePath/versions/:versionNumber/download',
    validateRequest(fileParamSchemas.filePathWithVersion, 'params'),
    fileController.downloadFileVersion
);

router.delete('/:filePath/versions/:versionNumber',
    validateRequest(fileParamSchemas.filePathWithVersion, 'params'),
    autoInvalidateCache('file', (req) => req.params.filePath, (req) => req.user.id),
    fileController.deleteFileVersion
);

router.get('/:filePath/versions',
    validateRequest(fileParamSchemas.filePath, 'params'),
    fileController.getFileVersions
);

router.post('/:filePath/rename',
    validateRequest(fileParamSchemas.filePath, 'params'),
    validateRequest(fileSchemas.renameFile),
    autoInvalidateCache('file', (req) => req.params.filePath, (req) => req.user.id),
    fileController.renameFile
);

/**
 * @route   GET /api/v1/files/:filePath/share
 * @desc    Get file sharing information
 * @access  Private (file owners only)
 */
router.get('/:filePath/share',
    authMiddleware.verifyToken(),
    validateRequest(fileParamSchemas.filePath, 'params'),
    cacheResponse(300, (req) => `file:sharing:${encodeURIComponent(req.params.filePath)}:${req.user.id}`), // Cache for 5 minutes
    fileController.getFileSharing
);

/**
 * @route   DELETE /api/v1/files/:filePath/share
 * @desc    Remove users from file permissions
 * @access  Private (file owners only)
 */
router.delete('/:filePath/share',
    authMiddleware.verifyToken(),
    validateRequest(fileParamSchemas.filePath, 'params'),
    validateRequest(fileSchemas.unshareFile),
    clearCache((req) => [
        `file:metadata:${encodeURIComponent(req.params.filePath)}:latest`,
        `file:sharing:${encodeURIComponent(req.params.filePath)}:${req.user.id}`,
        `user:files:${req.user.id}:all`
    ]),
    autoInvalidateCache('file', (req) => req.params.filePath, (req) => req.user.id),
    fileController.unshareFile
);

/**
 * @route   DELETE /api/v1/files/:filePath
 * @desc    Delete a file or directory
 * @access  Private (requires write permission on the resource)
 */
router.delete('/:filePath',
    authMiddleware.verifyToken(),
    validateRequest(fileParamSchemas.filePath, 'params'),
    fileController.deleteFile
);

// Add file handling error middleware (includes upload error handling)
router.use(handleFileErrors);

export default router;
