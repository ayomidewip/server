const mongoose = require('mongoose');
const mime = require('mime-types');
const {storeInGridFS, retrieveFromGridFS, deleteFromGridFS} = require('../config/db');

/**
 * Helper function to initialize transaction cleanup arrays
 * @param {Object} session - MongoDB session object
 */
const initializeTransactionCleanup = (session) => {
    if (session) {
        session.transaction = session.transaction || {};
        session.transaction.gridfsCleanup = session.transaction.gridfsCleanup || [];
    }
};

/**
 * Simplified File Schema for MongoDB storage
 * Single document per file with embedded version history
 */
const fileSchema = new mongoose.Schema({
    // Filesystem path (Unix-style absolute path) - UNIQUE per owner
    filePath: {
        type: String,
        required: true,
        validate: {
            validator: function (v) {
                // Validate path syntax: must start with /, no null chars, no double slashes
                return /^\/[^\0]*$/.test(v) && !v.includes('//') && (v === '/' || !v.endsWith('/'));
            },
            message: 'Invalid file path format. Must be absolute Unix-style path.'
        }
    },

    // Parent directory path (for efficient tree queries)
    parentPath: {
        type: String,
        index: true,
        default: function () {
            if (this.filePath === '/') return null;
            const lastSlash = this.filePath.lastIndexOf('/');
            return lastSlash === 0 ? '/' : this.filePath.substring(0, lastSlash);
        }
    },

    // File system type: file or directory
    type: {
        type: String,
        enum: ['file', 'directory'],
        default: 'file',
        required: true,
        index: true
    },

    // Depth level in filesystem hierarchy
    depth: {
        type: Number,
        index: true,
        default: function () {
            return this.filePath === '/' ? 0 : this.filePath.split('/').length - 1;
        }
    },

    // File name with extension (extracted from path)
    fileName: {
        type: String,
        required: function () {
            return this.type === 'file';
        },
        trim: true,
        default: function () {
            if (this.type === 'directory') return null;
            const parts = this.filePath.split('/');
            return parts[parts.length - 1];
        }
    },

    // File type/extension
    fileType: {
        type: String, required: true, lowercase: true, trim: true
    },

    // MIME type
    mimeType: {
        type: String, required: true
    },

    // Storage type - determines how file content is stored
    storageType: {
        type: String,
        enum: ['inline', 'gridfs'],
        default: 'inline',
        required: true
    },

    // Current file content (for inline storage)
    content: {
        type: String,
        default: "",
        required: false,
        validate: {
            validator: function (v) {
                return this.storageType !== 'inline' || typeof v === 'string';
            },
            message: 'Content must be a string for inline storage'
        }
    },

    // Note: GridFS files are identified by filePath, no separate gridfsFileId needed


    // Current version number (atomic increment)
    version: {
        type: Number,
        required: true,
        default: 1,
        min: 1
    },

    // File size in bytes (automatically calculated)
    size: {
        type: Number,
        min: [0, 'File size cannot be negative'],
        default: 0
    },

    // User who created/owns the file
    owner: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
        index: true
    },

    // File tags for organization
    tags: [{
        type: String,
        trim: true,
        maxlength: 50
    }],

    // File description
    description: {
        type: String,
        trim: true,
        maxlength: 500
    },

    // Last modified by (for tracking changes)
    lastModifiedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        default: function () {
            return this.owner;
        }
    },

    // Simple access permissions
    permissions: {
        read: [{
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User'
        }],
        write: [{
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User'
        }]
    },

    // Compression metadata
    compression: {
        isCompressed: {type: Boolean, default: false},
        algorithm: {
            type: String,
            enum: ['none', 'gzip', 'deflate', 'brotli'],
            default: 'none'
        },
        originalSize: {type: Number, default: 0},
        compressionRatio: {type: Number, default: 1, min: 0, max: 1},
        contentEncoding: {type: String, default: null}
    },

    // File metadata
    metadata: {
        encoding: {type: String, default: 'utf-8'},
        language: String,
        lineCount: {type: Number, default: 0},
        charCount: {type: Number, default: 0}
    },

    // Version history with actual content storage
    versionHistory: [{
        version: Number,
        timestamp: {type: Date, default: Date.now},
        modifiedBy: {type: mongoose.Schema.Types.ObjectId, ref: 'User'},
        message: {type: String, maxlength: 200},
        size: Number,

        // Store the actual content for each version
        content: {
            type: String,
            default: ""
        },

        // Storage information for this version
        storageType: {
            type: String,
            enum: ['inline', 'gridfs'],
            default: 'inline'
        },

        // GridFS file ID for this version (if using GridFS)
        gridfsFileId: {
            type: String,
            required: false
        },

        // File metadata for this version
        metadata: {
            encoding: {type: String, default: 'utf-8'},
            language: String,
            lineCount: {type: Number, default: 0},
            charCount: {type: Number, default: 0}
        },

        // Compression metadata for this version
        compression: {
            isCompressed: {type: Boolean, default: false},
            algorithm: {
                type: String,
                enum: ['none', 'gzip', 'deflate', 'brotli'],
                default: 'none'
            },
            originalSize: {type: Number, default: 0},
            compressionRatio: {type: Number, default: 1, min: 0, max: 1},
            contentEncoding: {type: String, default: null}
        },

        _id: false // Disable _id for subdocuments
    }]
}, {
    timestamps: true,
    toJSON: {virtuals: true},
    toObject: {virtuals: true}
});

// CRITICAL: Unique compound index - one file per path per owner
fileSchema.index({filePath: 1, owner: 1}, {unique: true});

// Performance indexes
fileSchema.index({owner: 1, createdAt: -1});
fileSchema.index({parentPath: 1, owner: 1});
fileSchema.index({type: 1, owner: 1});
fileSchema.index({depth: 1, owner: 1});

// Text search index
fileSchema.index({fileName: 'text', filePath: 'text'});

// Virtual for file identifier
fileSchema.virtual('fullIdentifier').get(function () {
    return `${this.filePath}_v${this.version}`;
});

// Virtual for Redis cache key
fileSchema.virtual('cacheKey').get(function () {
    return `file:cache:${Buffer.from(this.filePath).toString('base64')}`;
});

// Virtual for Redis autosave key
fileSchema.virtual('autosaveKey').get(function () {
    return `file:autosave:${Buffer.from(this.filePath).toString('base64')}`;
});

// Virtual for directory name (last part of path for directories)
fileSchema.virtual('directoryName').get(function () {
    if (this.type !== 'directory') return null;
    if (this.filePath === '/') return 'root';
    const parts = this.filePath.split('/');
    return parts[parts.length - 1];
});

// Virtual for file extension
fileSchema.virtual('fileExtension').get(function () {
    if (this.type === 'directory' || !this.fileName) return null;
    const lastDot = this.fileName.lastIndexOf('.');
    return lastDot === -1 ? null : this.fileName.substring(lastDot + 1).toLowerCase();
});

// Virtual for parent directory name
fileSchema.virtual('parentDirectoryName').get(function () {
    if (!this.parentPath || this.parentPath === '/') return 'root';
    const parts = this.parentPath.split('/');
    return parts[parts.length - 1];
});

// Virtual for full filesystem path with proper separators
fileSchema.virtual('displayPath').get(function () {
    return this.filePath;
});

// Simplified pre-save middleware
fileSchema.pre('save', function (next) {
    // Validate filesystem path
    if (!this.constructor.validatePath(this.filePath)) {
        return next(new Error('Invalid file path format'));
    }

    // Auto-set parentPath if not provided
    if (!this.parentPath && this.filePath !== '/') {
        const lastSlash = this.filePath.lastIndexOf('/');
        this.parentPath = lastSlash === 0 ? '/' : this.filePath.substring(0, lastSlash);
    }

    // Auto-set depth if not provided
    if (this.depth === undefined) {
        this.depth = this.filePath === '/' ? 0 : this.filePath.split('/').length - 1;
    }

    // Auto-set fileName for files if not provided
    if (this.type === 'file' && !this.fileName && this.filePath !== '/') {
        const parts = this.filePath.split('/');
        this.fileName = parts[parts.length - 1];
    }

    // Auto-detect file type and MIME type for files
    if (this.type === 'file' && this.fileName) {
        if (!this.fileType || !this.mimeType) {
            const detectedType = this.constructor.detectFileType(this.fileName);
            if (!this.fileType) this.fileType = detectedType.extension;
            if (!this.mimeType) this.mimeType = detectedType.mimeType;
        }

        // Determine storage type based on content size and type
        if (this.content !== undefined && (this.storageType === 'inline' || !this.storageType)) {
            const contentSize = Buffer.byteLength(this.content, 'utf8');
            this.storageType = this.constructor.determineStorageType(this.fileName, contentSize, this.mimeType);
        } else if (!this.storageType) {
            this.storageType = 'inline'; // Default fallback
        }
    } else if (this.type === 'directory') {
        this.mimeType = 'inode/directory';
        this.fileType = 'directory';
        this.fileName = null;
        this.storageType = 'inline';
    }

    // Calculate size based on storage type
    if (this.storageType === 'inline' && this.content !== undefined) {
        this.size = Buffer.byteLength(this.content, 'utf8');

        // Update metadata only if content is not compressed
        // For compressed content, metadata should be calculated from original content in setContent method
        if (!this.compression || !this.compression.isCompressed) {
            this.metadata.charCount = this.content.length;
            this.metadata.lineCount = this.content.split('\n').length;
        }
    }

    next();
});

// Simplified post-save middleware
fileSchema.post('save', function (doc, next) {
    // Add version to history if this is a content update (but not needed anymore with new publish system)
    if (doc.isModified('content') && doc.version > 0) {
        // Keep only last 10 version history entries to prevent memory bloat
        if (doc.versionHistory.length >= 10) {
            doc.versionHistory = doc.versionHistory.slice(-9);
        }

        doc.versionHistory.push({
            version: doc.version,
            timestamp: new Date(),
            modifiedBy: doc.lastModifiedBy,
            size: doc.size,
            message: 'File updated'
        });

        // Save without triggering middleware again
        doc.save({validateBeforeSave: false}).catch(err => {
            const logger = require('../utils/app.logger');
            logger.warn('Failed to update version history:', {
                fileId: doc._id,
                filePath: doc.filePath,
                error: err.message
            });
        });
    }
    next();
});

// Pre-remove middleware to clean up GridFS files
fileSchema.pre(['deleteOne', 'findOneAndDelete', 'remove'], async function () {
    try {
        // Get the document that's being deleted
        const doc = this.getQuery ? await this.model.findOne(this.getQuery()) : this;

        if (doc && doc.storageType === 'gridfs') {
            // Try to get session from options if available
            const session = this.getOptions()?.session;
            await doc.deleteContent(session);
        }
    } catch (error) {
        // Log but don't prevent deletion
        const logger = require('../utils/app.logger');
        logger.warn('Failed to clean up GridFS content during deletion:', {
            error: error.message
        });
    }
});

// Instance method for transactional deletion
fileSchema.methods.deleteWithTransaction = async function () {
    const session = await this.constructor.startSession();

    try {
        return await session.withTransaction(async () => {
            // Initialize transaction state for GridFS cleanup tracking
            initializeTransactionCleanup(session);

            // Clean up GridFS content first
            if (this.storageType === 'gridfs') {
                await this.deleteContent(session);
            }

            // Then delete the document
            await this.deleteOne({session});

            return {success: true, message: 'File deleted successfully'};
        });
    } catch (error) {
        const logger = require('../utils/app.logger');
        logger.error(`Error deleting file ${this.filePath}:`, error);
        throw error;
    } finally {
        await session.endSession();
    }
};

// Instance method to get version history
fileSchema.methods.getVersionHistory = function () {
    return this.versionHistory.sort((a, b) => b.version - a.version);
};

// Instance method to get content for a specific version
fileSchema.methods.getVersionContent = async function (versionNumber) {
    // If requesting current version, return current content
    if (versionNumber === this.version || versionNumber === 'latest') {
        return await this.getContent();
    }

    // Find the version in history
    const versionEntry = this.versionHistory.find(v => v.version === versionNumber);

    if (!versionEntry) {
        throw new Error(`Version ${versionNumber} not found`);
    }

    // Return the stored content for this version
    return versionEntry.content || '';
};

// Instance method to get all available version numbers
fileSchema.methods.getAvailableVersions = function () {
    const versions = this.versionHistory.map(v => v.version);
    versions.push(this.version); // Add current version
    return versions.sort((a, b) => b - a); // Sort descending (newest first)
};

// Instance method to delete a specific version
fileSchema.methods.deleteVersion = async function (versionNumber, deletedBy) {
    // Validate input
    if (!versionNumber || typeof versionNumber !== 'number') {
        throw new Error('Version number is required and must be a number');
    }

    // Cannot delete the current version
    if (versionNumber === this.version) {
        throw new Error('Cannot delete the current version of the file');
    }

    // Find the version in history
    const versionIndex = this.versionHistory.findIndex(v => v.version === versionNumber);

    if (versionIndex === -1) {
        throw new Error(`Version ${versionNumber} not found`);
    }

    const versionToDelete = this.versionHistory[versionIndex];

    // If version uses GridFS storage, clean up the GridFS file
    if (versionToDelete.storageType === 'gridfs' && versionToDelete.gridfsFileId) {
        try {
            const GridFSBucket = require('mongodb').GridFSBucket;
            const db = this.constructor.db;
            const bucket = new GridFSBucket(db);

            // Check if GridFS file exists before attempting deletion
            const files = await bucket.find({_id: new require('mongodb').ObjectId(versionToDelete.gridfsFileId)}).toArray();
            if (files.length > 0) {
                await bucket.delete(new require('mongodb').ObjectId(versionToDelete.gridfsFileId));
            }
        } catch (error) {
            const logger = require('../utils/app.logger');
            logger.warn(`Failed to delete GridFS file for version ${versionNumber}:`, {
                fileId: this._id,
                filePath: this.filePath,
                gridfsFileId: versionToDelete.gridfsFileId,
                error: error.message
            });
            // Continue with version deletion even if GridFS cleanup fails
        }
    }

    // Remove the version from history
    this.versionHistory.splice(versionIndex, 1);

    // Update lastModifiedBy
    if (deletedBy) {
        this.lastModifiedBy = deletedBy;
    }

    // Save the document
    await this.save();

    const logger = require('../utils/app.logger');
    logger.info(`Version ${versionNumber} deleted from file:`, {
        fileId: this._id,
        filePath: this.filePath,
        deletedBy: deletedBy?.toString(),
        remainingVersions: this.versionHistory.length
    });

    return {
        success: true,
        message: `Version ${versionNumber} deleted successfully`,
        remainingVersions: this.getAvailableVersions()
    };
};

// Instance method to get directory contents
fileSchema.methods.getDirectoryContents = function () {
    if (this.type !== 'directory') {
        throw new Error('Can only get contents of directories');
    }
    return this.constructor.find({
        parentPath: this.filePath,
        owner: this.owner
    }).sort({type: -1, fileName: 1}); // Directories first, then files alphabetically
};

// Instance method to get all children (recursive)
fileSchema.methods.getAllChildren = function () {
    if (this.type !== 'directory') {
        throw new Error('Can only get children of directories');
    }
    return this.constructor.find({
        filePath: new RegExp(`^${this.filePath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}/`),
        owner: this.owner
    }).sort({depth: 1, filePath: 1});
};

// Instance method to check if path exists in user's filesystem
fileSchema.methods.pathExists = function (targetPath) {
    return this.constructor.exists({
        filePath: targetPath,
        owner: this.owner
    });
};

// Instance method to check if user has read permission
fileSchema.methods.hasReadPermission = function (userId) {
    // Convert userId to string for comparison if it's an ObjectId
    const userIdStr = userId.toString();
    const ownerStr = this.owner.toString();

    // Owner always has read permission
    if (userIdStr === ownerStr) {
        return true;
    }

    // Check if user is in read permissions array
    return this.permissions.read.some(readUserId => readUserId.toString() === userIdStr);
};

// Instance method to check if user has write permission
fileSchema.methods.hasWritePermission = function (userId) {
    // Convert userId to string for comparison if it's an ObjectId
    const userIdStr = userId.toString();
    const ownerStr = this.owner.toString();

    // Owner always has write permission
    if (userIdStr === ownerStr) {
        return true;
    }

    // Check if user is in write permissions array
    return this.permissions.write.some(writeUserId => writeUserId.toString() === userIdStr);
};

// Instance method to check if user can manage file (admin/owner privileges)
fileSchema.methods.hasManagePermission = function (userId, userRoles = []) {
    // Convert userId to string for comparison if it's an ObjectId
    const userIdStr = userId.toString();
    const ownerStr = this.owner.toString();

    // File owner always has manage permission
    if (userIdStr === ownerStr) {
        return true;
    }

    // Check if user has admin/owner roles (global management permissions)
    const adminRoles = ['OWNER', 'ADMIN'];
    const hasAdminRole = Array.isArray(userRoles) ?
        userRoles.some(role => adminRoles.includes(role)) :
        adminRoles.includes(userRoles);

    if (hasAdminRole) {
        return true;
    }

    // Check if user is in write permissions array
    return this.permissions.write.some(writeUserId => writeUserId.toString() === userIdStr);
};

// Instance method to share file with users (only owners can share)
fileSchema.methods.shareWithUsers = function (userIds, permission = 'read', currentUserId) {
    // Note: Permission checking is now handled in controller layer for consistency
    // This method is now a pure model operation

    const userIdObjects = Array.isArray(userIds) ? userIds : [userIds];

    // Validate permission type
    if (!['read', 'write'].includes(permission)) {
        throw new Error('Permission must be either "read" or "write"');
    }

    // Add users to the appropriate permission array
    userIdObjects.forEach(userId => {
        const userIdStr = userId.toString();

        // Don't add owner to permissions (owner already has all permissions)
        if (userIdStr === this.owner.toString()) {
            return;
        }

        if (permission === 'read') {
            // Add to read permissions if not already present
            const alreadyHasRead = this.permissions.read.some(
                readUserId => readUserId.toString() === userIdStr
            );
            if (!alreadyHasRead) {
                this.permissions.read.push(userId);
            }
        } else if (permission === 'write') {
            // Add to write permissions if not already present
            const alreadyHasWrite = this.permissions.write.some(
                writeUserId => writeUserId.toString() === userIdStr
            );
            if (!alreadyHasWrite) {
                this.permissions.write.push(userId);
            }

            // Write permission includes read permission, so add to read as well
            const alreadyHasRead = this.permissions.read.some(
                readUserId => readUserId.toString() === userIdStr
            );
            if (!alreadyHasRead) {
                this.permissions.read.push(userId);
            }
        }
    });

    return this;
};

// Instance method to remove users from file permissions (only owners can remove)
fileSchema.methods.removeUsersFromPermissions = function (userIds, permission = 'read', currentUserId) {
    // Note: Permission checking is now handled in controller layer for consistency
    // This method is now a pure model operation

    const userIdObjects = Array.isArray(userIds) ? userIds : [userIds];

    // Validate permission type
    if (!['read', 'write', 'both'].includes(permission)) {
        throw new Error('Permission must be either "read", "write", or "both"');
    }

    userIdObjects.forEach(userId => {
        const userIdStr = userId.toString();

        if (permission === 'read' || permission === 'both') {
            // Remove from read permissions
            this.permissions.read = this.permissions.read.filter(
                readUserId => readUserId.toString() !== userIdStr
            );
        }

        if (permission === 'write' || permission === 'both') {
            // Remove from write permissions
            this.permissions.write = this.permissions.write.filter(
                writeUserId => writeUserId.toString() !== userIdStr
            );
        }
    });

    return this;
};

// Instance method to get all users with access to this file
fileSchema.methods.getSharedUsers = function () {
    const readUsers = this.permissions.read || [];
    const writeUsers = this.permissions.write || [];

    // Create a map to avoid duplicates
    const userPermissions = new Map();

    // Add read permissions
    readUsers.forEach(userId => {
        const userIdStr = userId.toString();
        userPermissions.set(userIdStr, {
            userId: userId,
            permissions: ['read']
        });
    });

    // Add write permissions (and upgrade read-only users to read+write)
    writeUsers.forEach(userId => {
        const userIdStr = userId.toString();
        if (userPermissions.has(userIdStr)) {
            userPermissions.get(userIdStr).permissions.push('write');
        } else {
            userPermissions.set(userIdStr, {
                userId: userId,
                permissions: ['write']
            });
        }
    });

    return Array.from(userPermissions.values());
};

// GridFS content management methods
fileSchema.methods.getContent = async function () {
    let rawContent;

    if (this.storageType === 'gridfs') {
        try {
            const result = await retrieveFromGridFS(this.filePath);
            rawContent = result.content;

            // GridFS returns compressed content as is - we need to update compression metadata
            // to ensure proper decompression after retrieval
            if (result.isCompressed && result.compressionAlgorithm &&
                (!this.compression || !this.compression.isCompressed)) {
                // If GridFS metadata indicates compression but our model doesn't have it updated
                this.compression = {
                    isCompressed: true,
                    algorithm: result.compressionAlgorithm,
                    originalSize: result.metadata?.originalSize || 0,
                    compressionRatio: result.metadata?.compressionRatio || 0,
                    contentEncoding: result.metadata?.contentEncoding || null
                };
                // We don't save here to avoid side effects, just update the instance
            }
        } catch (error) {
            const logger = require('../utils/app.logger');
            logger.error(`Failed to retrieve GridFS content for ${this.filePath}:`, error);
            // Fallback to inline content if GridFS fails
            if (this.content) {
                logger.warn(`Falling back to inline content for ${this.filePath}`);
                rawContent = this.content;
            } else {
                throw new Error(`Failed to retrieve content: ${error.message}`);
            }
        }
    } else {
        // Handle inline content
        rawContent = this.content || '';
    }

    // Handle decompression if content is compressed
    if ((this.compression && this.compression.isCompressed && rawContent) ||
        (rawContent && Buffer.isBuffer(rawContent) && this.mimeType && this.mimeType.startsWith('text/'))) {
        // Logging to help diagnose compression state
        const logger = require('../utils/app.logger');
        logger.debug(`Processing potentially compressed content for ${this.filePath}:`, {
            isCompressed: this.compression?.isCompressed,
            algorithm: this.compression?.algorithm,
            mimeType: this.mimeType,
            contentType: typeof rawContent,
            isBuffer: Buffer.isBuffer(rawContent),
            contentLength: Buffer.isBuffer(rawContent) ? rawContent.length :
                (typeof rawContent === 'string' ? rawContent.length : 'unknown')
        });

        try {
            const {decompressFileBuffer} = require('../middleware/file.middleware');

            let contentBuffer;
            if (Buffer.isBuffer(rawContent)) {
                contentBuffer = rawContent;
            } else if (typeof rawContent === 'string') {
                // Try to decode from base64 first (compressed content stored as base64)
                try {
                    contentBuffer = Buffer.from(rawContent, 'base64');
                } catch (decodeError) {
                    // If not base64, treat as regular string
                    contentBuffer = Buffer.from(rawContent, 'utf8');
                }
            } else {
                contentBuffer = Buffer.from(String(rawContent), 'utf8');
            }

            // Determine which algorithm to use for decompression
            const algorithm = this.compression?.algorithm || 'brotli'; // Default to brotli if unknown

            const decompressedBuffer = await decompressFileBuffer(
                contentBuffer,
                algorithm,
                this.fileName
            );

            const logger = require('../utils/app.logger');
            // Log the result of decompression for debugging
            logger.debug(`Successfully decompressed content for ${this.filePath}`, {
                originalSize: contentBuffer.length,
                decompressedSize: decompressedBuffer.length,
                algorithm: this.compression?.algorithm || 'unknown',
                ratio: contentBuffer.length / decompressedBuffer.length
            });

            // Return appropriate format based on file type
            if (this.constructor.isTextBasedFile(this.mimeType)) {
                const textContent = decompressedBuffer.toString('utf8');

                // Update metadata to reflect the actual content after decompression
                // This is important for tests that verify line counts
                if (!this.metadata) this.metadata = {};
                if (this.metadata.lineCount === 0 ||
                    (this.metadata.lineCount < 1000 && textContent.split('\n').length > this.metadata.lineCount)) {
                    this.metadata.lineCount = textContent.split('\n').length;
                    this.metadata.charCount = textContent.length;
                    logger.debug(`Updated metadata for ${this.filePath} after decompression`, {
                        lineCount: this.metadata.lineCount,
                        charCount: this.metadata.charCount
                    });
                }

                return textContent;
            } else {
                return decompressedBuffer;
            }
        } catch (decompError) {
            const logger = require('../utils/app.logger');
            logger.error(`Failed to decompress content for ${this.filePath}:`, decompError);
            // Return raw content as fallback
            return rawContent;
        }
    } else {
        // No compression - handle content format
        if (!rawContent) {
            return '';
        }

        // For binary files stored inline as base64, return as Buffer
        if (!this.constructor.isTextBasedFile(this.mimeType) && typeof rawContent === 'string') {
            try {
                return Buffer.from(rawContent, 'base64');
            } catch (error) {
                // If base64 decode fails, return as string
                return rawContent;
            }
        }

        return rawContent;
    }
};

// Add method to get content as stream (for efficient GridFS file downloads)
fileSchema.methods.getContentStream = async function () {
    if (this.storageType === 'gridfs') {
        try {
            const result = await retrieveFromGridFS(this.filePath, {asStream: true});
            return result.stream;
        } catch (error) {
            const logger = require('../utils/app.logger');
            logger.error(`Failed to retrieve GridFS stream for ${this.filePath}:`, error);
            throw new Error(`Failed to retrieve content stream: ${error.message}`);
        }
    } else {
        const logger = require('../utils/app.logger');
        logger.warn(`Attempting to get stream for inline file ${this.filePath}`);
        throw new Error('Cannot stream inline content - use getContent() instead');
    }
};

fileSchema.methods.setContent = async function (newContent, session = null, precomputedCompression = null) {
    // Step 1: Process input content
    const {contentBuffer, originalSize} = this._processContentInput(newContent);

    // Step 2: Handle compression
    const compressionResult = await this._handleCompression(contentBuffer, precomputedCompression);

    // Step 3: Update compression metadata
    this._updateCompressionMetadata(compressionResult);

    // Step 4: Determine storage strategy and execute
    const shouldUseGridFS = this.constructor.determineStorageType(this.fileName, compressionResult.compressedSize, this.mimeType) === 'gridfs';
    const rollbackData = this._captureRollbackData();

    try {
        if (shouldUseGridFS) {
            await this._storeInGridFS(compressionResult.buffer, session, rollbackData);
            this._updateMetadataForGridFS(newContent);
        } else {
            await this._storeInline(compressionResult, newContent, precomputedCompression, rollbackData);
            this._updateMetadataForInline(newContent);
        }
    } catch (error) {
        this._rollbackChanges(rollbackData);
        throw error;
    }
};

// Helper method: Process input content
fileSchema.methods._processContentInput = function (newContent) {
    if (Buffer.isBuffer(newContent)) {
        return {
            contentBuffer: newContent,
            originalSize: newContent.length
        };
    } else if (typeof newContent === 'string') {
        return {
            contentBuffer: Buffer.from(newContent, 'utf8'),
            originalSize: Buffer.byteLength(newContent, 'utf8')
        };
    } else {
        throw new Error('Content must be a string or Buffer');
    }
};

// Helper method: Handle compression logic
fileSchema.methods._handleCompression = async function (contentBuffer, precomputedCompression) {
    if (precomputedCompression) {
        // For precomputed compression from file uploads, the content passed to setContent
        // is already processed by middleware (Base64-encoded compressed data)
        return {
            compressed: precomputedCompression.isCompressed,
            algorithm: precomputedCompression.algorithm,
            originalSize: precomputedCompression.originalSize,
            compressionRatio: precomputedCompression.compressionRatio,
            compressedSize: precomputedCompression.isCompressed ?
                Buffer.from(contentBuffer).length : // Actual size of processed content
                contentBuffer.length,
            buffer: contentBuffer, // Already processed content (Base64 string for inline)
            contentEncoding: precomputedCompression.contentEncoding
        };
    }

    // Apply compression if beneficial (normal flow)
    const {compressFileBuffer} = require('../middleware/file.middleware');
    return await compressFileBuffer(contentBuffer, this.mimeType, this.fileName);
};

// Helper method: Update compression metadata
fileSchema.methods._updateCompressionMetadata = function (compressionResult) {
    if (!this.compression) this.compression = {};
    this.compression.isCompressed = compressionResult.compressed;
    this.compression.algorithm = compressionResult.algorithm;
    this.compression.originalSize = compressionResult.originalSize;
    this.compression.compressionRatio = compressionResult.compressionRatio;
    this.compression.contentEncoding = compressionResult.contentEncoding;
};

// Helper method: Capture rollback data
fileSchema.methods._captureRollbackData = function () {
    return {
        storageType: this.storageType,
        content: this.content,
        size: this.size,
        compression: {...this.compression}
    };
};

// Helper method: Store content in GridFS
fileSchema.methods._storeInGridFS = async function (finalContentBuffer, session, rollbackData) {
    // Initialize GridFS cleanup array if using a session
    if (session) {
        if (!session.transaction.gridfsCleanup) {
            session.transaction.gridfsCleanup = [];
        }
        // If switching from inline to GridFS within a transaction, we need to handle rollback
        if (rollbackData.storageType === 'inline') {
            session.transaction.gridfsCleanup.push(this.filePath);
        }
    }

    try {
        // Store compressed content in GridFS
        await storeInGridFS(this.filePath, finalContentBuffer, {
            mimeType: this.mimeType,
            fileName: this.fileName,
            owner: this.owner,
            compression: this.compression // Include compression metadata
        });

        // Add to cleanup list if in transaction (in case transaction fails after GridFS storage)
        if (session) {
            session.transaction.gridfsCleanup.push(this.filePath);
        }

        // Update document properties
        this.content = '';
        this.storageType = 'gridfs';
        this.size = finalContentBuffer.length;
    } catch (error) {
        throw new Error(`Failed to store content in GridFS: ${error.message}`);
    }
};

// Helper method: Store content inline
fileSchema.methods._storeInline = async function (compressionResult, newContent, precomputedCompression, rollbackData) {
    // Clean up old GridFS data if switching from GridFS to inline
    if (rollbackData.storageType === 'gridfs') {
        try {
            await deleteFromGridFS(this.filePath);
        } catch (error) {
            const logger = require('../utils/app.logger');
            logger.warn(`Failed to clean up old GridFS content for ${this.filePath}:`, error.message);
        }
    }

    // Store content based on compression state
    this.content = this._formatContentForInlineStorage(compressionResult, newContent, precomputedCompression);
    this.storageType = 'inline';
    this.size = compressionResult.compressedSize;
};

// Helper method: Format content for inline storage
fileSchema.methods._formatContentForInlineStorage = function (compressionResult, newContent, precomputedCompression) {
    if (compressionResult.compressed) {
        // Handle compressed content
        if (precomputedCompression) {
            // For uploads with precomputed compression, the content has already been processed
            // by the middleware and is already Base64-encoded compressed data for inline storage
            return typeof compressionResult.buffer === 'string' ?
                compressionResult.buffer :
                compressionResult.buffer.toString('utf8'); // Convert buffer back to string
        } else {
            // Normal compression flow - need to Base64 encode the compressed buffer
            return compressionResult.buffer.toString('base64');
        }
    }

    // Handle uncompressed content
    if (Buffer.isBuffer(newContent)) {
        return this.constructor.isTextBasedFile(this.mimeType)
            ? newContent.toString('utf8')
            : newContent.toString('base64');
    }

    return newContent;
};

// Helper method: Update metadata for GridFS storage
fileSchema.methods._updateMetadataForGridFS = function (newContent) {
    if (!this.metadata) this.metadata = {};

    if (this.constructor.isTextBasedFile(this.mimeType)) {
        // For text files, calculate char/line counts from original content
        const originalContent = typeof newContent === 'string' ? newContent : newContent.toString('utf8');
        this.metadata.charCount = originalContent.length;
        this.metadata.lineCount = originalContent.split('\n').length;
    } else {
        // For binary files, just store size info
        this.metadata.charCount = 0;
        this.metadata.lineCount = 0;
    }
};

// Helper method: Update metadata for inline storage
fileSchema.methods._updateMetadataForInline = function (newContent) {
    if (!this.metadata) this.metadata = {};

    if (typeof newContent === 'string') {
        this.metadata.charCount = newContent.length;
        this.metadata.lineCount = newContent.split('\n').length;
    } else if (Buffer.isBuffer(newContent) && this.constructor.isTextBasedFile(this.mimeType)) {
        const textContent = newContent.toString('utf8');
        this.metadata.charCount = textContent.length;
        this.metadata.lineCount = textContent.split('\n').length;
    } else {
        this.metadata.charCount = 0;
        this.metadata.lineCount = 0;
    }
};

// Helper method: Rollback changes on error
fileSchema.methods._rollbackChanges = function (rollbackData) {
    this.content = rollbackData.content;
    this.storageType = rollbackData.storageType;
    this.size = rollbackData.size;
    this.compression = rollbackData.compression;
};

fileSchema.methods.deleteContent = async function (session = null) {
    if (this.storageType === 'gridfs') {
        try {
            await deleteFromGridFS(this.filePath);

            // If we're in a transaction, mark this as a successful GridFS operation
            if (session && session.transaction) {
                if (!session.transaction.gridfsDeleted) {
                    session.transaction.gridfsDeleted = [];
                }
                session.transaction.gridfsDeleted.push(this.filePath);
            }
        } catch (error) {
            const logger = require('../utils/app.logger');
            logger.warn(`Failed to delete GridFS content for ${this.filePath}:`, error.message);

            // If in transaction, this is more critical - we should throw
            if (session) {
                throw new Error(`Failed to delete GridFS content: ${error.message}`);
            }
        }
    }
    // Clear inline content regardless
    this.content = '';
    this.storageType = 'inline';
    this.size = 0;
};


// Atomic update methods
fileSchema.methods.updateContent = async function (newContent, userId, message = 'Content updated', precomputedCompression = null) {
    const session = await this.constructor.startSession();

    try {
        return await session.withTransaction(async () => {
            // Initialize transaction cleanup arrays
            initializeTransactionCleanup(session);

            // Handle content storage (inline vs GridFS) within transaction
            await this.setContent(newContent, session, precomputedCompression);

            // Update document without incrementing version or creating history
            const updateData = {
                lastModifiedBy: userId,
                updatedAt: new Date(),
                $set: {
                    size: this.size,
                    content: this.content, // Will be empty string if GridFS
                    storageType: this.storageType,
                    'metadata.charCount': this.metadata?.charCount || 0,
                    'metadata.lineCount': this.metadata?.lineCount || 0,
                    // Update compression metadata
                    'compression.isCompressed': this.compression?.isCompressed || false,
                    'compression.algorithm': this.compression?.algorithm || 'none',
                    'compression.originalSize': this.compression?.originalSize || this.size,
                    'compression.compressionRatio': this.compression?.compressionRatio || 1,
                    'compression.contentEncoding': this.compression?.contentEncoding || null
                }
            };

            const result = await this.constructor.findOneAndUpdate(
                {_id: this._id},
                updateData,
                {
                    new: true,
                    session,
                    runValidators: true
                }
            );

            if (!result) {
                throw new Error('File not found or update failed');
            }

            // Update this instance with new values
            Object.assign(this, result.toObject());

            return this;
        });
    } catch (error) {
        const logger = require('../utils/app.logger');
        logger.error(`Error updating content for ${this.filePath}:`, error);
        throw error;
    } finally {
        await session.endSession();
    }
};

// Instance method to publish content as a new version
fileSchema.methods.publishContent = async function (userId, message = 'Published version') {
    const session = await this.constructor.startSession();

    try {
        return await session.withTransaction(async () => {
            // Initialize transaction cleanup arrays
            initializeTransactionCleanup(session);

            const newVersion = this.version + 1;
            const newVersionEntry = {
                version: newVersion,
                timestamp: new Date(),
                modifiedBy: userId,
                message: message,
                size: this.size,
                content: this.content, // Store actual content for published version
                storageType: this.storageType,
                metadata: {
                    encoding: this.metadata?.encoding || 'utf-8',
                    language: this.metadata?.language,
                    lineCount: this.metadata?.lineCount || 0,
                    charCount: this.metadata?.charCount || 0
                },
                // Include compression metadata in version history
                compression: {
                    isCompressed: this.compression?.isCompressed || false,
                    algorithm: this.compression?.algorithm || 'none',
                    originalSize: this.compression?.originalSize || this.size,
                    compressionRatio: this.compression?.compressionRatio || 1,
                    contentEncoding: this.compression?.contentEncoding || null
                }
            };

            const updateData = {
                lastModifiedBy: userId,
                updatedAt: new Date(),
                $inc: {version: 1}
            };

            // Add the new version to history
            if (this.versionHistory && this.versionHistory.length >= 10) {
                updateData.$push = {
                    versionHistory: {
                        $each: [newVersionEntry],
                        $slice: -10 // Keep only last 10 versions
                    }
                };
            } else {
                updateData.$push = {versionHistory: newVersionEntry};
            }

            const result = await this.constructor.findOneAndUpdate(
                {_id: this._id},
                updateData,
                {
                    new: true,
                    session,
                    runValidators: true
                }
            );

            if (!result) {
                throw new Error('File not found or publish failed');
            }

            // Update this instance with new values
            Object.assign(this, result.toObject());

            return this;
        });
    } catch (error) {
        const logger = require('../utils/app.logger');
        logger.error(`Error publishing content for ${this.filePath}:`, error);
        throw error;
    } finally {
        await session.endSession();
    }
};

// Instance method to move file/directory atomically
fileSchema.methods.moveTo = async function (newPath) {
    const oldPath = this.filePath;
    const isDirectory = this.type === 'directory';

    const session = await this.constructor.startSession();

    try {
        await session.withTransaction(async () => {
            // Initialize transaction cleanup arrays
            initializeTransactionCleanup(session);

            // Update this item's path
            await this.constructor.findOneAndUpdate(
                {_id: this._id},
                {
                    $set: {
                        filePath: newPath,
                        parentPath: newPath === '/' ? null : newPath.substring(0, newPath.lastIndexOf('/')) || '/',
                        depth: newPath === '/' ? 0 : newPath.split('/').length - 1,
                        fileName: newPath.split('/').pop()
                    }
                },
                {session}
            );

            if (isDirectory) {
                // Update all children paths atomically
                await this.constructor.updateMany(
                    {
                        filePath: new RegExp(`^${oldPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}/`),
                        owner: this.owner
                    },
                    [{
                        $set: {
                            filePath: {
                                $concat: [newPath, {$substr: ['$filePath', oldPath.length, -1]}]
                            },
                            parentPath: {
                                $cond: {
                                    if: {$eq: ['$filePath', {$concat: [oldPath, '/', {$arrayElemAt: [{$split: [{$substr: ['$filePath', oldPath.length + 1, -1]}, '/']}, 0]}]}]},
                                    then: newPath,
                                    else: {$concat: [newPath, {$substr: ['$parentPath', oldPath.length, -1]}]}
                                }
                            },
                            depth: {$add: [{$subtract: [{$size: {$split: [newPath, '/']}}, 1]}, {$subtract: ['$depth', {$subtract: [{$size: {$split: [oldPath, '/']}}, 1]}]}]}
                        }
                    }],
                    {session}
                );
            }

            // Update this instance
            this.filePath = newPath;
            this.parentPath = newPath === '/' ? null : newPath.substring(0, newPath.lastIndexOf('/')) || '/';
            this.depth = newPath === '/' ? 0 : newPath.split('/').length - 1;
        });
    } finally {
        await session.endSession();
    }

    return this;
};

// Instance method to migrate storage type atomically
fileSchema.methods.migrateStorageType = async function (targetStorageType) {
    if (this.storageType === targetStorageType) {
        return this; // No migration needed
    }

    const session = await this.constructor.startSession();

    try {
        return await session.withTransaction(async () => {
            // Initialize transaction cleanup arrays
            initializeTransactionCleanup(session);

            const currentContent = await this.getContent();

            // Update to new storage type
            await this.setContent(currentContent, session);

            // Force the target storage type
            this.storageType = targetStorageType;

            // Save the updated document
            await this.save({session});

            return this;
        });
    } catch (error) {
        const logger = require('../utils/app.logger');
        logger.error(`Error migrating storage type for ${this.filePath}:`, error);
        throw error;
    } finally {
        await session.endSession();
    }
};

// Static method to get supported file types
fileSchema.statics.getSupportedTypes = function () {
    return {
        text: ['txt', 'md', 'log', 'csv'],
        code: ['js', 'ts', 'jsx', 'tsx', 'py', 'java', 'cpp', 'c', 'h', 'css', 'scss', 'sass', 'less', 'html', 'xml', 'json', 'php', 'rb', 'go', 'rs', 'swift', 'kt', 'dart', 'sql'],
        config: ['ini', 'conf', 'config', 'env', 'toml'],
        documentation: ['md', 'rst', 'adoc', 'tex'],
        data: ['json', 'xml', 'csv', 'tsv', 'yaml', 'yml'], // yml should be in data, not code
        web: ['html', 'htm', 'css', 'js', 'ts', 'jsx', 'tsx', 'vue', 'svelte'],
        shell: ['sh', 'bash', 'zsh', 'fish', 'ps1', 'bat', 'cmd'],
        models3d: ['obj', 'fbx', 'gltf', 'glb', 'dae', 'stl', 'ply', '3ds', 'blend', 'x3d', 'wrl', 'max', 'ma', 'mb'], // 3D model formats
        other: ['*'] // Wildcard for any other text-based files
    };
};

// Static method to create or update file atomically
fileSchema.statics.createOrUpdate = async function (filePath, owner, content, options = {}) {
    const session = await this.startSession();

    try {
        return await session.withTransaction(async () => {
            // Initialize transaction cleanup arrays
            initializeTransactionCleanup(session);

            // Try to find existing file
            let file = await this.findOne({filePath, owner}).session(session);

            if (file) {
                // Update existing file
                return await file.updateContent(content, options.modifiedBy || owner, options.message, options.compression);
            } else {
                // Create new file
                const fileData = {
                    filePath,
                    owner,
                    lastModifiedBy: options.modifiedBy || owner,
                    ...options
                };

                // Auto-detect file properties if not provided
                if (!fileData.fileName && filePath !== '/') {
                    fileData.fileName = filePath.split('/').pop();
                }

                if (fileData.fileName && !fileData.fileType) {
                    const detectedType = this.detectFileType(fileData.fileName);
                    fileData.fileType = detectedType.extension;
                    fileData.mimeType = detectedType.mimeType;
                }

                // Set size if not provided
                const contentSize = Buffer.byteLength(content, 'utf8');
                if (!fileData.size) {
                    fileData.size = contentSize;
                }

                // Determine storage type based on content size and type
                if (!fileData.storageType && fileData.fileName && content) {
                    fileData.storageType = this.determineStorageType(fileData.fileName, contentSize, fileData.mimeType);
                } else if (!fileData.storageType) {
                    fileData.storageType = 'inline';
                }

                file = new this(fileData);

                // Handle content storage before saving (pass session for transaction support)
                await file.setContent(content, session, options.compression);

                return await file.save({session});
            }
        });
    } finally {
        await session.endSession();
    }
};

// Static method to create directory atomically
fileSchema.statics.createDirectory = async function (dirPath, owner, options = {}) {
    // Validate path
    if (!dirPath.startsWith('/') || dirPath.includes('//')) {
        throw new Error('Invalid directory path');
    }

    const session = await this.startSession();

    try {
        return await session.withTransaction(async () => {
            // Initialize transaction cleanup arrays
            initializeTransactionCleanup(session);

            // Check if directory already exists within transaction
            const existing = await this.findOne({filePath: dirPath, owner}).session(session);
            if (existing) {
                if (existing.type === 'directory') {
                    return existing; // Directory already exists
                } else {
                    throw new Error('A file already exists at this path');
                }
            }

            // Create directory within transaction
            const directory = new this({
                filePath: dirPath,
                type: 'directory',
                owner,
                fileName: null,
                fileType: 'directory',
                mimeType: 'inode/directory',
                storageType: 'inline',
                content: '',
                size: 0,
                ...options
            });

            return await directory.save({session});
        });
    } catch (error) {
        if (error.code === 11000) {
            // Duplicate key error - directory might have been created by another process
            // Check again outside transaction
            const existing = await this.findOne({filePath: dirPath, owner});
            if (existing && existing.type === 'directory') {
                return existing;
            }
        }
        throw error;
    } finally {
        await session.endSession();
    }
};

// Static method to get directory tree (simplified)
fileSchema.statics.getDirectoryTree = async function (rootPath = '/', owner, maxDepth = 10) {
    const items = await this.find({
        filePath: new RegExp(`^${rootPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`),
        owner,
        depth: {$lte: rootPath === '/' ? maxDepth : rootPath.split('/').length - 1 + maxDepth}
    })
        .sort({depth: 1, filePath: 1})
        .lean(); // Use lean for better performance

    // Build simple tree structure
    const tree = {};
    items.forEach(item => {
        const relativePath = item.filePath.substring(rootPath.length);
        const parts = relativePath.split('/').filter(part => part);
        let current = tree;

        parts.forEach((part, index) => {
            if (!current[part]) {
                current[part] = {
                    type: index === parts.length - 1 ? item.type : 'directory',
                    item: index === parts.length - 1 ? item : null,
                    children: {}
                };
            }
            current = current[part].children;
        });
    });

    return tree;
};

// Static method for bulk transactional deletion
fileSchema.statics.deleteManyWithTransaction = async function (query, options = {}) {
    const session = await this.startSession();

    try {
        return await session.withTransaction(async () => {
            // Initialize transaction cleanup arrays
            initializeTransactionCleanup(session);

            // Find all files that will be deleted to clean up GridFS content
            const filesToDelete = await this.find(query).session(session);

            const results = {
                deleted: 0,
                gridfsCleanedUp: 0,
                errors: []
            };

            // Clean up GridFS content for each file that uses it
            for (const file of filesToDelete) {
                try {
                    if (file.storageType === 'gridfs') {
                        await file.deleteContent(session);
                        results.gridfsCleanedUp++;
                    }
                } catch (error) {
                    results.errors.push({
                        filePath: file.filePath,
                        error: `GridFS cleanup failed: ${error.message}`
                    });

                    // If gridFS cleanup is critical, we can fail the transaction
                    if (options.failOnGridFSError) {
                        throw error;
                    }
                }
            }

            // Delete all documents
            const deleteResult = await this.deleteMany(query, {session});
            results.deleted = deleteResult.deletedCount;

            return results;
        });
    } catch (error) {
        const logger = require('../utils/app.logger');
        logger.error('Error in bulk deletion transaction:', error);
        throw error;
    } finally {
        await session.endSession();
    }
};

// Static method to build tree from items array (utility method)
fileSchema.statics.buildTree = function (items, rootPath = '/') {
    const tree = {};
    items.forEach(item => {
        const relativePath = item.filePath.substring(rootPath.length);
        const parts = relativePath.split('/').filter(part => part);
        let current = tree;

        parts.forEach((part, index) => {
            if (!current[part]) {
                current[part] = {
                    type: index === parts.length - 1 ? item.type : 'directory',
                    item: index === parts.length - 1 ? item : null,
                    children: {}
                };
            }
            current = current[part].children;
        });
    });

    return tree;
};

// Static method to find files by pattern (simplified)
fileSchema.statics.findByPattern = function (pattern, owner, options = {}) {
    const query = {owner};

    if (pattern.includes('*') || pattern.includes('?')) {
        // Convert simple glob pattern to regex
        const regexPattern = pattern
            .replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
            .replace(/\\\*/g, '.*')
            .replace(/\\\?/g, '.');
        query.filePath = new RegExp(`^${regexPattern}$`);
    } else {
        query.filePath = new RegExp(pattern, 'i');
    }

    if (options.fileType) {
        query.type = options.fileType;
    }

    return this.find(query).sort({filePath: 1});
};

// Static method to validate path
fileSchema.statics.validatePath = function (path) {
    // Check basic path rules
    if (!path.startsWith('/')) return false;
    if (path.includes('//')) return false;
    if (path.includes('\0')) return false;
    if (path.length > 4096) return false; // Reasonable path length limit
    if (path !== '/' && path.endsWith('/')) return false;

    // Check for invalid characters in path components
    const parts = path.split('/').filter(part => part);
    for (const part of parts) {
        if (part === '.' || part === '..') return false; // No relative references
        if (/[<>:"|*?]/.test(part)) return false; // No Windows-invalid chars
        if (part.length > 255) return false; // Reasonable filename length
    }

    return true;
};

/**
 * Static method to check file access with permissions
 * @param {Object} query - Query to find the file
 * @param {string} userId - User ID to check permissions for
 * @param {Array<string>} userRoles - User roles for permission check
 * @returns {Promise<Object|null>} - File document if access granted, null otherwise
 */
fileSchema.statics.checkAccessWithPermissions = async function (query, userId, userRoles = []) {
    // Find the file first
    const file = await this.findOne(query);

    // If file doesn't exist, return null
    if (!file) {
        return null;
    }

    // Check if user is admin or has global access rights
    const {hasRight, RIGHTS} = require('../config/rights');
    if (hasRight(userRoles, RIGHTS.MANAGE_ALL_CONTENT)) {
        return file;
    }

    // Check if user is the owner
    if (file.owner.toString() === userId.toString()) {
        return file;
    }

    // Check read permissions
    if (file.hasReadPermission(userId)) {
        return file;
    }

    // No access
    return null;
};

// Static method to detect file type from filename
fileSchema.statics.detectFileType = function (fileName) {
    // Check if filename has an extension
    const lastDotIndex = fileName.lastIndexOf('.');
    if (lastDotIndex === -1 || lastDotIndex === fileName.length - 1) {
        // No extension or ends with a dot
        return {
            category: 'other', extension: undefined, mimeType: 'application/octet-stream'
        };
    }

    const ext = fileName.slice(lastDotIndex + 1).toLowerCase();
    const supportedTypes = this.getSupportedTypes();

    for (const [category, extensions] of Object.entries(supportedTypes)) {
        if (extensions.includes(ext) || extensions.includes('*')) {
            return {
                category, extension: ext, mimeType: this.getMimeType(ext)
            };
        }
    }

    return {
        category: 'other', extension: ext, mimeType: this.getMimeType(ext)
    };
};

// Static method to get MIME type
fileSchema.statics.getMimeType = function (extension) {
    // Explicit overrides for known problematic extensions
    const overrides = {
        py: 'text/x-python', ts: 'text/typescript',
    };
    if (overrides[extension]) return overrides[extension];
    // Use mime-types package for standard MIME type detection
    const mimeType = mime.lookup(extension);

    // Return the detected MIME type, or default to text/plain for unknown extensions
    return mimeType || 'text/plain';
};

// Static method to determine storage type based on file characteristics
fileSchema.statics.determineStorageType = function (fileName, fileSize, mimeType) {
    // GridFS size threshold - files larger than 64KB should use GridFS
    const GRIDFS_SIZE_THRESHOLD = 64 * 1024; // 64KB

    // Check if file size exceeds threshold for GridFS
    if (fileSize && fileSize > GRIDFS_SIZE_THRESHOLD) {
        return 'gridfs';
    }

    // Binary files (like PDFs, images, etc.) over a smaller threshold should use GridFS
    const BINARY_GRIDFS_THRESHOLD = 16 * 1024; // 16KB for binary files
    if (mimeType && !this.isTextBasedFile(mimeType) && fileSize > BINARY_GRIDFS_THRESHOLD) {
        return 'gridfs';
    }

    // Default to inline storage for smaller files
    return 'inline';
};

// Static method to check if file type is text-based
fileSchema.statics.isTextBasedFile = function (mimeType) {
    const textMimeTypes = ['text/', 'application/json', 'application/xml', 'application/javascript', 'application/typescript'];

    return textMimeTypes.some(type => mimeType.startsWith(type));
};

// Static helper method to normalize user ID
fileSchema.statics.normalizeUserId = function (userId) {
    return typeof userId === 'string' ? new mongoose.Types.ObjectId(userId) : userId;
};

// Static helper method to check admin roles
fileSchema.statics.hasAdminRole = function (userRoles) {
    const adminRoles = ['OWNER', 'ADMIN', 'CREATOR'];
    return Array.isArray(userRoles) ?
        userRoles.some(role => adminRoles.includes(role)) :
        adminRoles.includes(userRoles);
};

// Static method to find file with read permission check
fileSchema.statics.findWithReadPermission = function (query, userId, userRoles = []) {
    if (this.hasAdminRole(userRoles)) {
        // Admin/Owner can read any file - use query as-is
        return this.findOne(query);
    }

    const readQuery = {
        ...query,
        $or: [
            {owner: userId}, // Owner can always read - let MongoDB handle ID conversion
            {'permissions.read': userId} // User has explicit read permission
        ]
    };
    return this.findOne(readQuery);
};

// Static method to find file with write permission check
fileSchema.statics.findWithWritePermission = function (query, userId, userRoles = []) {
    if (this.hasAdminRole(userRoles)) {
        // Admin/Owner can write to any file - use query as-is
        return this.findOne(query);
    }

    const writeQuery = {
        ...query,
        $or: [
            {owner: userId}, // Owner can always write
            {'permissions.write': userId} // User has explicit write permission
        ]
    };
    return this.findOne(writeQuery);
};

// Static method for admin file metadata updates (excluding content)
fileSchema.statics.findWithManagePermission = function (query, userId, userRoles = []) {
    const userIdObj = this.normalizeUserId(userId);

    if (this.hasAdminRole(userRoles)) {
        // Admin/Owner can manage any file
        return this.findOne(query);
    } else {
        // Regular users can only manage files they own or have write permission to
        return this.findOne({
            ...query,
            $or: [
                {owner: userIdObj}, // Owner can always manage
                {'permissions.write': userIdObj} // User has explicit write permission
            ]
        });
    }
};

// Static method to get all files a user has access to (owned + shared)
fileSchema.statics.getUserFiles = async function (userId, options = {}) {
    const {
        page = 1,
        limit = 50,
        sortBy = 'updatedAt',
        sortOrder = 'desc',
        type = null,
        search = null,
        includeContent = false,
        adminView = false
    } = options;

    const userIdObj = typeof userId === 'string' ? new mongoose.Types.ObjectId(userId) : userId;

    // Build base query
    let baseQuery = {};

    // If not admin view, filter by user permissions
    if (!adminView && userId) {
        baseQuery = {
            $or: [
                {owner: userIdObj}, // Files user owns
                {'permissions.read': userIdObj}, // Files user has read access to
                {'permissions.write': userIdObj} // Files user has write access to
            ]
        };
    }

    // Add type filter
    if (type) {
        baseQuery.type = type;
    }

    // Add search filter
    if (search) {
        baseQuery.$and = baseQuery.$and || [];
        baseQuery.$and.push({
            $or: [
                {fileName: {$regex: search, $options: 'i'}},
                {filePath: {$regex: search, $options: 'i'}},
                {description: {$regex: search, $options: 'i'}},
                {tags: {$in: [new RegExp(search, 'i')]}}
            ]
        });
    }

    // Build aggregation pipeline for better performance and consistent results
    const pipeline = [
        {$match: baseQuery},

        // Add computed fields for permissions
        {
            $addFields: {
                isOwner: {$eq: ['$owner', userIdObj]},
                hasReadAccess: {
                    $or: [
                        {$eq: ['$owner', userIdObj]},
                        {$in: [userIdObj, '$permissions.read']}
                    ]
                },
                hasWriteAccess: {
                    $or: [
                        {$eq: ['$owner', userIdObj]},
                        {$in: [userIdObj, '$permissions.write']}
                    ]
                }
            }
        },

        // Lookup owner information
        {
            $lookup: {
                from: 'users',
                localField: 'owner',
                foreignField: '_id',
                as: 'ownerInfo',
                pipeline: [
                    {
                        $project: {
                            firstName: 1,
                            lastName: 1,
                            username: 1,
                            email: 1
                        }
                    }
                ]
            }
        },

        // Lookup last modified by information
        {
            $lookup: {
                from: 'users',
                localField: 'lastModifiedBy',
                foreignField: '_id',
                as: 'lastModifiedByInfo',
                pipeline: [
                    {
                        $project: {
                            firstName: 1,
                            lastName: 1,
                            username: 1,
                            email: 1
                        }
                    }
                ]
            }
        },

        // Project final fields
        {
            $project: {
                filePath: 1,
                fileName: 1,
                type: 1,
                fileType: 1,
                mimeType: 1,
                size: 1,
                version: 1,
                description: 1,
                tags: 1,
                storageType: 1,
                depth: 1,
                parentPath: 1,
                metadata: 1,
                createdAt: 1,
                updatedAt: 1,
                owner: {$arrayElemAt: ['$ownerInfo', 0]},
                lastModifiedBy: {$arrayElemAt: ['$lastModifiedByInfo', 0]},
                permissions: 1,
                isOwner: 1,
                hasReadAccess: 1,
                hasWriteAccess: 1,
                // Only include content if specifically requested
                content: includeContent ? '$content' : '$$REMOVE',
                versionHistory: includeContent ? '$versionHistory' : '$$REMOVE'
            }
        },

        // Sort
        {$sort: {[sortBy]: sortOrder === 'desc' ? -1 : 1}},

        // Add pagination
        {
            $facet: {
                files: [
                    {$skip: (page - 1) * limit},
                    {$limit: limit}
                ],
                totalCount: [
                    {$count: 'count'}
                ],
                summary: [
                    {
                        $group: {
                            _id: null,
                            totalFiles: {$sum: 1},
                            totalSize: {$sum: '$size'},
                            fileTypes: {$addToSet: '$fileType'},
                            storageBreakdown: {
                                $push: {
                                    type: '$storageType',
                                    size: '$size'
                                }
                            }
                        }
                    }
                ]
            }
        }
    ];

    // Execute aggregation
    const result = await this.aggregate(pipeline);
    const data = result[0];

    const totalFiles = data.totalCount[0]?.count || 0;
    const totalPages = Math.ceil(totalFiles / limit);
    const summary = data.summary[0] || {
        totalFiles: 0,
        totalSize: 0,
        fileTypes: [],
        storageBreakdown: []
    };

    return {
        files: data.files,
        pagination: {
            currentPage: page,
            totalPages,
            totalFiles,
            hasNextPage: page < totalPages,
            hasPrevPage: page > 1,
            limit
        },
        summary: {
            ...summary,
            inlineStorage: summary.storageBreakdown?.filter(item => item.type === 'inline').reduce((sum, item) => sum + item.size, 0) || 0,
            gridfsStorage: summary.storageBreakdown?.filter(item => item.type === 'gridfs').reduce((sum, item) => sum + item.size, 0) || 0
        }
    };
};

// Static method to get files by access type (owned, shared-read, shared-write)
fileSchema.statics.getUserFilesByAccessType = async function (userId, options = {}) {
    const {
        page = 1,
        limit = 50,
        sortBy = 'updatedAt',
        sortOrder = 'desc',
        accessType = 'all', // 'owned', 'shared-read', 'shared-write', 'all'
        type = null,
        search = null,
        includeContent = false
    } = options;

    const userIdObj = this.normalizeUserId(userId);

    // Build base query based on access type
    let baseQuery = {};

    switch (accessType) {
        case 'owned':
            baseQuery.owner = userIdObj;
            break;
        case 'shared-read':
            baseQuery = {
                'permissions.read': userIdObj,
                owner: {$ne: userIdObj} // Exclude owned files
            };
            break;
        case 'shared-write':
            baseQuery = {
                'permissions.write': userIdObj,
                owner: {$ne: userIdObj} // Exclude owned files
            };
            break;
        case 'all':
        default:
            baseQuery = {
                $or: [
                    {owner: userIdObj},
                    {'permissions.read': userIdObj},
                    {'permissions.write': userIdObj}
                ]
            };
            break;
    }

    // Add type filter
    if (type) {
        baseQuery.type = type;
    }

    // Add search filter
    if (search) {
        baseQuery.$and = baseQuery.$and || [];
        baseQuery.$and.push({
            $or: [
                {fileName: {$regex: search, $options: 'i'}},
                {filePath: {$regex: search, $options: 'i'}},
                {description: {$regex: search, $options: 'i'}},
                {tags: {$in: [new RegExp(search, 'i')]}}
            ]
        });
    }

    // Execute query with pagination
    const files = await this.find(baseQuery)
        .populate('owner lastModifiedBy', 'firstName lastName username email')
        .select(includeContent ? '' : '-content -versionHistory')
        .sort({[sortBy]: sortOrder === 'desc' ? -1 : 1})
        .skip((page - 1) * limit)
        .limit(limit)
        .lean();

    // Get total count
    const totalFiles = await this.countDocuments(baseQuery);
    const totalPages = Math.ceil(totalFiles / limit);

    // Add computed fields for permissions
    const enrichedFiles = files.map(file => ({
        ...file,
        isOwner: file.owner._id.toString() === userId,
        hasReadAccess: file.owner._id.toString() === userId ||
            file.permissions.read.some(id => id.toString() === userId),
        hasWriteAccess: file.owner._id.toString() === userId ||
            file.permissions.write.some(id => id.toString() === userId)
    }));

    // Calculate summary
    const summary = {
        totalFiles,
        totalSize: files.reduce((sum, file) => sum + (file.size || 0), 0),
        fileTypes: [...new Set(files.map(file => file.fileType))],
        accessType,
        inlineStorage: files.filter(f => f.storageType === 'inline').reduce((sum, f) => sum + (f.size || 0), 0),
        gridfsStorage: files.filter(f => f.storageType === 'gridfs').reduce((sum, f) => sum + (f.size || 0), 0)
    };

    return {
        files: enrichedFiles,
        pagination: {
            currentPage: page,
            totalPages,
            totalFiles,
            hasNextPage: page < totalPages,
            hasPrevPage: page > 1,
            limit
        },
        summary
    };
};

module.exports = mongoose.model('File', fileSchema);
