import mongoose from 'mongoose';
import mime from 'mime-types';
import logger from '../utils/app.logger.js';
import {storeInGridFS, retrieveFromGridFS, deleteFromGridFS} from '../config/db.js';

/**
 * Hybrid File Schema for MongoDB storage
 * Separates text files (collaborative) from binary files (traditional storage)
 */
const fileSchema = new mongoose.Schema({
    // Filesystem path (Unix-style absolute path) - UNIQUE per owner
    filePath: {
        type: String,
        required: true,
        validate: {
            validator: function (v) {
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

    // Consolidated file type: directory, binary, or text (collaborative)
    type: {
        type: String,
        enum: ['directory', 'binary', 'text'],
        required: true,
        index: true,
        default: function() {
            // Auto-determine based on file extension if it's a file
            if (this.filePath && this.filePath.endsWith('/')) {
                return 'directory';
            }
            
            // For files, determine based on extension
            const ext = this.fileName ? this.fileName.toLowerCase().split('.').pop() : '';
            const binaryExtensions = [
                'jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'bmp', 'ico',
                'mp3', 'wav', 'mp4', 'webm', 'avi', 'mov', 'wmv', 'flv',
                'pdf', 'doc', 'docx', 'xls', 'xlsx', 'zip', 'rar', '7z',
                'exe', 'dll', 'bin', 'dmg', 'iso', 'tar', 'gz', 'db',
                'sqlite', 'mdb', 'psd', 'ai', 'indd'
            ];
            
            // All text files are now collaborative
            return binaryExtensions.includes(ext) ? 'binary' : 'text';
        }
    },

    // File name with extension (extracted from path)
    fileName: {
        type: String,
        required: function () {
            return this.type !== 'directory';
        },
        trim: true,
        default: function () {
            if (this.type === 'directory') return null;
            const parts = this.filePath.split('/');
            return parts[parts.length - 1];
        }
    },
    
    // GridFS storage for binary file content only (text files use Yjs persistence)
    gridFSId: {
        type: mongoose.Schema.Types.ObjectId,
        sparse: true,
        // Note: gridFSId is automatically generated during binary file upload
        // via the setContent() method, so it's not required at creation time
    },

    // MIME type
    mimeType: {
        type: String, 
        required: function() { return this.type !== 'directory'; },
        default: function() {
            if (this.type === 'directory') return undefined;
            return mime.lookup(this.fileName) || 'application/octet-stream';
        }
    },

    // File size in bytes
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

    // Depth level in filesystem hierarchy
    depth: {
        type: Number,
        index: true,
        default: function () {
            return this.filePath === '/' ? 0 : this.filePath.split('/').length - 1;
        }
    },

    // Compression information for binary files
    compression: {
        isCompressed: {
            type: Boolean,
            default: false,
            index: true // Index for aggregation performance
        },
        algorithm: {
            type: String,
            enum: ['none', 'gzip', 'deflate', 'brotli'],
            default: 'none'
        },
        originalSize: {
            type: Number,
            default: 0,
            min: [0, 'Original size cannot be negative']
        },
        compressionRatio: {
            type: Number,
            default: 1,
            min: [0, 'Compression ratio cannot be negative'],
            max: [1, 'Compression ratio cannot exceed 1']
        },
        contentEncoding: {
            type: String,
            enum: ['gzip', 'deflate', 'br', null],
            default: null
        }
    },

    // Media metadata for audio/video files
    mediaMetadata: {
        // Common fields (audio & video)
        duration: { type: Number, default: 0 }, // seconds
        bitrate: { type: Number, default: 0 }, // bits per second
        
        // Audio-specific fields
        title: { type: String, maxlength: 200 },
        artist: { type: String, maxlength: 200 },
        album: { type: String, maxlength: 200 },
        year: { type: Number },
        genre: { type: String, maxlength: 100 },
        track: { type: Number },
        albumArtist: { type: String, maxlength: 200 },
        
        // Video-specific fields
        width: { type: Number },
        height: { type: Number },
        fps: { type: Number },
        videoCodec: { type: String, maxlength: 50 },
        audioCodec: { type: String, maxlength: 50 },
        
        // Cover art / Thumbnail (stored in GridFS)
        coverArtId: { type: mongoose.Schema.Types.ObjectId },
        thumbnailId: { type: mongoose.Schema.Types.ObjectId }
    },

    // Version snapshots for binary files only
    // Collaborative files use Yjs built-in versioning
    // Versions are ordered oldest-first (index 0 = version 1, index 1 = version 2, etc.)
    versionHistory: [{
        timestamp: {type: Date, default: Date.now},
        modifiedBy: {type: mongoose.Schema.Types.ObjectId, ref: 'User'},
        message: {type: String, maxlength: 200},
        size: Number,
        gridFSId: mongoose.Schema.Types.ObjectId, // All version content stored in GridFS
        _id: false
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

// Compression aggregation indexes
fileSchema.index({'compression.isCompressed': 1, type: 1});
fileSchema.index({'compression.algorithm': 1, 'compression.isCompressed': 1});
fileSchema.index({type: 1, 'compression.isCompressed': 1, owner: 1});

// Text search index
fileSchema.index({fileName: 'text', filePath: 'text'});

// Virtual for file extension
fileSchema.virtual('fileExtension').get(function () {
    if (this.type === 'directory' || !this.fileName) return null;
    const lastDot = this.fileName.lastIndexOf('.');
    return lastDot === -1 ? null : this.fileName.substring(lastDot + 1).toLowerCase();
});

// Pre-save middleware to set defaults and validate
fileSchema.pre('save', async function(next) {
    // Auto-calculate parentPath and fileName when filePath exists or changes
    if (this.filePath && (this.isNew || this.isModified('filePath'))) {
        // Calculate parentPath
        if (this.filePath === '/') {
            this.parentPath = null;
        } else {
            const lastSlash = this.filePath.lastIndexOf('/');
            this.parentPath = lastSlash === 0 ? '/' : this.filePath.substring(0, lastSlash);
        }
        
        // Calculate fileName for non-directory files
        if (this.type !== 'directory') {
            const parts = this.filePath.split('/');
            this.fileName = parts[parts.length - 1];
        }
    }
    
    // Auto-calculate size for inline content
    if (this.content && typeof this.content === 'string') {
        this.size = Buffer.byteLength(this.content, 'utf8');
    }
    
    // Ensure compression fields exist for all file types (not directories)
    if (this.type !== 'directory' && !this.compression) {
        this.compression = {
            isCompressed: false,
            algorithm: 'none',
            originalSize: this.size || 0,
            compressionRatio: 1,
            contentEncoding: null
        };
    }
    
    next();
});

// Static method to validate file paths
fileSchema.statics.validatePath = function(path) {
    if (!path || typeof path !== 'string') return false;
    return /^\/[^\0]*$/.test(path) && !path.includes('//') && (path === '/' || !path.endsWith('/'));
};

// Static method to get supported file types
fileSchema.statics.getSupportedTypes = function() {
    return {
        text: {
            extensions: ['md', 'txt', 'js', 'jsx', 'ts', 'tsx', 'json', 'xml', 
                        'html', 'css', 'scss', 'sass', 'less', 'yaml', 'yml', 
                        'sql', 'py', 'java', 'c', 'cpp', 'h', 'go', 'rs', 'php',
                        'rb', 'sh', 'bat', 'ps1', 'dockerfile', 'gitignore',
                        'ini', 'conf', 'config', 'env', 'log'],
            description: 'Text files stored as Yjs collaborative documents'
        },
        binary: {
            extensions: ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'bmp', 'ico',
                        'mp3', 'wav', 'mp4', 'webm', 'avi', 'mov', 'wmv', 'flv',
                        'pdf', 'doc', 'docx', 'xls', 'xlsx', 'zip', 'rar', '7z',
                        'exe', 'dll', 'bin', 'dmg', 'iso', 'tar', 'gz', 'db',
                        'sqlite', 'mdb', 'psd', 'ai', 'indd'],
            description: 'Binary files stored in GridFS with version snapshots'
        }
    };
};

// Static method to get MIME type from extension
fileSchema.statics.getMimeType = function(extension) {
    const ext = extension.toLowerCase();
    const mimeTypes = {
        // Text files
        'txt': 'text/plain',
        'md': 'text/markdown',
        'json': 'application/json',
        'js': 'application/javascript',
        'jsx': 'application/javascript',
        'ts': 'application/typescript',
        'tsx': 'application/typescript',
        'html': 'text/html',
        'css': 'text/css',
        'xml': 'application/xml',
        'yaml': 'application/yaml',
        'yml': 'application/yaml',
        // Images - compressed formats
        'jpg': 'image/jpeg',
        'jpeg': 'image/jpeg',
        'png': 'image/png',
        'gif': 'image/gif',
        'webp': 'image/webp',
        'avif': 'image/avif',
        'heic': 'image/heic',
        'heif': 'image/heif',
        // Images - uncompressed formats (will benefit from compression)
        'bmp': 'image/bmp',
        'tiff': 'image/tiff',
        'tif': 'image/tiff',
        'tga': 'image/tga',
        'ppm': 'image/ppm',
        'pgm': 'image/pgm',
        'pbm': 'image/pbm',
        'svg': 'image/svg+xml',
        // Documents
        'pdf': 'application/pdf',
        // Archives
        'zip': 'application/zip',
        'tar': 'application/x-tar',
        'gz': 'application/gzip'
    };
    
    return mimeTypes[ext] || 'application/octet-stream';
};

// Static method to detect file type with detailed information
fileSchema.statics.detectFileType = function(fileName) {
    if (!fileName || typeof fileName !== 'string') {
        return {
            extension: 'txt',
            type: 'text',
            mimeType: 'text/plain',
            wasDefaulted: true,
            reason: 'No filename provided',
            originalExtension: null,
            defaultedTo: 'txt'
        };
    }
    
    const parts = fileName.toLowerCase().split('.');
    const ext = parts.length > 1 ? parts.pop() : null;
    
    if (!ext) {
        return {
            extension: 'txt',
            type: 'text', 
            mimeType: 'text/plain',
            wasDefaulted: true,
            reason: 'No file extension found',
            originalExtension: null,
            defaultedTo: 'txt'
        };
    }
    
    const supportedTypes = this.getSupportedTypes();
    const textExtensions = supportedTypes.text.extensions;
    const binaryExtensions = supportedTypes.binary.extensions;
    
    // Check if extension is supported
    if (textExtensions.includes(ext) || binaryExtensions.includes(ext)) {
        const type = textExtensions.includes(ext) ? 'text' : 'binary';
        return {
            extension: ext,
            type: type,
            mimeType: this.getMimeType(ext),
            wasDefaulted: false,
            reason: null,
            originalExtension: ext,
            defaultedTo: null
        };
    }
    
    // Unsupported extension - default to text
    return {
        extension: 'txt',
        type: 'text',
        mimeType: 'text/plain', 
        wasDefaulted: true,
        reason: `Unsupported file extension: .${ext}`,
        originalExtension: ext,
        defaultedTo: 'txt'
    };
};

// Static method to determine file type from filename
fileSchema.statics.getFileType = function(fileName) {
    if (!fileName) return 'binary';
    
    const ext = fileName.toLowerCase().split('.').pop();
    const binaryExtensions = [
        'jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'bmp', 'ico',
        'mp3', 'wav', 'mp4', 'webm', 'avi', 'mov', 'wmv', 'flv',
        'pdf', 'doc', 'docx', 'xls', 'xlsx', 'zip', 'rar', '7z',
        'exe', 'dll', 'bin', 'dmg', 'iso', 'tar', 'gz', 'db',
        'sqlite', 'mdb', 'psd', 'ai', 'indd'
    ];
    
    // Directories remain as 'directory', any text file becomes 'collaborative'
    return binaryExtensions.includes(ext) ? 'binary' : 'text';
};

// Instance method to get current content (binary files only - text files use Yjs)
fileSchema.methods.getContent = async function() {
    if (this.type === 'text') {
        throw new Error('Text files use Yjs persistence. Use Yjs document to get content.');
    }
    
    // Handle binary files that don't have content yet (just created)
    if (!this.gridFSId) {
        return ''; // Return empty string for files without content
    }
    
    const retrievedData = await retrieveFromGridFS(this.filePath);
    return retrievedData.content; // Already base64 encoded
};

// Instance method to set content (binary files only - text files use Yjs persistence)
fileSchema.methods.setContent = async function(newContent, session = null, compressionOptions = null) {
    if (this.type === 'text') {
        throw new Error('Text files use Yjs persistence. Use Yjs document to set content.');
    }
    
    // Handle different content types appropriately for binary files
    let contentBuffer;
    
    if (Buffer.isBuffer(newContent)) {
        contentBuffer = newContent;
    } else {
        // For binary files or base64 encoded content
        contentBuffer = Buffer.from(newContent, 'base64');
    }
        
    const contentSize = contentBuffer.length;
    
    // Clean up old GridFS file if exists
    if (this.gridFSId) {
        try {
            await deleteFromGridFS(this.filePath);
        } catch (error) {
            logger.warn('Failed to delete old GridFS file during cleanup', {
                error: error.message,
                filePath: this.filePath
            });
        }
    }
    
    // Store binary file content in GridFS
    const gridFile = await storeInGridFS(this.filePath, contentBuffer, {
        mimeType: this.mimeType,
        fileName: this.fileName,
        fileType: this.type
    });
    this.gridFSId = gridFile._id;
    
    this.size = contentSize;
    this.lastModifiedBy = this.lastModifiedBy || this.owner;
    
    // Set compression info if provided
    if (compressionOptions) {
        this.compression = {
            isCompressed: compressionOptions.isCompressed || false,
            algorithm: compressionOptions.algorithm || 'none',
            originalSize: compressionOptions.originalSize || contentSize,
            compressionRatio: compressionOptions.compressionRatio || 1,
            contentEncoding: compressionOptions.contentEncoding || null
        };
    } else {
        // Ensure compression fields exist for statistics
        this.compression = {
            isCompressed: false,
            algorithm: 'none',
            originalSize: contentSize,
            compressionRatio: 1,
            contentEncoding: null
        };
    }
    
    return this.save({ session });
};

// Instance method to update size for text files based on Yjs document content
fileSchema.methods.updateTextFileSize = async function(yjsDocumentSize) {
    if (this.type !== 'text') {
        throw new Error('This method is only for text files with Yjs documents');
    }
    
    if (typeof yjsDocumentSize !== 'number' || yjsDocumentSize < 0) {
        throw new Error('Invalid document size provided');
    }
    
    // Update size for text files (simplified)
    this.size = yjsDocumentSize;
    this.lastModifiedBy = this.lastModifiedBy || this.owner;
    
    return this.save();
};

// Instance method to get specific version content
fileSchema.methods.getVersionContent = async function(version) {
    const versionNumber = typeof version === 'number' ? version : parseInt(version, 10);
    
    if (isNaN(versionNumber) || versionNumber <= 0) {
        throw new Error(`Invalid version identifier: ${version}`);
    }

    // Convert 1-based version number to 0-based array index (sequential numbering)
    // Version 1 = array[0], Version 2 = array[1], etc.
    const versionIndex = versionNumber - 1;
    
    if (versionIndex < 0 || versionIndex >= this.versionHistory.length) {
        throw new Error(`Version ${versionNumber} not found`);
    }
    
    const versionEntry = this.versionHistory[versionIndex];
    
    // All version content is stored in GridFS
    if (!versionEntry.gridFSId) {
        throw new Error(`No GridFS content found for version ${versionNumber}`);
    }
    
    // Use timestamp-based path for GridFS storage to avoid conflicts
    const versionPath = `${this.filePath}@${versionEntry.timestamp.getTime()}`;
     
    try {
        const retrievedData = await retrieveFromGridFS(versionPath);
        return retrievedData.content;
    } catch (error) {
        // If GridFS content is missing, try to regenerate from current content or provide helpful error
        if (error.message.includes('File not found in GridFS')) {
            // For now, provide a more helpful error message
            throw new Error(`Version ${versionNumber} content is not available (GridFS data missing for ${versionPath}). This may be due to data corruption or an incomplete version creation process.`);
        }
        throw error;
    }
};

// Instance method to delete a specific version
fileSchema.methods.deleteVersion = async function(versionNumber, userId) {
    // Convert 1-based version number to 0-based array index (sequential numbering)
    const versionIndex = versionNumber - 1;
    
    if (versionIndex < 0 || versionIndex >= this.versionHistory.length) {
        throw new Error(`Version ${versionNumber} not found`);
    }
    
    const versionToDelete = this.versionHistory[versionIndex];
    
    // If the version has GridFS content, delete it from GridFS
    if (versionToDelete.gridFSId) {
        try {
            const versionPath = `${this.filePath}@${versionToDelete.timestamp.getTime()}`;
            await deleteFromGridFS(versionPath);
        } catch (error) {
            // Log error but don't fail the deletion
            logger.warn('Failed to delete GridFS file during version cleanup', {
                error: error.message,
                versionPath: `${this.filePath}@${versionToDelete.timestamp.getTime()}`,
                fileId: this._id
            });
        }
    }
    
    // Remove the version from the array
    this.versionHistory.splice(versionIndex, 1);
    
    // Return remaining versions with computed version numbers (sequential numbering)
    const remainingVersions = this.versionHistory.map((v, arrayIndex) => ({
        version: arrayIndex + 1, // Sequential version numbering
        timestamp: v.timestamp,
        modifiedBy: v.modifiedBy,
        message: v.message
    }));
    
    await this.save();
    
    return {
        message: `Version ${versionNumber} deleted successfully`,
        remainingVersions
    };
};

// Instance method to get shared users list
fileSchema.methods.getSharedUsers = function() {
    const allUsers = new Set();
    
    // Add read users
    this.permissions.read.forEach(userId => allUsers.add(userId.toString()));
    
    // Add write users
    this.permissions.write.forEach(userId => allUsers.add(userId.toString()));
    
    return Array.from(allUsers);
};

// Instance method to share file with users and propagate to parents
fileSchema.methods.shareWithUsers = async function(userIds, permission = 'read') {
    if (!userIds || (!Array.isArray(userIds) && typeof userIds !== 'string')) {
        throw new Error('userIds is required and must be an array or string');
    }

    if (!['read', 'write'].includes(permission)) {
        throw new Error('Permission must be either "read" or "write"');
    }

    // Convert userIds to array if it's a string
    const userIdsArray = Array.isArray(userIds) ? userIds : [userIds];
    
    // Add users to the appropriate permission array for this file
    for (const userId of userIdsArray) {
        if (permission === 'read') {
            if (!this.permissions.read.includes(userId)) {
                this.permissions.read.push(userId);
            }
        } else if (permission === 'write') {
            if (!this.permissions.write.includes(userId)) {
                this.permissions.write.push(userId);
            }
            // Write permission should also include read permission
            if (!this.permissions.read.includes(userId)) {
                this.permissions.read.push(userId);
            }
        }
    }
    
    // Propagate permissions to parent directories
    await this.constructor.propagatePermissionsToParents(this.filePath, userIdsArray, permission);
    
    return this;
};

// Static method to propagate permissions to parent directories
fileSchema.statics.propagatePermissionsToParents = async function(filePath, userIds, permission = 'read') {
    if (!filePath || filePath === '/') {
        return; // No parent directories to update for root
    }

    // Convert userIds to array if it's a string
    const userIdsArray = Array.isArray(userIds) ? userIds : [userIds];
    
    // Get all parent directory paths
    const pathParts = filePath.split('/').filter(part => part !== '');
    const parentPaths = [];
    
    // Build parent paths from root down to immediate parent
    for (let i = 0; i < pathParts.length - 1; i++) {
        const parentPath = '/' + pathParts.slice(0, i + 1).join('/');
        parentPaths.push(parentPath);
    }
    
    // Also include root if file is not in root
    if (pathParts.length > 1) {
        parentPaths.unshift('/');
    }

    // Update permissions for all parent directories
    for (const parentPath of parentPaths) {
        const updateOperation = {};
        
        if (permission === 'read' || permission === 'both') {
            updateOperation.$addToSet = updateOperation.$addToSet || {};
            updateOperation.$addToSet['permissions.read'] = { $each: userIdsArray };
        }
        
        if (permission === 'write' || permission === 'both') {
            updateOperation.$addToSet = updateOperation.$addToSet || {};
            updateOperation.$addToSet['permissions.write'] = { $each: userIdsArray };
        }

        // Update parent directory permissions
        await this.updateOne(
            { 
                filePath: parentPath, 
                type: 'directory' 
            },
            updateOperation
        );
    }
};

// Instance method to remove users from file permissions
fileSchema.methods.removeUsersFromPermissions = function(userIds, permission = 'both') {
    if (!userIds || (!Array.isArray(userIds) && typeof userIds !== 'string')) {
        throw new Error('userIds is required and must be an array or string');
    }

    if (!['read', 'write', 'both'].includes(permission)) {
        throw new Error('Permission must be either "read", "write", or "both"');
    }

    // Convert userIds to array if it's a string
    const userIdsArray = Array.isArray(userIds) ? userIds : [userIds];
    
    // Remove users from the appropriate permission arrays
    for (const userId of userIdsArray) {
        if (permission === 'read' || permission === 'both') {
            this.permissions.read = this.permissions.read.filter(
                readUserId => readUserId.toString() !== userId.toString()
            );
        }
        
        if (permission === 'write' || permission === 'both') {
            this.permissions.write = this.permissions.write.filter(
                writeUserId => writeUserId.toString() !== userId.toString()
            );
        }
    }
    
    return this;
};

// Instance method to create version snapshot (all file types)
fileSchema.methods.createVersionSnapshot = async function(userId, message = 'Version snapshot', yjsContentGetter = null) {
    let currentContent;
    let contentBuffer;
    
    // Handle different file types for version creation
    if (this.type === 'text') {
        // For text files, get content from Yjs collaborative document
        if (!this.filePath) {
            throw new Error('Text file missing file path for versioning');
        }
        
        if (!yjsContentGetter) {
            throw new Error('Text file versioning requires Yjs content getter function');
        }
        
        // Get text content from Yjs document using provided function (use filePath directly)
        const textContent = await yjsContentGetter(this.filePath);
        contentBuffer = Buffer.from(textContent, 'utf8');
    } else {
        // For binary files, use existing GridFS content
        currentContent = await this.getContent(); // Already in base64
        contentBuffer = Buffer.from(currentContent, 'base64');
    }
    
    const contentSize = contentBuffer.length;
    const timestamp = new Date();
    
    const versionEntry = {
        timestamp: timestamp,
        modifiedBy: userId,
        message,
        size: contentSize
    };
    
    // Always store version content in GridFS with timestamp-based path
    const versionPath = `${this.filePath}@${timestamp.getTime()}`;
    

    
    const gridFile = await storeInGridFS(versionPath, contentBuffer, {
        mimeType: this.mimeType,
        fileName: this.fileName,
        timestamp: timestamp.getTime(),
        fileType: this.type // Track whether this version came from text or binary file
    });
    versionEntry.gridFSId = gridFile._id;
    
    // Append to end (sequential ordering - latest version has highest number)
    this.versionHistory.push(versionEntry);
    return this.save();
};

// Instance method to check access permissions
fileSchema.methods.hasReadAccess = function(userId, userRoles = []) {
    // Owner always has access
    if (this.owner.toString() === userId.toString()) return true;
    
    // Check explicit read permissions
    if (this.permissions.read.some(readUserId => readUserId.toString() === userId.toString())) {
        return true;
    }
    
    // Check write permissions (write includes read)
    if (this.permissions.write.some(writeUserId => writeUserId.toString() === userId.toString())) {
        return true;
    }
    
    // No role-based override - only explicit permissions matter
    return false;
};

fileSchema.methods.hasWriteAccess = function(userId, userRoles = []) {
    // Owner always has write access
    if (this.owner.toString() === userId.toString()) return true;
    
    // Check explicit write permissions
    if (this.permissions.write.some(writeUserId => writeUserId.toString() === userId.toString())) {
        return true;
    }
    
    // No role-based override - only explicit permissions matter
    return false;
};

// Static method to find files with read permission
fileSchema.statics.findWithReadPermission = function(query, userId, userRoles = []) {
    const permissionQuery = {
        $or: [
            { owner: userId },
            { 'permissions.read': userId },
            { 'permissions.write': userId }
        ]
    };
    
    // Only file owners and explicitly granted users can read
    // No role-based override for file permissions
    return this.find({ ...query, ...permissionQuery });
};

// Static method to find one file with read permission
fileSchema.statics.findOneWithReadPermission = function(query, userId, userRoles = []) {
    const permissionQuery = {
        $or: [
            { owner: userId },
            { 'permissions.read': userId },
            { 'permissions.write': userId }
        ]
    };
    
    // Only file owners and explicitly granted users can read
    // No role-based override for file permissions
    return this.findOne({ ...query, ...permissionQuery });
};

// Static method to find files with write permission
fileSchema.statics.findWithWritePermission = function(query, userId, userRoles = []) {
    const permissionQuery = {
        $or: [
            { owner: userId },
            { 'permissions.write': userId }
        ]
    };
    
    // Only file owners and explicitly granted users can write
    // No role-based override for file permissions
    return this.find({ ...query, ...permissionQuery });
};

// Static method to find one file with write permission
fileSchema.statics.findOneWithWritePermission = function(query, userId, userRoles = []) {
    const permissionQuery = {
        $or: [
            { owner: userId },
            { 'permissions.write': userId }
        ]
    };
    
    // Only file owners and explicitly granted users can write
    // No role-based override for file permissions
    return this.findOne({ ...query, ...permissionQuery });
};

fileSchema.statics.buildTree = function(items, rootPath = '/') {
    if (!items || items.length === 0) return [];

    const nodeMap = {};
    const rootNodes = [];

    // Create nodes
    items.forEach(item => {
        const node = {
            id: item._id?.toString() || item.filePath,
            name: item.fileName || item.filePath.split('/').pop(),
            filePath: item.filePath,
            type: item.type,
            size: item.size,
            createdAt: item.createdAt,
            updatedAt: item.updatedAt,
            children: item.type === 'directory' ? [] : undefined
        };
        nodeMap[item.filePath] = node;
    });

    // Build hierarchical tree structure
    items.forEach(item => {
        const node = nodeMap[item.filePath];
        const isRoot = !item.parentPath || item.parentPath === rootPath;
        
        if (isRoot) {
            rootNodes.push(node);
        } else {
            const parent = nodeMap[item.parentPath];
            if (parent?.children) {
                parent.children.push(node);
            }
        }
    });

    return rootNodes;
};

// Static method to check if a file type is text-based
fileSchema.statics.isTextBasedFile = function(mimeType) {
    if (!mimeType) return false;
    
    const textMimeTypes = [
        'text/',
        'application/json',
        'application/javascript',
        'application/xml',
        'application/yaml',
        'application/x-yaml'
    ];
    
    return textMimeTypes.some(type => mimeType.startsWith(type));
};

// Check if model already exists to prevent recompilation errors
const File = mongoose.models.File || mongoose.model('File', fileSchema);

export default File;
