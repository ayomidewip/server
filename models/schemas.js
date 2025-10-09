import {Joi, password} from '../utils/validator.js';
import {ROLES} from '../config/rights.js';

// Get all valid roles as an array for validation
const VALID_ROLES = Object.values(ROLES);

/**
 * Standardize and validate schema for requests received
 */

export const authSchemas = {
    signup: Joi.object({
        firstName: Joi.string().min(2).max(50).required()
            .messages({
                'string.min': 'First name must be at least 2 characters',
                'string.max': 'First name cannot exceed 50 characters',
                'any.required': 'First name is required'
            }), lastName: Joi.string().min(2).max(50).required()
            .messages({
                'string.min': 'Last name must be at least 2 characters',
                'string.max': 'Last name cannot exceed 50 characters',
                'any.required': 'Last name is required'
            }), username: Joi.string().min(3).max(30).pattern(/^[a-zA-Z0-9_]+$/).required()
            .messages({
                'string.min': 'Username must be at least 3 characters',
                'string.max': 'Username cannot exceed 30 characters',
                'any.required': 'Username is required',
                'string.pattern.base': 'Username can only contain letters, numbers, and underscores'
            }), email: Joi.string().email().required()
            .messages({
                'string.email': 'Please enter a valid email address', 'any.required': 'Email is required'
            }), password: password().required()
            .messages({
                'password.complexity': 'Password must contain 8-30 characters with uppercase, lowercase, number and special character',
                'any.required': 'Password is required'
            }), roles: Joi.array().items(Joi.string().valid(...VALID_ROLES))
    }),

    login: Joi.object({
        identifier: Joi.string().required()
            .messages({
                'string.empty': 'Email or username is required', 'any.required': 'Email or username is required'
            }), password: Joi.string().required()
            .messages({
                'string.empty': 'Password is required', 'any.required': 'Password is required'
            })
    }),

    forgotPassword: Joi.object({
        email: Joi.string().email().required()
            .messages({
                'string.email': 'Please enter a valid email address', 'any.required': 'Email is required'
            })
    }), resetPassword: Joi.object({
        password: password().required()
            .messages({
                'password.complexity': 'Password must contain 8-30 characters with uppercase, lowercase, number and special character',
                'any.required': 'Password is required'
            }), confirmPassword: Joi.string().optional()
            .messages({
                'string.base': 'Confirm password must be a string'
            })
    }),

    refreshToken: Joi.object({
        // No body parameters needed - refresh token comes from cookies only
    }),

    logout: Joi.object({
        // No body parameters needed - logout uses token from cookies and middleware
    })
};

export const userSchemas = {
    userId: Joi.object({
        id: Joi.objectId().required()
    }),

    createUser: Joi.object({
        firstName: Joi.string().min(2).max(50).required()
            .messages({
                'string.min': 'First name must be at least 2 characters',
                'string.max': 'First name cannot exceed 50 characters',
                'any.required': 'First name is required'
            }), lastName: Joi.string().min(2).max(50).required()
            .messages({
                'string.min': 'Last name must be at least 2 characters',
                'string.max': 'Last name cannot exceed 50 characters',
                'any.required': 'Last name is required'
            }), username: Joi.string().min(3).max(30).pattern(/^[a-zA-Z0-9_]+$/).required()
            .messages({
                'string.min': 'Username must be at least 3 characters',
                'string.max': 'Username cannot exceed 30 characters',
                'any.required': 'Username is required',
                'string.pattern.base': 'Username can only contain letters, numbers, and underscores'
            }), email: Joi.string().email().required()
            .messages({
                'string.email': 'Please enter a valid email address', 'any.required': 'Email is required'
            }), password: password().required()
            .messages({
                'password.complexity': 'Password must contain 8-30 characters with uppercase, lowercase, number and special character',
                'any.required': 'Password is required'
            }), profilePhoto: Joi.string(), roles: Joi.array().items(Joi.string().valid(...VALID_ROLES))
    }), updateUser: Joi.object({
        firstName: Joi.string().min(2).max(50),
        lastName: Joi.string().min(2).max(50),
        username: Joi.string().min(3).max(30).pattern(/^[a-zA-Z0-9_]+$/),
        email: Joi.string().email(),
        profilePhoto: Joi.string(),
        roles: Joi.array().items(Joi.string().valid(...VALID_ROLES)),
        active: Joi.boolean()
    }).min(1),

    changePassword: Joi.object({
        currentPassword: Joi.string().optional()
            .messages({
                'string.base': 'Current password must be a string'
            }),
        newPassword: password()
            .required()
            .messages({
                'password.complexity': 'Password must contain 8-30 characters with uppercase, lowercase, number and special character',
                'any.required': 'New password is required'
            })
    })
};

// Filter validation schemas for stats endpoints
export const filterSchemas = {
    // Common filter parameters
    common: Joi.object({
        // Date range filters
        startDate: Joi.date().iso()
            .messages({
                'date.format': 'Start date must be in ISO format (YYYY-MM-DD or YYYY-MM-DDTHH:mm:ss.sssZ)'
            }),
        endDate: Joi.date().iso().min(Joi.ref('startDate'))
            .messages({
                'date.format': 'End date must be in ISO format (YYYY-MM-DD or YYYY-MM-DDTHH:mm:ss.sssZ)',
                'date.min': 'End date must be after start date'
            }),

        // Time period shortcuts
        period: Joi.string().valid('1h', '24h', '1d', '7d', '1w', '30d', '1m', '90d', '3m', '1y')
            .messages({
                'any.only': 'Period must be one of: 1h, 24h, 1d, 7d, 1w, 30d, 1m, 90d, 3m, 1y'
            }),

        // Pagination
        page: Joi.number().integer().min(1).default(1)
            .messages({
                'number.min': 'Page must be at least 1'
            }),
        limit: Joi.number().integer().min(1).max(1000).default(50)
            .messages({
                'number.min': 'Limit must be at least 1',
                'number.max': 'Limit cannot exceed 1000'
            }),

        // Sorting
        sortBy: Joi.string().max(50)
            .messages({
                'string.max': 'Sort field name cannot exceed 50 characters'
            }),
        sortOrder: Joi.string().valid('asc', 'desc').default('desc')
            .messages({
                'any.only': 'Sort order must be either "asc" or "desc"'
            }),

        // Search
        search: Joi.string().max(200)
            .messages({
                'string.max': 'Search term cannot exceed 200 characters'
            }),

        // Grouping
        groupBy: Joi.string().max(200)
            .messages({
                'string.max': 'Group by fields cannot exceed 200 characters'
            })
    }),

    // User-specific filters
    users: Joi.object({
        // User status
        active: Joi.boolean()
            .messages({
                'boolean.base': 'Active filter must be true or false'
            }),

        // User roles
        roles: Joi.string().pattern(/^[A-Z_,\s]+$/)
            .messages({
                'string.pattern.base': 'Roles must contain only uppercase letters, underscores, commas, and spaces'
            }),

        // User ID
        userId: Joi.objectId()
            .messages({
                'objectId.invalid': 'User ID must be a valid MongoDB ObjectID'
            })
    }),

    // File-specific filters
    files: Joi.object({
        // File type
        fileType: Joi.string().max(50)
            .messages({
                'string.max': 'File type cannot exceed 50 characters'
            }),

        // MIME type
        mimeType: Joi.string().max(100)
            .messages({
                'string.max': 'MIME type cannot exceed 100 characters'
            }),

        // File size range
        minSize: Joi.number().integer().min(0)
            .messages({
                'number.min': 'Minimum size cannot be negative'
            }),
        maxSize: Joi.number().integer().min(Joi.ref('minSize'))
            .messages({
                'number.min': 'Maximum size must be greater than or equal to minimum size'
            }),

        // Owner
        owner: Joi.objectId()
            .messages({
                'objectId.invalid': 'Owner ID must be a valid MongoDB ObjectID'
            }),
        createdBy: Joi.objectId()
            .messages({
                'objectId.invalid': 'Created by ID must be a valid MongoDB ObjectID'
            })
    }),

    // Log-specific filters
    logs: Joi.object({
        // HTTP status codes
        statusCode: Joi.alternatives().try(
            Joi.number().integer().min(100).max(599),
            Joi.string().pattern(/^\d{3}(-\d{3})?(,\d{3}(-\d{3})?)*$/)
        ).messages({
            'number.min': 'Status code must be between 100 and 599',
            'number.max': 'Status code must be between 100 and 599',
            'string.pattern.base': 'Status code must be a valid HTTP status code, range (e.g., 400-499), or comma-separated list'
        }),

        // HTTP methods
        method: Joi.string().pattern(/^[A-Z,\s]+$/)
            .messages({
                'string.pattern.base': 'Method must contain only uppercase letters, commas, and spaces'
            }),

        // Log levels
        level: Joi.string().pattern(/^[a-z,\s]+$/)
            .messages({
                'string.pattern.base': 'Level must contain only lowercase letters, commas, and spaces'
            }),

        // Response time range
        minResponseTime: Joi.number().min(0)
            .messages({
                'number.min': 'Minimum response time cannot be negative'
            }),
        maxResponseTime: Joi.number().min(Joi.ref('minResponseTime'))
            .messages({
                'number.min': 'Maximum response time must be greater than or equal to minimum response time'
            }),

        // IP address
        ip: Joi.alternatives().try(
            Joi.string().ip(),
            Joi.string().pattern(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(,\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})*$/)
        ).messages({
            'string.ip': 'IP must be a valid IP address',
            'string.pattern.base': 'IP must be a valid IP address or comma-separated list of IP addresses'
        }),

        // URL pattern
        url: Joi.string().max(500)
            .messages({
                'string.max': 'URL pattern cannot exceed 500 characters'
            })
    }),

    // Combined filter schema for all endpoints
    all: Joi.object().concat(
        Joi.object().keys({
            // Include all common filters
            startDate: Joi.date().iso(),
            endDate: Joi.date().iso().min(Joi.ref('startDate')),
            period: Joi.string().valid('1h', '24h', '1d', '7d', '1w', '30d', '1m', '90d', '3m', '1y'),
            page: Joi.number().integer().min(1).default(1),
            limit: Joi.number().integer().min(1).max(1000).default(50),
            sortBy: Joi.string().max(50),
            sortOrder: Joi.string().valid('asc', 'desc').default('desc'),
            search: Joi.string().max(200),
            groupBy: Joi.string().max(200),

            // All specific filters (will be ignored if not applicable)
            active: Joi.boolean(),
            roles: Joi.string().pattern(/^[A-Z_,\s]+$/),
            userId: Joi.objectId(),
            fileType: Joi.string().max(50),
            mimeType: Joi.string().max(100),
            minSize: Joi.number().integer().min(0),
            maxSize: Joi.number().integer(),
            owner: Joi.objectId(),
            createdBy: Joi.objectId(),
            statusCode: Joi.alternatives().try(
                Joi.number().integer().min(100).max(599),
                Joi.string().pattern(/^\d{3}(-\d{3})?(,\d{3}(-\d{3})?)*$/)
            ),
            method: Joi.string().pattern(/^[A-Z,\s]+$/),
            level: Joi.string().pattern(/^[a-z,\s]+$/),
            minResponseTime: Joi.number().min(0),
            maxResponseTime: Joi.number(),
            ip: Joi.alternatives().try(
                Joi.string().ip(),
                Joi.string().pattern(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(,\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})*$/)
            ),
            url: Joi.string().max(500)
        })
    ).pattern(/^filter_/, Joi.alternatives().try(
        Joi.string(),
        Joi.number(),
        Joi.boolean(),
        Joi.objectId()
    ))
};

// Statistics schemas
export const statsSchemas = {
    userStats: Joi.object({
        // Time period filters
        period: Joi.string().pattern(/^\d+[dhwmy]$/),  // e.g., 30d, 12h, 2w, 6m, 1y
        startDate: Joi.date(),
        endDate: Joi.date(),

        // Pagination
        page: Joi.number().integer().min(1),
        limit: Joi.number().integer().min(1).max(100),

        // Sorting
        sortBy: Joi.string().valid('createdAt', 'lastLogin', 'activityCount', 'fileCount'),
        sortOrder: Joi.string().valid('asc', 'desc'),

        // User filters
        active: Joi.boolean(),
        roles: Joi.string().pattern(/^[A-Z_,\s]+$/),

        // Grouping and analysis
        groupBy: Joi.string().valid('role', 'active', 'day', 'week', 'month'),
        includeInactive: Joi.boolean()
    }),

    userStatsFields: Joi.object({
        // Specific fields to retrieve (dot notation)
        fields: Joi.string().pattern(/^[a-zA-Z_][a-zA-Z0-9_.]*(?:,[a-zA-Z_][a-zA-Z0-9_.]*)*$/),

        // Time period filters (same as userStats)
        period: Joi.string().pattern(/^\d+[dhwmy]$/),
        startDate: Joi.date(),
        endDate: Joi.date(),

        // Pagination for array fields
        page: Joi.number().integer().min(1),
        limit: Joi.number().integer().min(1).max(100),

        // Sorting for array fields
        sortBy: Joi.string().valid('timestamp', 'createdAt', 'count', 'size'),
        sortOrder: Joi.string().valid('asc', 'desc')
    })
};

// Application statistics schemas
export const appStatsSchemas = {
    overview: Joi.object({
        // Time period filters
        period: Joi.string().pattern(/^\d+[dhwmy]$/),  // e.g., 30d, 12h, 2w, 6m, 1y
        startDate: Joi.date(),
        endDate: Joi.date(),

        // Data inclusion options
        includeUsers: Joi.boolean().default(true),
        includeFiles: Joi.boolean().default(true),
        includeLogs: Joi.boolean().default(true),
        includeCache: Joi.boolean().default(true),
        includeEmail: Joi.boolean().default(true)
    }),

    performance: Joi.object({
        // Time period filters
        period: Joi.string().pattern(/^\d+[dhwmy]$/),  // e.g., 7d, 24h, 1w
        startDate: Joi.date(),
        endDate: Joi.date(),

        // Performance analysis options
        includeEndpoints: Joi.boolean().default(true),
        includeTrafficPattern: Joi.boolean().default(true),
        endpointLimit: Joi.number().integer().min(1).max(50).default(10),

        // Grouping options
    })
};

// File management schemas
export const fileSchemas = {
    getFiles: Joi.object({
        page: Joi.number().integer().min(1).default(1),
        limit: Joi.alternatives().try(Joi.number().integer().min(1).max(100), Joi.string().valid('all'), Joi.number().valid(-1)).default(10),
        fileType: Joi.string().max(10),
        tags: Joi.string().max(50),
        search: Joi.string().max(100),
        // Size filtering
        minSize: Joi.number().integer().min(0),
        maxSize: Joi.number().integer().min(0),
        // Date filtering
        startDate: Joi.date().iso(),
        endDate: Joi.date().iso(),
        period: Joi.string().valid('1h', '24h', '7d', '30d', '90d', '1y'),
        // Sorting
        sortBy: Joi.string().valid('fileName', 'fileType', 'size', 'createdAt', 'updatedAt', 'version'),
        sortOrder: Joi.string().valid('asc', 'desc', 'ascending', 'descending'),
        // Custom field filters (allow filter_* pattern)
        customFilters: Joi.any()
    }).unknown(true), // Allow unknown keys for custom filters starting with filter_

    createFile: Joi.object({
        filePath: Joi.filePath().required()
            .messages({
                'any.required': 'File path is required'
            }),
        content: Joi.string().allow('').default(''),
        description: Joi.string().allow('').max(500),
        tags: Joi.array().items(Joi.string().trim().max(50)).max(10),
        permissions: Joi.object({
            read: Joi.array().items(Joi.objectId()),
            write: Joi.array().items(Joi.objectId())
        })
    }),

    getFileById: Joi.object({
        version: Joi.number().integer().min(0)
    }),

    getFileContent: Joi.object({
        version: Joi.number().integer().min(0),
        includeAutosave: Joi.string().valid('true', 'false')
    }),

    saveFile: Joi.object({
        content: Joi.string().allow('').required()
            .messages({
                'any.required': 'Content is required to save file'
            }),
        description: Joi.string().min(0).max(500)
    }),

    publishFile: Joi.object({
        message: Joi.string().max(200)
            .default('Published version')
            .messages({
                'string.max': 'Message cannot exceed 200 characters'
            })
    }),

    // updateFile, deleteFile, patchFile schemas removed - operations now use WebSocket

    autoSave: Joi.object({
        content: Joi.string().allow('').required()
            .messages({
                'any.required': 'Content is required for auto-save'
            })
    }),

    getDirectory: Joi.object({
        path: Joi.string().pattern(/^\/([a-zA-Z0-9._/-]*)?$/).default('/')
            .messages({
                'string.pattern.base': 'Directory path must be a valid filesystem path starting with /'
            })
    }),

    checkPath: Joi.object({
        path: Joi.string().pattern(/^\/([a-zA-Z0-9._/-]*[a-zA-Z0-9._-])?$/).required()
            .messages({
                'string.pattern.base': 'File path must be a valid filesystem path starting with /',
                'any.required': 'File path is required'
            })
    }),

    createDirectory: Joi.object({
        dirPath: Joi.string().pattern(/^\/([a-zA-Z0-9._/-]+)?$/).required()
            .messages({
                'string.pattern.base': 'Directory path must be a valid filesystem path starting with /',
                'any.required': 'Directory path is required'
            }),
        description: Joi.string().max(500).allow('')
    }),

    getDirectoryTree: Joi.object({
        rootPath: Joi.string().pattern(/^\/([a-zA-Z0-9._/-]*)?$/).default('/'),
        includeFiles: Joi.string().valid('true', 'false').default('true'),
        format: Joi.string().valid('array', 'object').default('object')
            .messages({
                'any.only': 'Format must be either "array" or "object"'
            })
    }),

    getDirectoryContents: Joi.object({
        filePath: Joi.string().pattern(/^\/([a-zA-Z0-9._/-]*[a-zA-Z0-9._-])?$/).required()
            .messages({
                'string.pattern.base': 'File path must be a valid filesystem path starting with /',
                'any.required': 'File path is required'
            }),
        sortBy: Joi.string().valid('fileName', 'fileType', 'size', 'createdAt', 'updatedAt').default('fileName'),
        sortOrder: Joi.string().valid('asc', 'desc').default('asc'),
        fileType: Joi.string().valid('file', 'directory')
    }),

    moveFile: Joi.object({
        sourcePath: Joi.filePath().required()
            .messages({
                'any.required': 'Source path is required'
            }),
        destinationPath: Joi.filePath().required()
            .messages({
                'any.required': 'Destination path is required'
            })
    }),

    copyFile: Joi.object({
        sourcePath: Joi.filePath().required()
            .messages({
                'any.required': 'Source path is required'
            }),
        destinationPath: Joi.filePath().required()
            .messages({
                'any.required': 'Destination path is required'
            }),
        includeVersionHistory: Joi.boolean().default(false)
    }),

    renameFile: Joi.object({
        newName: Joi.string().min(1).max(255)
            .pattern(/^[^\\/:*?"<>|]+$/)
            .pattern(/^(?!\.\.)(?!.*\.\.)[\s\S]+$/)
            .required()
            .messages({
                'string.min': 'New name cannot be empty',
                'string.max': 'New name cannot exceed 255 characters',
                'string.pattern.base': 'New name contains invalid characters',
                'any.required': 'New name is required'
            })
    }),

    bulkOperations: Joi.object({
        operation: Joi.string().valid('delete', 'addTags', 'updatePermissions').required()
            .messages({
                'any.required': 'Operation is required',
                'any.only': 'Operation must be one of: delete, addTags, updatePermissions'
            }),
        filePaths: Joi.array().items(
            Joi.string().pattern(/^\/([a-zA-Z0-9._/-]*[a-zA-Z0-9._-])?$/)
        ).min(1).max(100).required()
            .messages({
                'array.min': 'At least one file path is required',
                'array.max': 'Maximum 100 file paths allowed per operation',
                'any.required': 'File paths array is required'
            }),
        options: Joi.object({
            force: Joi.boolean().default(false),
            tags: Joi.array().items(Joi.string().max(50)).max(10),
            permissions: Joi.object({
                read: Joi.array().items(Joi.objectId()),
                write: Joi.array().items(Joi.objectId())
            })
        }).default({})
    }),

    shareFile: Joi.object({
        userIds: Joi.alternatives().try(
            Joi.array().items(Joi.objectId()).min(1).max(50),
            Joi.objectId()
        ).required()
            .messages({
                'any.required': 'userIds is required',
                'array.min': 'At least one user ID is required',
                'array.max': 'Maximum 50 users can be shared with at once'
            }),
        permission: Joi.string().valid('read', 'write').default('read')
            .messages({
                'any.only': 'Permission must be either "read" or "write"'
            })
    }),

    unshareFile: Joi.object({
        userIds: Joi.alternatives().try(
            Joi.array().items(Joi.objectId()).min(1).max(50),
            Joi.objectId()
        ).required()
            .messages({
                'any.required': 'userIds is required',
                'array.min': 'At least one user ID is required',
                'array.max': 'Maximum 50 users can be processed at once'
            }),
        permission: Joi.string().valid('read', 'write', 'both').default('both')
            .messages({
                'any.only': 'Permission must be either "read", "write", or "both"'
            })
    })
};

// File parameter schemas (for URL params)
export const fileParamSchemas = {
    filePath: Joi.object({
        filePath: Joi.filePath().required()
            .messages({
                'any.required': 'File path parameter is required'
            })
    }),

    fileId: Joi.object({
        fileId: Joi.string().required()
            .messages({
                'any.required': 'File ID parameter is required'
            })
    }),

    filePathWithVersion: Joi.object({
        filePath: Joi.filePath().required()
            .messages({
                'any.required': 'File path parameter is required'
            }),
        versionNumber: Joi.number().integer().min(1).required()
            .messages({
                'any.required': 'Version number parameter is required',
                'number.base': 'Version number must be a number',
                'number.integer': 'Version number must be an integer',
                'number.min': 'Version number must be at least 1'
            })
    })
};

// Two-Factor Authentication Schemas
export const twoFactorSchemas = {
    verifySetup: Joi.object({
        token: Joi.string().length(6).pattern(/^\d+$/).required()
            .messages({
                'string.length': '2FA token must be 6 digits',
                'string.pattern.base': '2FA token must contain only digits',
                'any.required': '2FA token is required'
            })
    }),

    disable2FA: Joi.object({
        password: Joi.string().required()
            .messages({
                'any.required': 'Password is required to disable 2FA'
            }),
        token: Joi.string().required()
            .messages({
                'any.required': '2FA token is required to disable 2FA'
            })
    }),

    generateBackupCodes: Joi.object({
        password: Joi.string().required()
            .messages({
                'any.required': 'Password is required'
            }),
        token: Joi.string().required()
            .messages({
                'any.required': '2FA token is required'
            })
    })
};

// Email Verification Schemas
export const emailVerificationSchemas = {
    sendVerification: Joi.object({
        email: Joi.string().email().optional()
            .messages({
                'string.email': 'Please provide a valid email address'
            })
    }),

    verifyEmail: Joi.object({
        token: Joi.string().length(64).required()
            .messages({
                'string.length': 'Verification token must be 64 characters',
                'any.required': 'Verification token is required'
            })
    })
};

// Update auth schemas to include 2FA token
authSchemas.login = Joi.object({
    identifier: Joi.string().required()
        .messages({
            'string.empty': 'Email or username is required',
            'any.required': 'Email or username is required'
        }),
    password: Joi.string().required()
        .messages({
            'string.empty': 'Password is required',
            'any.required': 'Password is required'
        }),
    twoFactorToken: Joi.string().optional()
        .messages({
            'string.base': '2FA token must be a string'
        })
});
