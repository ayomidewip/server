import {Router} from 'express';
import groupController from '../controllers/group.controller.js';
import * as authMiddleware from '../middleware/auth.middleware.js';
import {loadGroup, requireMembership, requireGroupRole} from '../middleware/group.middleware.js';
import {validateRequest} from '../middleware/validation.middleware.js';
import {groupSchemas} from '../models/schemas.js';
import {GROUP_ROLES} from '../models/group.model.js';
import {cacheResponse} from '../middleware/cache.middleware.js';

const router = Router();

// Define group routes for validation
router.validRoutes = [
    '/api/v1/groups',
    '/api/v1/groups/discover',
    '/api/v1/groups/:groupId',
    '/api/v1/groups/:groupId/members',
    '/api/v1/groups/:groupId/members/:userId',
    '/api/v1/groups/:groupId/join',
    '/api/v1/groups/:groupId/leave',
    '/api/v1/groups/:groupId/transfer',
    '/api/v1/groups/:groupId/files',
    '/api/v1/groups/:groupId/files/:fileId'
];

// All group routes require authentication
router.use(authMiddleware.verifyToken());

// List my groups
router.get('/', groupController.getMyGroups);

// Discover public groups
router.get('/discover', groupController.discoverGroups);

// Create a new group
router.post('/',
    validateRequest(groupSchemas.createGroup),
    groupController.createGroup
);

// --- Routes that require a loaded group ---

// Get group details
router.get('/:groupId',
    loadGroup,
    requireMembership,
    groupController.getGroup
);

// Update group details
router.patch('/:groupId',
    loadGroup,
    requireGroupRole(GROUP_ROLES.ADMIN),
    validateRequest(groupSchemas.updateGroup),
    groupController.updateGroup
);

// Delete a group
router.delete('/:groupId',
    loadGroup,
    requireGroupRole(GROUP_ROLES.OWNER),
    groupController.deleteGroup
);

// --- Member management ---

// Add member
router.post('/:groupId/members',
    loadGroup,
    requireGroupRole(GROUP_ROLES.ADMIN),
    validateRequest(groupSchemas.addMember),
    groupController.addMember
);

// Remove member
router.delete('/:groupId/members/:userId',
    loadGroup,
    requireMembership,
    groupController.removeMember
);

// Update member role
router.patch('/:groupId/members/:userId',
    loadGroup,
    requireGroupRole(GROUP_ROLES.ADMIN),
    validateRequest(groupSchemas.updateMemberRole),
    groupController.updateMemberRole
);

// Join a public group
router.post('/:groupId/join',
    loadGroup,
    groupController.joinGroup
);

// Leave a group
router.post('/:groupId/leave',
    loadGroup,
    requireMembership,
    groupController.leaveGroup
);

// Transfer ownership
router.patch('/:groupId/transfer',
    loadGroup,
    requireGroupRole(GROUP_ROLES.OWNER),
    validateRequest(groupSchemas.transferOwnership),
    groupController.transferOwnership
);

// --- Group file management ---

// Share file to group
router.post('/:groupId/files',
    loadGroup,
    requireGroupRole(GROUP_ROLES.CREATOR),
    validateRequest(groupSchemas.shareFile),
    groupController.shareFileToGroup
);

// Get group files (timeline)
router.get('/:groupId/files',
    loadGroup,
    requireMembership,
    groupController.getGroupFiles
);

// Remove file from group
router.delete('/:groupId/files/:fileId',
    loadGroup,
    requireMembership,
    groupController.removeFileFromGroup
);

// Update group file metadata (pin/caption)
router.patch('/:groupId/files/:fileId',
    loadGroup,
    requireGroupRole(GROUP_ROLES.ADMIN),
    validateRequest(groupSchemas.updateGroupFile),
    groupController.updateGroupFile
);

export default router;
