import Group, {GROUP_ROLES, GROUP_ROLE_HIERARCHY} from '../models/group.model.js';
import File from '../models/file.model.js';
import User from '../models/user.model.js';
import {asyncHandler} from '../middleware/app.middleware.js';
import {AppError} from '../middleware/error.middleware.js';
import {cache} from '../middleware/cache.middleware.js';
import logger from '../utils/app.logger.js';
import {sanitizeHtmlInput} from '../utils/sanitize.js';

const groupController = {
    // =========================================================================
    // GROUP CRUD
    // =========================================================================

    /**
     * @desc    Create a new group
     * @route   POST /api/v1/groups
     * @access  Authenticated
     */
    createGroup: asyncHandler(async (req, res) => {
        const {name, description, privacy} = req.body;
        const userId = req.user.id;

        const group = await Group.create({
            name: sanitizeHtmlInput(name),
            description: description ? sanitizeHtmlInput(description) : undefined,
            privacy: privacy || 'private',
            createdBy: userId,
            members: [{user: userId, role: GROUP_ROLES.OWNER}]
        });

        await cache.del(`groups:user:${userId}`);

        logger.info(`[Group] Group "${group.name}" created by ${userId}`);

        res.status(201).json({
            success: true,
            data: group
        });
    }),

    /**
     * @desc    Get group by ID
     * @route   GET /api/v1/groups/:groupId
     * @access  Members / public groups
     */
    getGroup: asyncHandler(async (req, res, next) => {
        const group = req.group; // set by loadGroup middleware

        // Populate member user details
        await group.populate('members.user', 'firstName lastName username email profilePhoto');

        res.status(200).json({
            success: true,
            data: group
        });
    }),

    /**
     * @desc    Update group details (name, description, privacy, avatar)
     * @route   PATCH /api/v1/groups/:groupId
     * @access  Group ADMIN+
     */
    updateGroup: asyncHandler(async (req, res, next) => {
        const group = req.group;
        const {name, description, privacy, avatar} = req.body;

        if (name !== undefined) group.name = sanitizeHtmlInput(name);
        if (description !== undefined) group.description = sanitizeHtmlInput(description);
        if (privacy !== undefined) group.privacy = privacy;
        if (avatar !== undefined) group.avatar = avatar;

        await group.save();
        await cache.del(`groups:detail:${group._id}`);

        res.status(200).json({
            success: true,
            data: group
        });
    }),

    /**
     * @desc    Delete a group
     * @route   DELETE /api/v1/groups/:groupId
     * @access  Group OWNER only
     */
    deleteGroup: asyncHandler(async (req, res, next) => {
        const group = req.group;
        const userId = req.user.id;

        if (!group.hasMinRole(userId, GROUP_ROLES.OWNER)) {
            return next(new AppError('Only the group owner can delete the group', 403));
        }

        // Invalidate caches for all members
        const memberIds = group.members.map(m => m.user);
        await Group.findByIdAndDelete(group._id);

        await Promise.all(
            memberIds.map(id => cache.del(`groups:user:${id}`))
        );
        await cache.del(`groups:detail:${group._id}`);

        logger.info(`[Group] Group "${group.name}" deleted by ${userId}`);

        res.status(200).json({
            success: true,
            message: 'Group deleted successfully'
        });
    }),

    /**
     * @desc    List groups the current user belongs to
     * @route   GET /api/v1/groups
     * @access  Authenticated
     */
    getMyGroups: asyncHandler(async (req, res) => {
        const userId = req.user.id;
        const page = Math.max(1, parseInt(req.query.page, 10) || 1);
        const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 20));
        const skip = (page - 1) * limit;

        const filter = {'members.user': userId};
        const [groups, total] = await Promise.all([
            Group.find(filter)
                .sort({updatedAt: -1})
                .skip(skip)
                .limit(limit)
                .populate('members.user', 'firstName lastName username profilePhoto'),
            Group.countDocuments(filter)
        ]);

        res.status(200).json({
            success: true,
            data: groups,
            pagination: {page, limit, total, pages: Math.ceil(total / limit)}
        });
    }),

    /**
     * @desc    Discover public groups
     * @route   GET /api/v1/groups/discover
     * @access  Authenticated
     */
    discoverGroups: asyncHandler(async (req, res) => {
        const page = Math.max(1, parseInt(req.query.page, 10) || 1);
        const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 20));
        const skip = (page - 1) * limit;
        const search = req.query.search;

        const filter = {privacy: 'public'};
        if (search) {
            // Escape regex special characters to prevent ReDoS / injection
            const escaped = search.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            filter.name = {$regex: escaped, $options: 'i'};
        }

        const [groups, total] = await Promise.all([
            Group.find(filter)
                .sort({memberCount: -1, createdAt: -1})
                .skip(skip)
                .limit(limit)
                .select('name description avatar privacy memberCount fileCount createdAt'),
            Group.countDocuments(filter)
        ]);

        res.status(200).json({
            success: true,
            data: groups,
            pagination: {page, limit, total, pages: Math.ceil(total / limit)}
        });
    }),

    // =========================================================================
    // MEMBER MANAGEMENT
    // =========================================================================

    /**
     * @desc    Add a member to a group
     * @route   POST /api/v1/groups/:groupId/members
     * @access  Group ADMIN+
     */
    addMember: asyncHandler(async (req, res, next) => {
        const group = req.group;
        const {userId, role} = req.body;
        const actorRole = group.getMemberRole(req.user.id);

        // Verify target user exists
        const targetUser = await User.findById(userId).select('_id');
        if (!targetUser) {
            return next(new AppError('User not found', 404));
        }

        // Check if already a member
        if (group.isMember(userId)) {
            return next(new AppError('User is already a member of this group', 400));
        }

        // Only owners can add admins; admins can add creators/members
        const assignedRole = role || GROUP_ROLES.MEMBER;
        if (GROUP_ROLE_HIERARCHY[assignedRole] >= GROUP_ROLE_HIERARCHY[actorRole]) {
            return next(new AppError('You cannot assign a role equal to or higher than your own', 403));
        }

        group.members.push({user: userId, role: assignedRole});
        await group.save();

        await Promise.all([
            cache.del(`groups:detail:${group._id}`),
            cache.del(`groups:user:${userId}`)
        ]);

        logger.info(`[Group] User ${userId} added to group ${group._id} as ${assignedRole}`);

        res.status(200).json({
            success: true,
            message: 'Member added successfully'
        });
    }),

    /**
     * @desc    Remove a member from a group
     * @route   DELETE /api/v1/groups/:groupId/members/:userId
     * @access  Group ADMIN+ or self
     */
    removeMember: asyncHandler(async (req, res, next) => {
        const group = req.group;
        const targetUserId = req.params.userId;
        const actorId = req.user.id;

        const targetMember = group.members.find(m => m.user.equals(targetUserId));
        if (!targetMember) {
            return next(new AppError('User is not a member of this group', 404));
        }

        // Owner cannot be removed
        if (targetMember.role === GROUP_ROLES.OWNER) {
            return next(new AppError('The group owner cannot be removed', 403));
        }

        // Self-removal is always allowed (except owner)
        const isSelf = actorId === targetUserId;
        if (!isSelf) {
            const actorRole = group.getMemberRole(actorId);
            if (GROUP_ROLE_HIERARCHY[actorRole] <= GROUP_ROLE_HIERARCHY[targetMember.role]) {
                return next(new AppError('You cannot remove a member with equal or higher role', 403));
            }
        }

        group.members = group.members.filter(m => !m.user.equals(targetUserId));
        await group.save();

        await Promise.all([
            cache.del(`groups:detail:${group._id}`),
            cache.del(`groups:user:${targetUserId}`)
        ]);

        res.status(200).json({
            success: true,
            message: isSelf ? 'You have left the group' : 'Member removed successfully'
        });
    }),

    /**
     * @desc    Update a member's role
     * @route   PATCH /api/v1/groups/:groupId/members/:userId
     * @access  Group OWNER (for admin promotion), ADMIN+ for lower roles
     */
    updateMemberRole: asyncHandler(async (req, res, next) => {
        const group = req.group;
        const targetUserId = req.params.userId;
        const {role: newRole} = req.body;
        const actorId = req.user.id;
        const actorRole = group.getMemberRole(actorId);

        if (!Object.values(GROUP_ROLES).includes(newRole)) {
            return next(new AppError('Invalid role', 400));
        }

        const targetMember = group.members.find(m => m.user.equals(targetUserId));
        if (!targetMember) {
            return next(new AppError('User is not a member of this group', 404));
        }

        // Cannot change owner's role
        if (targetMember.role === GROUP_ROLES.OWNER) {
            return next(new AppError('Cannot change the owner\'s role', 403));
        }

        // Cannot promote to equal or higher than your own role
        if (GROUP_ROLE_HIERARCHY[newRole] >= GROUP_ROLE_HIERARCHY[actorRole]) {
            return next(new AppError('You cannot assign a role equal to or higher than your own', 403));
        }

        targetMember.role = newRole;
        await group.save();

        await cache.del(`groups:detail:${group._id}`);

        res.status(200).json({
            success: true,
            message: `Member role updated to ${newRole}`
        });
    }),

    /**
     * @desc    Join a public group
     * @route   POST /api/v1/groups/:groupId/join
     * @access  Authenticated
     */
    joinGroup: asyncHandler(async (req, res, next) => {
        const group = req.group;
        const userId = req.user.id;

        if (group.privacy !== 'public') {
            return next(new AppError('This group is private. You need an invite to join.', 403));
        }

        if (group.isMember(userId)) {
            return next(new AppError('You are already a member of this group', 400));
        }

        group.members.push({user: userId, role: GROUP_ROLES.MEMBER});
        await group.save();

        await Promise.all([
            cache.del(`groups:detail:${group._id}`),
            cache.del(`groups:user:${userId}`)
        ]);

        res.status(200).json({
            success: true,
            message: 'Joined group successfully'
        });
    }),

    /**
     * @desc    Leave a group (alias for self-removal)
     * @route   POST /api/v1/groups/:groupId/leave
     * @access  Authenticated member
     */
    leaveGroup: asyncHandler(async (req, res, next) => {
        const group = req.group;
        const userId = req.user.id;

        const member = group.members.find(m => m.user.equals(userId));
        if (!member) {
            return next(new AppError('You are not a member of this group', 400));
        }

        if (member.role === GROUP_ROLES.OWNER) {
            return next(new AppError('Group owners cannot leave. Transfer ownership or delete the group.', 403));
        }

        group.members = group.members.filter(m => !m.user.equals(userId));
        await group.save();

        await Promise.all([
            cache.del(`groups:detail:${group._id}`),
            cache.del(`groups:user:${userId}`)
        ]);

        res.status(200).json({
            success: true,
            message: 'You have left the group'
        });
    }),

    /**
     * @desc    Transfer group ownership
     * @route   PATCH /api/v1/groups/:groupId/transfer
     * @access  Group OWNER only
     */
    transferOwnership: asyncHandler(async (req, res, next) => {
        const group = req.group;
        const actorId = req.user.id;
        const {userId: newOwnerId} = req.body;

        if (!group.hasMinRole(actorId, GROUP_ROLES.OWNER)) {
            return next(new AppError('Only the group owner can transfer ownership', 403));
        }

        const newOwnerMember = group.members.find(m => m.user.equals(newOwnerId));
        if (!newOwnerMember) {
            return next(new AppError('Target user must be a member of the group', 400));
        }

        // Demote current owner to admin, promote new owner
        const currentOwner = group.members.find(m => m.user.equals(actorId));
        currentOwner.role = GROUP_ROLES.ADMIN;
        newOwnerMember.role = GROUP_ROLES.OWNER;
        await group.save();

        await cache.del(`groups:detail:${group._id}`);

        logger.info(`[Group] Ownership of group ${group._id} transferred from ${actorId} to ${newOwnerId}`);

        res.status(200).json({
            success: true,
            message: 'Ownership transferred successfully'
        });
    }),

    // =========================================================================
    // GROUP FILE MANAGEMENT
    // =========================================================================

    /**
     * @desc    Share/upload a file to the group timeline
     * @route   POST /api/v1/groups/:groupId/files
     * @access  Group CREATOR+
     */
    shareFileToGroup: asyncHandler(async (req, res, next) => {
        const group = req.group;
        const userId = req.user.id;
        const {fileId, caption} = req.body;

        // Verify file exists
        const file = await File.findById(fileId).select('_id owner fileName');
        if (!file) {
            return next(new AppError('File not found', 404));
        }

        // Check if file is already shared to this group
        const alreadyShared = group.files.some(f => f.file.equals(fileId));
        if (alreadyShared) {
            return next(new AppError('File is already shared to this group', 400));
        }

        group.files.push({
            file: fileId,
            sharedBy: userId,
            caption: caption ? sanitizeHtmlInput(caption) : undefined
        });
        await group.save();

        await cache.del(`groups:detail:${group._id}`);
        await cache.del(`groups:files:${group._id}`);

        logger.info(`[Group] File ${fileId} shared to group ${group._id} by ${userId}`);

        res.status(200).json({
            success: true,
            message: 'File shared to group successfully'
        });
    }),

    /**
     * @desc    Get files shared in a group (timeline)
     * @route   GET /api/v1/groups/:groupId/files
     * @access  Group MEMBER+
     */
    getGroupFiles: asyncHandler(async (req, res) => {
        const group = req.group;
        const page = Math.max(1, parseInt(req.query.page, 10) || 1);
        const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 20));
        const skip = (page - 1) * limit;

        // Sort: pinned first, then by sharedAt desc
        const sortedFiles = [...group.files].sort((a, b) => {
            if (a.pinned && !b.pinned) return -1;
            if (!a.pinned && b.pinned) return 1;
            return new Date(b.sharedAt) - new Date(a.sharedAt);
        });

        const total = sortedFiles.length;
        const paginatedFiles = sortedFiles.slice(skip, skip + limit);

        // Populate file and sharedBy details
        const fileIds = paginatedFiles.map(f => f.file);
        const userIds = [...new Set(paginatedFiles.map(f => f.sharedBy.toString()))];

        const [files, users] = await Promise.all([
            File.find({_id: {$in: fileIds}}).select('fileName filePath type mimeType size owner tags description createdAt'),
            User.find({_id: {$in: userIds}}).select('firstName lastName username profilePhoto')
        ]);

        const fileMap = new Map(files.map(f => [f._id.toString(), f]));
        const userMap = new Map(users.map(u => [u._id.toString(), u]));

        const data = paginatedFiles.map(gf => ({
            file: fileMap.get(gf.file.toString()) || null,
            sharedBy: userMap.get(gf.sharedBy.toString()) || null,
            sharedAt: gf.sharedAt,
            caption: gf.caption,
            pinned: gf.pinned
        })).filter(item => item.file !== null);

        res.status(200).json({
            success: true,
            data,
            pagination: {page, limit, total, pages: Math.ceil(total / limit)}
        });
    }),

    /**
     * @desc    Remove a file from a group
     * @route   DELETE /api/v1/groups/:groupId/files/:fileId
     * @access  Group OWNER, or the user who shared the file
     */
    removeFileFromGroup: asyncHandler(async (req, res, next) => {
        const group = req.group;
        const {fileId} = req.params;
        const userId = req.user.id;

        const groupFile = group.files.find(f => f.file.equals(fileId));
        if (!groupFile) {
            return next(new AppError('File not found in this group', 404));
        }

        // Permission: group owner can delete any, or the user who shared it
        const isGroupOwner = group.hasMinRole(userId, GROUP_ROLES.OWNER);
        const isSharer = groupFile.sharedBy.equals(userId);

        if (!isGroupOwner && !isSharer) {
            return next(new AppError('Only the group owner or the user who shared the file can remove it', 403));
        }

        group.files = group.files.filter(f => !f.file.equals(fileId));
        await group.save();

        await cache.del(`groups:detail:${group._id}`);
        await cache.del(`groups:files:${group._id}`);

        res.status(200).json({
            success: true,
            message: 'File removed from group'
        });
    }),

    /**
     * @desc    Update group file metadata (pin, caption)
     * @route   PATCH /api/v1/groups/:groupId/files/:fileId
     * @access  Group ADMIN+
     */
    updateGroupFile: asyncHandler(async (req, res, next) => {
        const group = req.group;
        const {fileId} = req.params;
        const {caption, pinned} = req.body;

        const groupFile = group.files.find(f => f.file.equals(fileId));
        if (!groupFile) {
            return next(new AppError('File not found in this group', 404));
        }

        if (caption !== undefined) groupFile.caption = sanitizeHtmlInput(caption);
        if (pinned !== undefined) groupFile.pinned = pinned;

        await group.save();
        await cache.del(`groups:detail:${group._id}`);

        res.status(200).json({
            success: true,
            message: 'Group file updated'
        });
    })
};

export default groupController;
