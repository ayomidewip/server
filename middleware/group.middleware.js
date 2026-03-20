import Group, {GROUP_ROLES} from '../models/group.model.js';
import {asyncHandler} from './app.middleware.js';
import {AppError} from './error.middleware.js';

/**
 * Load a group by :groupId param and attach to req.group
 * Also verifies the requesting user has access:
 *   - Private groups: user must be a member
 *   - Public groups: anyone can view, but modifications still require membership
 */
export const loadGroup = asyncHandler(async (req, res, next) => {
    const {groupId} = req.params;

    const group = await Group.findById(groupId);
    if (!group) {
        return next(new AppError('Group not found', 404));
    }

    req.group = group;
    next();
});

/**
 * Require that the current user is a member of the loaded group.
 * Public groups allow read access via getGroup/discoverGroups, but all
 * modification routes should use this middleware.
 */
export const requireMembership = asyncHandler(async (req, res, next) => {
    const group = req.group;
    if (!group) {
        return next(new AppError('Group not loaded', 500));
    }

    if (!group.isMember(req.user.id)) {
        // Allow public group read-only access (GET)
        if (group.privacy === 'public' && req.method === 'GET') {
            return next();
        }
        return next(new AppError('You must be a member of this group', 403));
    }
    next();
});

/**
 * Factory: require a minimum group role on the loaded group.
 * @param {string} minRole - One of GROUP_ROLES
 */
export const requireGroupRole = (minRole) => {
    return asyncHandler(async (req, res, next) => {
        const group = req.group;
        if (!group) {
            return next(new AppError('Group not loaded', 500));
        }

        if (!group.hasMinRole(req.user.id, minRole)) {
            return next(new AppError(`This action requires at least ${minRole} role in the group`, 403));
        }
        next();
    });
};
