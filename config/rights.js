/**
 * Role-based permission system
 *
 * Roles hierarchy (highest to lowest):
 * - OWNER: Can do everything including deleting users
 * - ADMIN: Can do everything except deleting users
 * - SUPER_CREATOR: Extended creation privileges
 * - CREATOR: Basic creation privileges
 * - USER: Can only manage their own account
 */

// Define roles
const ROLES = {
    OWNER: 'OWNER', ADMIN: 'ADMIN', SUPER_CREATOR: 'SUPER_CREATOR', CREATOR: 'CREATOR', USER: 'USER'
};

// Define permissions
const RIGHTS = {
    DELETE_USERS: 'DELETE_USERS',
    MANAGE_ALL_USERS: 'MANAGE_ALL_USERS',
    MANAGE_OWN_ACCOUNT: 'MANAGE_OWN_ACCOUNT',
    CREATE_CONTENT: 'CREATE_CONTENT',
    MANAGE_ALL_CONTENT: 'MANAGE_ALL_CONTENT',
    ASSIGN_ROLES: 'ASSIGN_ROLES',
    APPROVE_ROLES: 'APPROVE_ROLES',
    REQUEST_ROLE_ELEVATION: 'REQUEST_ROLE_ELEVATION'
};

// Role hierarchy for role-based checks
const ROLE_HIERARCHY = {
    [ROLES.OWNER]: 5, [ROLES.ADMIN]: 4, [ROLES.SUPER_CREATOR]: 3, [ROLES.CREATOR]: 2, [ROLES.USER]: 1
};

// Map roles to permissions
const RIGHT_ASSIGNMENT = {
    [ROLES.OWNER]: [RIGHTS.DELETE_USERS, RIGHTS.MANAGE_ALL_USERS, RIGHTS.MANAGE_OWN_ACCOUNT, RIGHTS.CREATE_CONTENT, RIGHTS.MANAGE_ALL_CONTENT, RIGHTS.ASSIGN_ROLES, RIGHTS.APPROVE_ROLES],
    [ROLES.ADMIN]: [RIGHTS.MANAGE_ALL_USERS, RIGHTS.MANAGE_OWN_ACCOUNT, RIGHTS.CREATE_CONTENT, RIGHTS.MANAGE_ALL_CONTENT, RIGHTS.REQUEST_ROLE_ELEVATION],
    [ROLES.SUPER_CREATOR]: [RIGHTS.MANAGE_OWN_ACCOUNT, RIGHTS.CREATE_CONTENT, RIGHTS.REQUEST_ROLE_ELEVATION],
    [ROLES.CREATOR]: [RIGHTS.MANAGE_OWN_ACCOUNT, RIGHTS.CREATE_CONTENT, RIGHTS.REQUEST_ROLE_ELEVATION],
    [ROLES.USER]: [RIGHTS.MANAGE_OWN_ACCOUNT, RIGHTS.REQUEST_ROLE_ELEVATION]
};

/**
 * Check if a user has a specific right
 * @param {Array} userRoles - Array of user rights
 * @param {String} right - Required right
 * @returns {Boolean} - Whether the user has the right
 */
const hasRight = (userRoles, right) => {
    // Convert single role to array for consistency
    const roles = Array.isArray(userRoles) ? userRoles : [userRoles];

    // Check each role if it has the required permission
    return roles.some(role => {
        const rights = RIGHT_ASSIGNMENT[role];
        return rights && rights.includes(right);
    });
};

/**
 * Check if user has a required role or higher in hierarchy
 * @param {Array|String} userRoles - User's roles
 * @param {String} requiredRole - Minimum role required
 * @returns {Boolean} - Whether user has the required role level
 */
const hasRole = (userRoles, requiredRole) => {
    // Convert single role to array for consistency
    const roles = Array.isArray(userRoles) ? userRoles : [userRoles];

    // Get the hierarchy level of the required role
    const requiredLevel = ROLE_HIERARCHY[requiredRole] || 0;

    // Check if any of the user's roles meet or exceed the required level
    return roles.some(role => {
        const roleLevel = ROLE_HIERARCHY[role] || 0;
        return roleLevel >= requiredLevel;
    });
};

/**
 * Get the highest role level for a user
 * @param {Array|String} userRoles - User's roles
 * @returns {Number} - Highest role level
 */
const getHighestRoleLevel = (userRoles) => {
    // Convert single role to array for consistency
    const roles = Array.isArray(userRoles) ? userRoles : [userRoles];

    // Get the highest level among all user roles
    return Math.max(...roles.map(role => ROLE_HIERARCHY[role] || 0));
};

/**
 * Check if user can assign a specific role
 * @param {Array|String} userRoles - User's current roles
 * @param {String} targetRole - Role to be assigned
 * @returns {Boolean} - Whether user can assign the target role
 */
const canAssignRole = (userRoles, targetRole) => {
    const userLevel = getHighestRoleLevel(userRoles);
    const targetLevel = ROLE_HIERARCHY[targetRole] || 0;

    // Users can only assign roles that are strictly lower than their own level
    return userLevel > targetLevel;
};

/**
 * Check if roles require owner approval
 * @param {Array|String} roles - Roles to check
 * @returns {Boolean} - Whether any of the roles require owner approval
 */
const requiresOwnerApproval = (roles) => {
    const rolesArray = Array.isArray(roles) ? roles : [roles];

    // All roles except USER require owner approval
    return rolesArray.some(role => role !== ROLES.USER);
};

/**
 * Get roles that are considered elevated (above USER)
 * @param {Array|String} roles - Roles to check
 * @returns {Array} - Array of elevated roles
 */
const getElevatedRoles = (roles) => {
    const rolesArray = Array.isArray(roles) ? roles : [roles];

    return rolesArray.filter(role => role !== ROLES.USER);
};

/**
 * Check if user is owner
 * @param {Array|String} userRoles - User's roles
 * @returns {Boolean} - Whether user has owner role
 */
const isOwner = (userRoles) => {
    const roles = Array.isArray(userRoles) ? userRoles : [userRoles];
    return roles.includes(ROLES.OWNER);
};

module.exports = {
    ROLES,
    RIGHTS,
    ROLE_HIERARCHY,
    hasRight,
    hasRole,
    getHighestRoleLevel,
    canAssignRole,
    requiresOwnerApproval,
    getElevatedRoles,
    isOwner
};
