import mongoose from 'mongoose';

/**
 * Group roles (separate from system-level roles in rights.js):
 *   OWNER   – full control: manage members, permissions, delete any file
 *   ADMIN   – can change file metadata, manage members below admin
 *   CREATOR – can read, write, and share new files to the group
 *   MEMBER  – read-only access to group files
 */
export const GROUP_ROLES = {
    OWNER: 'OWNER',
    ADMIN: 'ADMIN',
    CREATOR: 'CREATOR',
    MEMBER: 'MEMBER'
};

export const GROUP_ROLE_HIERARCHY = {
    [GROUP_ROLES.OWNER]: 4,
    [GROUP_ROLES.ADMIN]: 3,
    [GROUP_ROLES.CREATOR]: 2,
    [GROUP_ROLES.MEMBER]: 1
};

const memberSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    role: {
        type: String,
        enum: Object.values(GROUP_ROLES),
        default: GROUP_ROLES.MEMBER
    },
    joinedAt: {
        type: Date,
        default: Date.now
    }
}, {_id: false});

const groupFileSchema = new mongoose.Schema({
    file: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'File',
        required: true
    },
    // Who shared/uploaded this file to the group
    sharedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    sharedAt: {
        type: Date,
        default: Date.now
    },
    // Optional timeline caption / description
    caption: {
        type: String,
        trim: true,
        maxlength: 1000
    },
    // Pinned files stay at the top of the timeline
    pinned: {
        type: Boolean,
        default: false
    }
}, {_id: false});

const groupSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'Group name is required'],
        trim: true,
        minlength: [2, 'Group name must be at least 2 characters'],
        maxlength: [100, 'Group name must be less than 100 characters']
    },
    description: {
        type: String,
        trim: true,
        maxlength: 500
    },
    avatar: {
        type: String,
        default: null
    },
    // Privacy: public groups are discoverable, private require invite
    privacy: {
        type: String,
        enum: ['public', 'private'],
        default: 'private'
    },
    members: [memberSchema],
    files: [groupFileSchema],
    // Cached member count for efficient queries
    memberCount: {
        type: Number,
        default: 0
    },
    // Cached file count
    fileCount: {
        type: Number,
        default: 0
    },
    createdBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    }
}, {
    timestamps: true
});

// Indexes
groupSchema.index({createdBy: 1});
groupSchema.index({'members.user': 1});
groupSchema.index({privacy: 1, name: 1});
groupSchema.index({'files.file': 1});

// Keep cached counts in sync
groupSchema.pre('save', function (next) {
    this.memberCount = this.members.length;
    this.fileCount = this.files.length;
    next();
});

/**
 * Get a member's role in this group
 */
groupSchema.methods.getMemberRole = function (userId) {
    const member = this.members.find(m => m.user.equals(userId));
    return member ? member.role : null;
};

/**
 * Check if a user is a member of this group
 */
groupSchema.methods.isMember = function (userId) {
    return this.members.some(m => m.user.equals(userId));
};

/**
 * Check if a user meets a minimum role requirement
 */
groupSchema.methods.hasMinRole = function (userId, minRole) {
    const memberRole = this.getMemberRole(userId);
    if (!memberRole) return false;
    return GROUP_ROLE_HIERARCHY[memberRole] >= GROUP_ROLE_HIERARCHY[minRole];
};

const Group = mongoose.models.Group || mongoose.model('Group', groupSchema);

export default Group;
