// models/User.js
import mongoose from 'mongoose';
import validator from 'validator';
import bcrypt from 'bcryptjs';
import crypto from 'node:crypto';

const userSchema = new mongoose.Schema({
    firstName: {
        type: String,
        trim: true,
        minlength: [2, 'Name must be at least 2 characters'],
        maxlength: [50, 'Name must be less than 50 characters']
    },
    lastName: {
        type: String,
        trim: true,
        minlength: [2, 'Name must be at least 2 characters'],
        maxlength: [50, 'Name must be less than 50 characters']
    },
    username: {
        type: String,
        required: [true, 'Please provide a username'],
        trim: true,
        minlength: [3, 'Username must be at least 3 characters'],
        maxlength: [30, 'Username must be less than 30 characters'],
        unique: true,
        match: [/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers, and underscores']
    },
    email: {
        type: String,
        required: [true, 'Please provide your email'],
        unique: true,
        lowercase: true,
        validate: [validator.isEmail, 'Please provide a valid email']
    },
    password: {
        type: String,
        required: [true, 'Please provide a password'],
        minlength: [8, 'Password must be at least 8 characters'],
        select: false
    },
    roles: {
        type: [String], enum: ['USER', 'CREATOR', 'SUPER_CREATOR', 'ADMIN', 'OWNER'], default: ['USER']
    },
    pendingRoles: {
        type: [String],
        enum: ['USER', 'CREATOR', 'SUPER_CREATOR', 'ADMIN', 'OWNER'],
        default: []
    },
    roleApprovalStatus: {
        type: String,
        enum: ['NONE', 'PENDING', 'APPROVED', 'REJECTED'],
        default: 'NONE'
    },
    roleApprovalRequest: {
        requestedRoles: [String],
        requestedBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User'
        },
        requestedAt: Date,
        approvedBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User'
        },
        approvedAt: Date,
        rejectedBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User'
        },
        rejectedAt: Date,
        reason: String
    },
    active: {
        type: Boolean, default: true, select: false
    },
    passwordChangedAt: Date,
    passwordResetToken: String,
    passwordResetExpires: Date,
    emailVerificationToken: String,
    emailVerificationExpires: Date,
    emailVerified: {
        type: Boolean, default: false
    },
    pendingEmail: String, // For email changes
    createdAt: {
        type: Date, default: Date.now
    },
    profilePhoto: {
        type: String, default: 'default.jpg'
    },
    twoFactorEnabled: {
        type: Boolean, default: false
    },
    twoFactorSecret: {
        type: String, select: false
    },
    twoFactorBackupCodes: {
        type: [String], select: false
    },
    knownDevices: [{
        deviceId: {
            type: String, required: true
        }, deviceFingerprint: {
            type: String, required: true
        }, userAgent: String, browser: String, os: String, platform: String, ipAddress: String, location: {
            country: String, city: String, region: String
        }, firstSeenAt: {
            type: Date, default: Date.now
        }, lastSeenAt: {
            type: Date, default: Date.now
        }, isActive: {
            type: Boolean, default: true
        }
    }],
    // Password history for preventing password reuse (stores hashed passwords)
    passwordHistory: {
        type: [String],
        select: false,
        default: []
    }
}, {
    toJSON: {virtuals: false}, toObject: {virtuals: false}
});

userSchema.pre('save', function (next) {
    // Update `passwordChangedAt` when the password is modified
    if (!this.isModified('password') || this.isNew) {
        return next();
    }
    this.passwordChangedAt = Date.now() - 1000; // Subtract 1 second to account for token issuance delay
    next();
});

userSchema.methods.correctPassword = async function (candidatePassword, userPassword) {
    // Compare provided password with hashed password
    return await bcrypt.compare(candidatePassword, userPassword);
};

userSchema.methods.changedPasswordAfter = function (JWTTimestamp) {
    // Check if the password was changed after the JWT was issued
    if (this.passwordChangedAt) {
        const changedTimestamp = parseInt(this.passwordChangedAt.getTime() / 1000, 10);
        return JWTTimestamp < changedTimestamp;
    }
    return false;
};

userSchema.methods.createPasswordResetToken = function () {
    // Generate a password reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    this.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
    this.passwordResetExpires = Date.now() + 10 * 60 * 1000; // Token valid for 10 minutes
    return resetToken;
};

userSchema.methods.createEmailVerificationToken = function () {
    // Generate an email verification token
    const verificationToken = crypto.randomBytes(32).toString('hex');
    this.emailVerificationToken = crypto.createHash('sha256').update(verificationToken).digest('hex');
    this.emailVerificationExpires = Date.now() + 24 * 60 * 60 * 1000; // Token valid for 24 hours
    return verificationToken;
};

/**
 * Check if a password was previously used (for password reuse prevention)
 * @param {string} candidatePassword - The plaintext password to check
 * @returns {Promise<boolean>} - True if password was previously used
 */
userSchema.methods.isPasswordPreviouslyUsed = async function (candidatePassword) {
    if (!this.passwordHistory || this.passwordHistory.length === 0) {
        return false;
    }
    
    // Check against each stored password hash
    for (const oldHash of this.passwordHistory) {
        const isMatch = await bcrypt.compare(candidatePassword, oldHash);
        if (isMatch) {
            return true;
        }
    }
    return false;
};

/**
 * Add current password to history before changing password
 * Keeps only the last 5 passwords
 * @param {string} hashedPassword - The hashed password to add to history
 */
userSchema.methods.addPasswordToHistory = function (hashedPassword) {
    if (!this.passwordHistory) {
        this.passwordHistory = [];
    }
    
    // Add current password to history
    this.passwordHistory.push(hashedPassword);
    
    // Keep only the last 5 passwords
    const MAX_PASSWORD_HISTORY = 5;
    if (this.passwordHistory.length > MAX_PASSWORD_HISTORY) {
        this.passwordHistory = this.passwordHistory.slice(-MAX_PASSWORD_HISTORY);
    }
};

// Check if model exists to prevent recompilation errors in tests
const User = mongoose.models.User || mongoose.model('User', userSchema);

export default User;
