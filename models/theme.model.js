/**
 * Theme model — dynamic, user-created themes as data.
 *
 * A theme is a JSON token document. The web app compiles tokens to CSS custom
 * properties scoped to `.theme-<slug>` at runtime; the mobile app consumes the
 * token object directly. The six App Base themes are seeded as locked presets
 * (isPreset: true) so the component contract never changes.
 */

import mongoose from 'mongoose';

const colorTokenValidator = {
    validator: (value) => /^#([0-9a-fA-F]{3,4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$/.test(value),
    message: '{PATH} must be a hex color (e.g. #3F84E5)'
};

const colorToken = (required = true) => ({
    type: String,
    required,
    validate: colorTokenValidator
});

const themeSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'Theme name is required'],
        trim: true,
        minlength: [2, 'Theme name must be at least 2 characters'],
        maxlength: [50, 'Theme name must be less than 50 characters']
    },
    slug: {
        type: String,
        required: true,
        trim: true,
        lowercase: true,
        match: [/^[a-z0-9-]+$/, 'Slug can only contain lowercase letters, numbers, and hyphens'],
        index: true
    },
    description: {
        type: String,
        trim: true,
        maxlength: [300, 'Description must be less than 300 characters'],
        default: ''
    },
    owner: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: function () { return !this.isPreset; },
        index: true
    },
    /** Built-in preset themes (seeded from App Base's six themes) are locked */
    isPreset: {
        type: Boolean,
        default: false
    },
    visibility: {
        type: String,
        enum: ['private', 'unlisted', 'public'],
        default: 'private',
        index: true
    },
    forkedFrom: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Theme',
        default: null
    },
    /** Design tokens — single source of truth for web CSS vars and mobile objects */
    tokens: {
        darkMode: {type: Boolean, default: false},
        colors: {
            primary: colorToken(),
            primaryAccent: colorToken(),
            secondary: colorToken(),
            secondaryAccent: colorToken(),
            tertiary: colorToken(false),
            tertiaryAccent: colorToken(false),
            neutral: colorToken(false),
            neutralAccent: colorToken(false),
            success: colorToken(false),
            warning: colorToken(false),
            error: colorToken(false),
            background: colorToken(),
            surface: colorToken(),
            surfaceAccent: colorToken(false),
            border: colorToken(false),
            text: colorToken(),
            textContrast: colorToken(),
            shadow: {type: String, default: 'rgba(0, 0, 0, 0.15)'}
        },
        fonts: {
            /** Keys into the curated font registry (mapped to Google Fonts on web, Expo fonts on mobile) */
            primary: {type: String, default: 'urbanist', maxlength: 50},
            secondary: {type: String, default: 'montserrat-alternates', maxlength: 50},
            monospace: {type: String, default: 'jetbrains-mono', maxlength: 50}
        },
        radii: {
            base: {type: String, default: '0.375rem', maxlength: 20},
            card: {type: String, default: '0.5rem', maxlength: 20},
            input: {type: String, default: '0.375rem', maxlength: 20},
            button: {type: String, default: '0.375rem', maxlength: 20},
            checkbox: {type: String, default: '0.25rem', maxlength: 20},
            fab: {type: String, default: '50%', maxlength: 20},
            progress: {type: String, default: '9999px', maxlength: 20},
            notification: {type: String, default: '0.5rem', maxlength: 20}
        }
    },
    /** How many accounts/portfolios currently apply this theme (denormalized counter) */
    appliedCount: {
        type: Number,
        default: 0,
        min: 0
    }
}, {
    timestamps: true,
    toJSON: {virtuals: false},
    toObject: {virtuals: false}
});

// One slug per owner; presets share the global namespace
themeSchema.index({owner: 1, slug: 1}, {unique: true, partialFilterExpression: {owner: {$exists: true}}});
themeSchema.index({visibility: 1, appliedCount: -1});

/** Public projection — what non-owners see in galleries */
themeSchema.methods.toPublicJSON = function () {
    return {
        id: this._id,
        name: this.name,
        slug: this.slug,
        description: this.description,
        isPreset: this.isPreset,
        tokens: this.tokens,
        forkedFrom: this.forkedFrom,
        appliedCount: this.appliedCount,
        createdAt: this.createdAt,
        updatedAt: this.updatedAt
    };
};

const Theme = mongoose.model('Theme', themeSchema);

export default Theme;
