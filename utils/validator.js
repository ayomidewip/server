const Joi = require('joi');
const {ObjectId} = require('mongodb');

const joiHelpers = {
    // Phone number validation
    phoneNumber: (value, helpers) => {
        const phoneRegex = /^\+?[1-9]\d{1,14}$/; // E.164 format
        if (!phoneRegex.test(value)) {
            return helpers.error('phone.invalid');
        }
        return value;
    },

    // Positive number validation
    positiveNumber: (value, helpers) => {
        if (value <= 0) {
            return helpers.error('number.positive');
        }
        return value;
    }
};

const customJoi = Joi.extend((joi) => ({
    type: 'objectId',
    base: joi.string(),
    messages: {
        'objectId.invalid': '{{#label}} must be a valid MongoDB ObjectID'
    },
    validate(value, helpers) {
        // Validate ObjectId format
        if (!ObjectId.isValid(value)) {
            return {value, errors: helpers.error('objectId.invalid')};
        }
        return {value};
    }
})).extend((joi) => ({
    type: 'password',
    base: joi.string(),
    messages: {
        'password.complexity': 'Password must contain 8-30 characters with uppercase, lowercase, number and special character'
    },
    rules: {
        complexity: {
            validate(value, helpers) {
                const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,30}$/;
                if (!passwordRegex.test(value)) {
                    return helpers.error('password.complexity');
                }
                return value;
            }
        }
    }
})).extend((joi) => ({
    type: 'futureDate',
    base: joi.date(),
    messages: {
        'date.future': '{{#label}} must be a future date'
    },
    validate(value, helpers) {
        const date = new Date(value);
        if (date <= new Date()) {
            return {value, errors: helpers.error('date.future')};
        }
        return {value};
    }
})).extend((joi) => ({
    type: 'filePath',
    base: joi.string(),
    messages: {
        'filePath.invalid': '{{#label}} must be a valid Unix-style file path'
    },
    validate(value, helpers) {
        // Handle both raw filePaths and base64-encoded filePaths
        let actualFilePath = value;

        // Check if this might be a base64-encoded filePath
        try {
            // Base64 strings typically don't start with '/' and contain valid base64 characters
            if (!value.startsWith('/') && /^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
                const decoded = Buffer.from(value, 'base64').toString('utf-8');
                // If decoding results in a valid-looking path, use it
                if (decoded.startsWith('/')) {
                    actualFilePath = decoded;
                }
            }
        } catch (error) {
            // If base64 decoding fails, use the original value
        }

        // Validate Unix-style absolute file paths
        if (!actualFilePath || actualFilePath.trim() === '') {
            return {value, errors: helpers.error('filePath.invalid')};
        }

        // Must start with /
        if (!actualFilePath.startsWith('/')) {
            return {value, errors: helpers.error('filePath.invalid')};
        }

        // No double slashes
        if (actualFilePath.includes('//')) {
            return {value, errors: helpers.error('filePath.invalid')};
        }

        // No null characters
        if (actualFilePath.includes('\0')) {
            return {value, errors: helpers.error('filePath.invalid')};
        }

        // Root path is valid
        if (actualFilePath === '/') {
            return {value};
        }

        // Should not end with / (except root)
        if (actualFilePath.endsWith('/')) {
            return {value, errors: helpers.error('filePath.invalid')};
        }

        // Check path length (reasonable limit)
        if (actualFilePath.length > 4096) {
            return {value, errors: helpers.error('filePath.invalid')};
        }

        // Check individual path components
        const parts = actualFilePath.split('/').filter(part => part);
        for (const part of parts) {
            // No relative references
            if (part === '.' || part === '..') {
                return {value, errors: helpers.error('filePath.invalid')};
            }

            // No Windows-invalid characters
            if (/[<>:"|*?]/.test(part)) {
                return {value, errors: helpers.error('filePath.invalid')};
            }

            // Reasonable filename length
            if (part.length > 255) {
                return {value, errors: helpers.error('filePath.invalid')};
            }
        }

        return {value};
    }
}));

module.exports = {
    objectId: customJoi.objectId,
    password: () => customJoi.password().complexity(),
    futureDate: customJoi.futureDate,
    filePath: customJoi.filePath,
    phoneNumber: customJoi.string().custom(joiHelpers.phoneNumber, 'phone number validation'),
    positiveNumber: customJoi.number().custom(joiHelpers.positiveNumber, 'positive number validation'),
    Joi: customJoi
};
