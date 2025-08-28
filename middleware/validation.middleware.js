// middlewares/validation.middleware.js
const validator = require('validator');
const {AppError} = require('./error.middleware');
const logger = require('../utils/app.logger');

const validateRequest = (schema, payloadLocation = 'body') => {
    return (req, res, next) => {
        const {error} = schema.validate(req[payloadLocation], {
            abortEarly: false, allowUnknown: payloadLocation === 'params' ? false : false
        });

        if (error) {
            const errorMessages = error.details.map(detail => {
                // Customize message format
                const path = detail.path.join('.');
                return `${path}: ${detail.message.replace(/['"]/g, '')}`;
            });

            // Log validation errors without sensitive payload data
            const sanitizedPayload = {...req[payloadLocation]};
            if (sanitizedPayload.password) sanitizedPayload.password = '[REDACTED]';
            if (sanitizedPayload.currentPassword) sanitizedPayload.currentPassword = '[REDACTED]';
            if (sanitizedPayload.newPassword) sanitizedPayload.newPassword = '[REDACTED]';

            logger.error('Validation error:', {
                errors: errorMessages, payload: sanitizedPayload, ip: req.ip, originalUrl: req.originalUrl
            });
            return res.status(400).json({
                success: false, message: `Validation error: ${errorMessages.join(', ')}`
            });
        }

        // Log successful validation without sensitive data
        const sanitizedPayload = {...req[payloadLocation]};
        if (sanitizedPayload.password) sanitizedPayload.password = '[REDACTED]';
        if (sanitizedPayload.currentPassword) sanitizedPayload.currentPassword = '[REDACTED]';
        if (sanitizedPayload.newPassword) sanitizedPayload.newPassword = '[REDACTED]';

        next();
    };
};


module.exports = {
    validateRequest, validateMultiple: (validations) => {
        return async (req, res, next) => {
            try {
                for (const validation of validations) {
                    const {schema, payloadLocation = 'body'} = validation; // Added default for payloadLocation
                    const {error} = schema.validate(req[payloadLocation], {
                        abortEarly: false, allowUnknown: false
                    });
                    if (error) {
                        const errorMessages = error.details.map(detail => {
                            const path = detail.path.join('.');
                            return `${path}: ${detail.message.replace(/['"]/g, '')}`;
                        });

                        // Log validation errors without sensitive payload data
                        const sanitizedPayload = {...req[payloadLocation]};
                        if (sanitizedPayload.password) sanitizedPayload.password = '[REDACTED]';
                        if (sanitizedPayload.currentPassword) sanitizedPayload.currentPassword = '[REDACTED]';
                        if (sanitizedPayload.newPassword) sanitizedPayload.newPassword = '[REDACTED]';

                        logger.error('Multi-validation error:', {
                            errors: errorMessages, payload: sanitizedPayload, ip: req.ip, originalUrl: req.originalUrl
                        });
                        return res.status(400).json({
                            success: false, message: `Validation error: ${errorMessages.join(', ')}`
                        });
                    }
                }
                next();
            } catch (err) { // Changed variable name from error to err                logger.error('Unexpected validation error:', { message: err.message, stack: err.stack, error: err, ip: req.ip, originalUrl: req.originalUrl });
                return res.status(400).json({
                    success: false, message: err.message || 'Validation error'
                });
            }
        };
    }
};
