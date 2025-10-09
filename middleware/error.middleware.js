import logger from '../utils/app.logger.js';
const {NODE_ENV} = process.env;

// AppError class for operational errors
class AppError extends Error {
    constructor(message, statusCode) {
        super(message);
        this.statusCode = statusCode;
        this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
        this.isOperational = true;
        Error.captureStackTrace(this, this.constructor);
    }
}

const handleCastErrorDB = (err) => {
    const message = `Invalid ${err.path}: ${err.value}`;
    return new AppError(message, 400);
};

const handleDuplicateFieldsDB = (err) => {
    const value = err.keyValue ? Object.values(err.keyValue)[0] : 'unknown';
    const message = `Duplicate field value: ${value}. Please use another value!`;
    return new AppError(message, 400);
};

const handleValidationErrorDB = (err) => {
    const errors = Object.values(err.errors).map(el => el.message);
    const message = `Invalid input data. ${errors.join('. ')}`;
    return new AppError(message, 400);
};

const handleJWTError = () => new AppError('Invalid token. Please log in again!', 401);
const handleJWTExpiredError = () => new AppError('Your token has expired! Please log in again!', 401);

const sendErrorDev = (err, res) => {
    res.status(err.statusCode).json({
        success: false, message: err.message, stack: err.stack
    });
};

const sendErrorProd = (err, res) => {
    if (err.isOperational) {
        res.status(err.statusCode).json({
            success: false, message: err.message
        });
    } else {
        logger.error('ERROR 💥', err);
        res.status(500).json({
            success: false, message: 'Something went very wrong!'
        });
    }
};

const errorMiddleware = (err, req, res, next) => {
    // Prevent multiple responses if headers have already been sent
    if (res.headersSent) {
        return next(err);
    }

    // --- Handle malformed JSON (SyntaxError from express.json) ---
    if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
        logger.warn('Malformed JSON received:', {url: req.originalUrl, ip: req.ip});
        return res.status(400).json({
            success: false, message: 'Request body is missing or malformed.'
        });
    }

    // --- Handle network/database/Redis timeouts ---
    const timeoutCodes = ['ECONNABORTED', 'ETIMEDOUT'];
    const timeoutNames = ['MongoNetworkTimeoutError'];
    if ((err.code && timeoutCodes.includes(err.code)) || (err.name && timeoutNames.includes(err.name)) || (err.message && typeof err.message === 'string' && err.message.toLowerCase().includes('timeout'))) {
        logger.error('Timeout error:', err);
        return res.status(504).json({
            success: false, message: 'A network or database timeout occurred. Please try again later.'
        });
    }

    err.statusCode = err.statusCode || 500;
    err.status = err.status || 'error';

    // Check if this is a 404 error and set an appropriate message
    if (err.statusCode === 404 && !err.message) {
        err.message = 'Resource not found';
    }

    // Use development or production error response
    if (NODE_ENV === 'development') {
        sendErrorDev(err, res);
    } else {
        sendErrorProd(err, res);
    }
};

export default errorMiddleware;
export {AppError};