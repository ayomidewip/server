/**
 * Universal appLogger utility for App Base
 * Provides structured logging using Winston with beautiful console output
 */

const winston = require('winston');
const figlet = require('figlet');
const {format, transports, createLogger} = winston;

// Import Log model for database storage
let Log = null;
// Function to safely get Log model and handle circular dependencies
const getLogModel = () => {
    if (!Log) {
        try {
            Log = require('../models/log.model');
        } catch (error) {
            console.warn('Log model not available, database logging disabled:', error.message);
        }
    }
    return Log;
};

// Define colors for console output
const colors = {
    error: '\x1b[31m',   // red
    warn: '\x1b[33m',    // yellow
    info: '\x1b[36m',    // cyan
    http: '\x1b[35m',    // magenta
    websocket: '\x1b[94m', // bright blue
    debug: '\x1b[32m',   // green
    reset: '\x1b[0m',    // reset
    bold: '\x1b[1m',     // bold
    dim: '\x1b[2m',      // dim
    bgRed: '\x1b[41m',   // background red
    bgGreen: '\x1b[42m', // background green
    bgYellow: '\x1b[43m', // background yellow
    cyan: '\x1b[36m',    // cyan
    green: '\x1b[32m',   // green
    magenta: '\x1b[35m', // magenta
    startup: '\x1b[32m'  // green for startup
};


// Define custom levels (extending Winston's defaults)
const customLevels = {
    error: 0,
    warn: 1,
    info: 2,
    http: 3,
    websocket: 3, // Same priority as HTTP
    verbose: 4,
    debug: 5,
    silly: 6
};

// Add colors to Winston (including custom levels)
winston.addColors({
    error: 'red',
    warn: 'yellow',
    info: 'cyan',
    http: 'magenta',
    websocket: 'blue',
    verbose: 'blue',
    debug: 'green',
    silly: 'grey'
});

// Define icons for log levels
const icons = {
    error: '\u274C', // ❌
    warn: '\u26A0\uFE0F', // ⚠️
    info: '\u2139\uFE0F', // ℹ️
    http: '\uD83D\uDCE1', // 📡
    websocket: '\uD83D\uDD0C', // 🔌
    verbose: '\uD83D\uDD0D', // 🔍
    debug: '\u2728', // ✨
    silly: '\uD83E\uDD13', // 🤓
    startup: '\uD83C\uDF89', // 🎉
};

// Defensive helper for color usage
function safeColor(color) {
    return typeof color === 'string' ? color : '';
}

/**
 * Generate ASCII art banner using figlet
 * @param {string} text - Text to convert to ASCII art (defaults to APP_NAME from env)
 * @returns {Promise<string>} ASCII art banner with color formatting
 */
function generateBanner(text = process.env.APP_NAME) {
    return new Promise((resolve, reject) => {
        figlet.text(text, {
            font: 'AMC Neko', // Use a fun font: Fraktur
            horizontalLayout: 'default',
            verticalLayout: 'default',
            width: 150,
            whitespaceBreak: true
        }, (err, data) => {
            if (err) {
                // Fallback to simple text if figlet fails
                console.warn('Figlet failed, using fallback banner:', err.message);
                resolve(`${safeColor(colors.bold)}${safeColor(colors.cyan)}🚀 ${text} 🚀${safeColor(colors.reset)}`);
                return;
            }

            // Apply cyan color to the figlet output
            const coloredBanner = data
                .split('\n')
                .map(line => `${safeColor(colors.bold)}${safeColor(colors.cyan)}${line}${safeColor(colors.reset)}`)
                .join('\n');

            resolve(coloredBanner);
        });
    });
}

const startupMessages = [
    `${safeColor(colors.green)}🎯 Ready to build something awesome!${safeColor(colors.reset)}`,
    `${safeColor(colors.yellow)}💻 Let's get coding!${safeColor(colors.reset)}`,
    `${safeColor(colors.magenta)}⚡ API is live and kicking!${safeColor(colors.reset)}`,
    `${safeColor(colors.cyan)}✨ May your bugs be few and your logs be beautiful!${safeColor(colors.reset)}`
];

/**
 * Get a random startup message
 * @returns {string} Random motivational message
 */
function getRandomStartupMessage() {
    return startupMessages[Math.floor(Math.random() * startupMessages.length)];
}

// Safe JSON stringifier to avoid circular references
function safeStringify(obj, space = 0) {
    const seen = new WeakSet();
    return JSON.stringify(obj, (key, val) => {
        if (val != null && typeof val === "object") {
            if (seen.has(val)) {
                return "[Circular]";
            }
            seen.add(val);
        }
        return val;
    }, space);
}

/**
 * Custom Database Transport for Winston
 * Stores only HTTP requests/responses in MongoDB
 */
class DatabaseTransport extends winston.Transport {
    constructor(options = {}) {
        super(options);
        this.name = 'database';
        this.level = options.level || 'http';
    }

    async log(info, callback) {
        setImmediate(() => {
            this.emit('logged', info);
        });

        try {
            // STRICT FILTER: Only save logs that are explicitly HTTP level AND have HTTP metadata
            // This ensures ONLY actual HTTP requests/responses are saved to database
            if (info.level !== 'http' || (!info.method && !info.url && !info.statusCode)) {
                callback();
                return;
            }

            // Retry importing Log model if not available
            const LogModel = getLogModel();
            if (!LogModel) {
                // Fallback to console if model not available
                console.log(info.message);
                callback();
                return;
            }

            // Prepare log data for database
            const logData = {
                timestamp: new Date(info.timestamp),
                environment: info.environment || process.env.NODE_ENV,
                service: info.service || 'app-base-server'
            };

            if (info.method) {
                logData.method = info.method;
            }
            if (info.url) {
                logData.url = info.url;
                // Determine request type based on URL pattern
                logData.requestType = LogModel.determineRequestType(info.url);
            }
            if (info.statusCode) logData.statusCode = info.statusCode;
            if (info.responseTime) logData.responseTime = info.responseTime;
            if (info.ip) logData.ip = info.ip;
            if (info.userAgent) logData.userAgent = info.userAgent;
            if (info.userId) logData.userId = info.userId;      
            
            // Add request/response body and header data if present
            if (info.requestBody !== undefined) logData.requestBody = info.requestBody;
            if (info.responseBody !== undefined) logData.responseBody = info.responseBody;
            if (info.requestHeaders) logData.requestHeaders = info.requestHeaders;
            if (info.responseHeaders) logData.responseHeaders = info.responseHeaders;
            if (info.contentType) logData.contentType = info.contentType;
            if (info.contentLength) logData.contentLength = info.contentLength;

            // Add error-specific fields if present (for HTTP errors)
            if (info.stack) logData.stack = info.stack;
            if (info.errorCode) logData.errorCode = info.errorCode;

            // Add any additional metadata
            const meta = {...info};
            delete meta.message;
            delete meta.timestamp;
            delete meta.environment;
            delete meta.service;
            delete meta.method;
            delete meta.url;
            delete meta.statusCode;
            delete meta.responseTime;
            delete meta.ip;
            delete meta.userAgent;
            delete meta.userId;
            delete meta.requestBody;
            delete meta.responseBody;
            delete meta.requestHeaders;
            delete meta.responseHeaders;
            delete meta.contentType;
            delete meta.contentLength;
            delete meta.socketId;
            delete meta.transport;
            delete meta.socketOperation;
            delete meta.disconnectReason;
            delete meta.operationType;
            delete meta.stack;
            delete meta.errorCode;

            if (Object.keys(meta).length > 0) {
                logData.meta = meta;
            }      // Save to database and capture the ObjectId
            const savedLog = await LogModel.createLog(logData);

            // Database save successful (ObjectId now handled in appLogger.http method)
        } catch (error) {
            // Silently fail database logging to avoid noise
            if (process.env.LOG_LEVEL === 'debug') {
                console.error('Database logging failed:', error.message);
            }
        }

        callback();
    }
}

// Custom format for console output with color
const consoleFormat = format.printf(({level, message, timestamp, service, stack, preformatted, ...metadata}) => {
    // If this is a pre-formatted message (like HTTP logs), just return it as-is
    if (preformatted) {
        return message;
    }

    let levelColor;
    let icon = icons[level] || '';
    switch (level) {
        case 'error':
            levelColor = colors.bgRed + colors.bold;
            break;
        case 'warn':
            levelColor = colors.bgYellow + colors.bold;
            break;
        case 'info':
            levelColor = colors.bgGreen + colors.bold;
            break;
        case 'http':
            levelColor = colors.magenta + colors.bold;
            break;
        case 'verbose':
            levelColor = colors.cyan;
            break;
        case 'debug':
            levelColor = colors.cyan + colors.bold;
            break;
        case 'silly':
            levelColor = colors.dim;
            break;
        default:
            levelColor = colors.reset;
    }

    const levelFormatted = `${levelColor}${icon} ${level.toUpperCase()}${colors.reset}`;
    const timeFormatted = `${colors.dim}${timestamp}${colors.reset}`;

    // Handle stack traces with proper line breaks
    let stackStr = '';
    if (stack && typeof stack === 'string') {
        // Format stack trace with proper indentation and line breaks
        const stackLines = stack.split('\n');
        stackStr = '\n' + stackLines.map(line => `    ${colors.dim}${line}${colors.reset}`).join('\n');
    }

    // Handle other metadata
    let metadataStr = '';
    const metaKeys = Object.keys(metadata);
    if (metaKeys.length > 0 && metaKeys[0] !== '0') {
        try {
            // Don't include stack in metadata since we handle it separately
            const cleanMetadata = {...metadata};
            delete cleanMetadata.stack;

            if (Object.keys(cleanMetadata).length > 0) {
                metadataStr = ` ${safeStringify(cleanMetadata)}`;
            }
        } catch (err) {
            metadataStr = ` [Object - Cannot stringify]`;
        }
    }

    return `${timeFormatted} [ ${levelFormatted} ] ${message}${metadataStr}${stackStr}`;
});

// Create appLogger instance - NO DATABASE TRANSPORT
const appLogger = createLogger({
    levels: customLevels, // Use custom levels
    level: process.env.LOG_LEVEL,
    defaultMeta: {
        service: 'app-base',
        environment: process.env.NODE_ENV
    },
    format: format.combine(
        format.timestamp({format: 'YYYY-MM-DD HH:mm:ss'}),
        format.errors({stack: true}),
        format.splat(),
        format.json()
    ),
    transports: [
        // Console transport for all log levels
        new transports.Console({
            level: process.env.LOG_LEVEL, // Use same level as main logger
            format: format.combine(
                format.timestamp({format: 'HH:mm:ss'}),
                format.errors({stack: true}),
                // Remove the default metadata output for cleaner logs
                format((info) => {
                    // Don't show default metadata in console output
                    const {service, environment, ...rest} = info;
                    return rest;
                })(),
                consoleFormat
            ),
            handleExceptions: true
        })
    ],
    exitOnError: false // Don't exit on handled exceptions
});

// Simplified HTTP logging method - output beautiful console logs via winston
appLogger.http = async (message, metadata = {}) => {
    // Generate timestamp and format
    const timestamp = new Date().toLocaleTimeString('en-US', {hour12: false});
    const timeFormatted = `${colors.dim}${timestamp}${colors.reset}`;
    const levelFormatted = `${colors.magenta}${colors.bold}📡 HTTP${colors.reset}`;

    let objectIdStr = '';

    // Try to save to database and get ObjectId (if HTTP metadata exists)
    if (metadata && (metadata.method || metadata.url || metadata.statusCode)) {
        try {
            const LogModel = getLogModel();
            if (LogModel) {
                const logData = {
                    timestamp: new Date(),
                    environment: process.env.NODE_ENV,
                    service: 'app-base-server',
                    method: metadata.method,
                    url: metadata.url,
                    statusCode: metadata.statusCode,
                    responseTime: metadata.responseTime,
                    ip: metadata.ip,
                    userAgent: metadata.userAgent,
                    userId: metadata.userId,
                    requestBody: metadata.requestBody,
                    responseBody: metadata.responseBody,
                    requestHeaders: metadata.requestHeaders,
                    responseHeaders: metadata.responseHeaders,
                    contentType: metadata.contentType,
                    contentLength: metadata.contentLength
                };

                if (metadata.method) {
                    logData.operationType = LogModel.determineOperationType(metadata.method);
                }

                const savedLog = await LogModel.createLog(logData);
                if (savedLog && savedLog._id) {
                    objectIdStr = ` ${colors.bgYellow}${colors.bold}[${savedLog._id.toString()}]${colors.reset}`;
                }
            }
        } catch (error) {
            // Silently fail database save
            if (process.env.LOG_LEVEL === 'debug') {
                console.error('Database logging failed:', error.message);
            }
        }
    }

    // Output the main HTTP log
    const finalMessage = `${timeFormatted} [ ${levelFormatted} ] ${message}${objectIdStr}`;
    appLogger.log({
        level: 'http',
        message: finalMessage,
        preformatted: true, // This tells winston to use the message as-is
        ...metadata
    });

    // If verbose logging is enabled, output request/response details right after the HTTP log
    const currentLogLevel = process.env.LOG_LEVEL;
    const logLevels = {error: 0, warn: 1, info: 2, http: 3, verbose: 4, debug: 5, silly: 6};
    const isVerboseEnabled = logLevels[currentLogLevel] >= logLevels.verbose;

    if (isVerboseEnabled && metadata) {
        const verboseTimestamp = new Date().toLocaleTimeString('en-US', {hour12: false});
        const verboseTimeFormatted = `${colors.dim}${verboseTimestamp}${colors.reset}`;
        const verboseLevelFormatted = `${colors.cyan}🔍 VERBOSE${colors.reset}`;

        // Request Body
        if (metadata.requestBody !== undefined && metadata.requestBody !== null) {
            let formattedRequestBody = '';
            try {
                if (typeof metadata.requestBody === 'string') {
                    // Try to parse and re-stringify for proper formatting
                    try {
                        const parsed = JSON.parse(metadata.requestBody);
                        formattedRequestBody = JSON.stringify(parsed, null, 2);
                    } catch {
                        formattedRequestBody = metadata.requestBody;
                    }
                } else {
                    formattedRequestBody = JSON.stringify(metadata.requestBody, null, 2);
                }

                // Split into lines and add proper indentation
                const bodyLines = formattedRequestBody.split('\n');
                const indentedBody = bodyLines.map((line, index) => {
                    if (index === 0) return line;
                    return `    ${line}`;
                }).join('\n');

                const requestMessage = `${verboseTimeFormatted} [ ${verboseLevelFormatted} ] 📊 Request Body (${metadata.method} ${metadata.url})\n    ${indentedBody}`;
                appLogger.log({
                    level: 'verbose',
                    message: requestMessage,
                    preformatted: true
                });
            } catch (error) {
                const requestMessage = `${verboseTimeFormatted} [ ${verboseLevelFormatted} ] 📊 Request Body (${metadata.method} ${metadata.url}): [Unable to format]`;
                appLogger.log({
                    level: 'verbose',
                    message: requestMessage,
                    preformatted: true
                });
            }
        }

        // Response Body
        if (metadata.responseBody !== undefined && metadata.responseBody !== null) {
            let formattedResponseBody = '';
            try {
                if (typeof metadata.responseBody === 'string') {
                    // Try to parse and re-stringify for proper formatting
                    try {
                        const parsed = JSON.parse(metadata.responseBody);
                        formattedResponseBody = JSON.stringify(parsed, null, 2);
                    } catch {
                        formattedResponseBody = metadata.responseBody;
                    }
                } else {
                    formattedResponseBody = JSON.stringify(metadata.responseBody, null, 2);
                }

                // Split into lines and add proper indentation
                const bodyLines = formattedResponseBody.split('\n');
                const indentedBody = bodyLines.map((line, index) => {
                    if (index === 0) return line;
                    return `    ${line}`;
                }).join('\n');

                const responseMessage = `${verboseTimeFormatted} [ ${verboseLevelFormatted} ] 📊 Response Body (${metadata.statusCode} ${metadata.url})\n    ${indentedBody}`;
                appLogger.log({
                    level: 'verbose',
                    message: responseMessage,
                    preformatted: true
                });
            } catch (error) {
                const responseMessage = `${verboseTimeFormatted} [ ${verboseLevelFormatted} ] 📊 Response Body (${metadata.statusCode} ${metadata.url}): [Unable to format]`;
                appLogger.log({
                    level: 'verbose',
                    message: responseMessage,
                    preformatted: true
                });
            }
        }

        // Request Headers (if verbose enough)
        if (metadata.requestHeaders && Object.keys(metadata.requestHeaders).length > 0) {
            try {
                const formattedHeaders = JSON.stringify(metadata.requestHeaders, null, 2);
                const headerLines = formattedHeaders.split('\n');
                const indentedHeaders = headerLines.map((line, index) => {
                    if (index === 0) return line;
                    return `    ${line}`;
                }).join('\n');

                const headersMessage = `${verboseTimeFormatted} [ ${verboseLevelFormatted} ] 📊 Request Headers (${metadata.method} ${metadata.url})\n    ${indentedHeaders}`;
                appLogger.log({
                    level: 'verbose',
                    message: headersMessage,
                    preformatted: true
                });
            } catch (error) {
                const headersMessage = `${verboseTimeFormatted} [ ${verboseLevelFormatted} ] 📊 Request Headers (${metadata.method} ${metadata.url}): [Unable to format]`;
                appLogger.log({
                    level: 'verbose',
                    message: headersMessage,
                    preformatted: true
                });
            }
        }

        // Response Headers (if verbose enough)
        if (metadata.responseHeaders && Object.keys(metadata.responseHeaders).length > 0) {
            try {
                const formattedHeaders = JSON.stringify(metadata.responseHeaders, null, 2);
                const headerLines = formattedHeaders.split('\n');
                const indentedHeaders = headerLines.map((line, index) => {
                    if (index === 0) return line;
                    return `    ${line}`;
                }).join('\n');

                const headersMessage = `${verboseTimeFormatted} [ ${verboseLevelFormatted} ] 📊 Response Headers (${metadata.statusCode} ${metadata.url})\n    ${indentedHeaders}`;
                appLogger.log({
                    level: 'verbose',
                    message: headersMessage,
                    preformatted: true
                });
            } catch (error) {
                const headersMessage = `${verboseTimeFormatted} [ ${verboseLevelFormatted} ] 📊 Response Headers (${metadata.statusCode} ${metadata.url}): [Unable to format]`;
                appLogger.log({
                    level: 'verbose',
                    message: headersMessage,
                    preformatted: true
                });
            }
        }
    }
};

// WebSocket logging method - mirrors HTTP logging functionality
appLogger.websocket = async (message, metadata = {}) => {
    const timestamp = new Date().toLocaleTimeString('en-US', {hour12: false});
    const timeFormatted = `${colors.dim}${timestamp}${colors.reset}`;
    const levelFormatted = `${colors.cyan}${colors.bold}🔌 WEBSOCKET${colors.reset}`;

    let objectIdStr = '';

    // Save to database if WebSocket metadata exists
    if (metadata && (metadata.method || metadata.url || metadata.statusCode)) {
        try {
            const LogModel = getLogModel();
            if (LogModel) {
                const logData = {
                    timestamp: new Date(),
                    environment: process.env.NODE_ENV,
                    service: 'app-base-server',
                    ...metadata
                };

                if (metadata.method) {
                    logData.operationType = LogModel.determineOperationType(metadata.method);
                }

                const savedLog = await LogModel.createLog(logData);
                if (savedLog && savedLog._id) {
                    objectIdStr = ` ${colors.bgYellow}${colors.bold}[${savedLog._id.toString()}]${colors.reset}`;
                }
            }
        } catch (error) {
            if (process.env.LOG_LEVEL === 'debug') {
                console.error('Database logging failed:', error.message);
            }
        }
    }

    // Output the main WebSocket log
    const finalMessage = `${timeFormatted} [ ${levelFormatted} ] ${message}${objectIdStr}`;
    appLogger.log({
        level: 'websocket',
        message: finalMessage,
        preformatted: true,
        ...metadata
    });

    // Verbose logging for detailed WebSocket info
    const logLevels = {error: 0, warn: 1, info: 2, http: 3, websocket: 3, verbose: 4, debug: 5, silly: 6};
    if (logLevels[process.env.LOG_LEVEL] >= logLevels.verbose && metadata) {
        const verboseTime = `${colors.dim}${timestamp}${colors.reset}`;
        const verboseLevel = `${colors.cyan}🔍 VERBOSE${colors.reset}`;

        if (metadata.requestBody !== undefined && metadata.requestBody !== null) {
            try {
                const formattedData = typeof metadata.requestBody === 'string' 
                    ? metadata.requestBody 
                    : JSON.stringify(metadata.requestBody, null, 2);
                
                const eventMessage = `${verboseTime} [ ${verboseLevel} ] 📊 WebSocket Event Data (${metadata.eventName || 'unknown'})\n    ${formattedData}`;
                appLogger.log({level: 'verbose', message: eventMessage, preformatted: true});
            } catch {
                appLogger.log({level: 'verbose', message: `${verboseTime} [ ${verboseLevel} ] 📊 WebSocket Event Data: [Unable to format]`, preformatted: true});
            }
        }

        if (metadata.error) {
            appLogger.log({level: 'verbose', message: `${verboseTime} [ ${verboseLevel} ] ❌ WebSocket Error: ${metadata.error}`, preformatted: true});
        }
    }
};

// Remove the old conditional console transport addition since it's now included by default

// Enhanced data body logging for verbose debugging (ported from test logger)
appLogger.data = (label, data, options = {}) => {
    const {
        level = 'verbose', // Default to verbose level
        format = 'full', // 'full', 'compact', or 'summary'
        maxDepth = 3,
        maxLength = 2000
    } = options;

    // Format data based on the requested format
    let formattedData;
    try {
        if (format === 'compact') {
            // Compact format for quick review with one-line representation
            formattedData = safeStringify(data).replace(/\s+/g, ' ').substring(0, maxLength);
            if (formattedData.length === maxLength) formattedData += '...';
        } else if (format === 'summary') {
            // Summary format for key counts and structure
            const summary = {};

            if (Array.isArray(data)) {
                summary.type = 'Array';
                summary.length = data.length;
                summary.sample = data.length > 0 ?
                    typeof data[0] === 'object' ? 'Object' : typeof data[0] : 'empty';
            } else if (data && typeof data === 'object') {
                summary.type = 'Object';
                summary.keys = Object.keys(data);
                summary.keyCount = summary.keys.length;
            } else {
                summary.type = typeof data;
                summary.length = data?.toString().length;
            }

            formattedData = summary;
        } else {
            // Full format with indentation and complete data (default)
            formattedData = data;
        }

        // Log the data with appropriate icon and formatting
        const dataIcon = '📊';
        appLogger.log(level, `${dataIcon} ${label}`, {data: formattedData});
    } catch (err) {
        appLogger.error(`Failed to format data body: ${err.message}`, {originalData: data});
    }
};

// Test-compatible logging methods (for easier migration from test logger)
appLogger.test = (message, metadata = {}) => {
    appLogger.log('verbose', `🧪 ${message}`, metadata);
};

appLogger.apiCall = (method, url, options = {}) => {
    appLogger.verbose(`🌐 ${method.toUpperCase()} ${url}`, {
        method: method.toUpperCase(),
        url,
        testContext: options.testContext
    });
};

appLogger.apiResponse = (response, metadata = {}) => {
    const status = response.status || response.statusCode;
    const statusIcon = status >= 200 && status < 300 ? '✅' : status >= 400 ? '❌' : '⚠️';

    const responseInfo = {
        status,
        statusText: response.statusText,
        headers: response.headers,
        ...metadata
    };

    if (metadata.includeData && response.data !== null && response.data !== undefined) {
        responseInfo.data = response.data;
    }

    appLogger.verbose(`${statusIcon} Response: ${status}`, responseInfo);
};

// Test suite logging methods
let stepCounter = 0;
appLogger.step = (message, metadata = {}) => {
    stepCounter++;
    appLogger.test(`Step ${stepCounter}: ${message}`, metadata);
};

appLogger.resetSteps = () => {
    stepCounter = 0;
};

appLogger.suiteStart = (suiteName, metadata = {}) => {
    appLogger.resetSteps();
    appLogger.test(`🚀 Starting test suite: ${suiteName}`, {
        suiteName,
        startTime: new Date().toISOString(),
        ...metadata
    });
};

appLogger.suiteEnd = (suiteName, stats = {}, metadata = {}) => {
    appLogger.test(`🏁 Completed test suite: ${suiteName}`, {
        suiteName,
        endTime: new Date().toISOString(),
        stats,
        ...metadata
    });
    appLogger.resetSteps();
};

// Simplified stream for Express compatibility - not used with our custom middleware
appLogger.stream = {
    write: (message) => {
        // Just use console.log for any fallback HTTP logging
        console.log(message.trim());
    }
};

appLogger.startupMessage = async (serverName, port, mode) => {
    const padding = '='.repeat(60);
    appLogger.info(padding);

    // Generate and print figlet banner
    try {
        const banner = await generateBanner();
        banner.split('\n').forEach(line => appLogger.info(line));
    } catch (error) {
        appLogger.info(`🚀 ${process.env.APP_NAME} 🚀`);
    }

    appLogger.info(`${safeColor(colors.bold)}${safeColor(colors.startup)}${icons.startup || ''} SERVER STARTED ${icons.startup || ''}${safeColor(colors.reset)}`);
    appLogger.info(`${safeColor(colors.info)}► Mode: ${mode}${safeColor(colors.reset)}`);
    appLogger.info(`${safeColor(colors.info)}► Port: ${port}${safeColor(colors.reset)}`);
    appLogger.info(`${safeColor(colors.info)}► Time: ${new Date().toLocaleString()}${safeColor(colors.reset)}`);
    appLogger.info(padding);
    appLogger.info(getRandomStartupMessage());
};

appLogger.routeRegistered = (method, path) => {
    appLogger.info(`📍 Route registered: ${safeColor(colors.bold)}${method}${safeColor(colors.reset)} ${path}`);
};

appLogger.dbConnected = (uri) => {
    appLogger.info(`${safeColor(colors.green)}🌱 MongoDB connection established! ${uri}${safeColor(colors.reset)}`);
};

// Store original console methods for HTTP logging
const originalConsoleLog = console.log;

// Expose original console for special cases (like HTTP logging)
appLogger.originalConsole = {
    log: originalConsoleLog
};

// Expose colors and icons for use in other modules
appLogger.colors = colors;
appLogger.icons = icons;

// Export the safeColor function and other utilities for use in other files
appLogger.safeColor = safeColor;
appLogger.getRandomStartupMessage = getRandomStartupMessage;

module.exports = appLogger;