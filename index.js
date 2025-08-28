/**
 * Entry point for the App-Base Server application
 * Creates and starts the server instance
 */

const {serverInstance} = require('./server');
const logger = require('./utils/app.logger');

// Start the server and handle errors
serverInstance.start()
    .then(server => {
        // Server is now running
        const address = server.address();
    })
    .catch(err => {
        logger.error('[Index] Failed to start server:', err);
        process.exit(1);
    });

// Export server instance for testing purposes
module.exports = serverInstance;
