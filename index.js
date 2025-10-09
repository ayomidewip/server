/**
 * Entry point for the App-Base Server application
 * Creates and starts the server instance
 */

import {serverInstance} from './server.js';

const {default: logger = console} = await import('./utils/app.logger.js').catch(() => ({default: console}));

serverInstance.start()
    .then((server) => {
        const address = server?.address?.();
        if (address?.port) {
            logger.debug?.(`[Index] Server listening on port ${address.port}`);
        }
    })
    .catch((err) => {
        logger.error?.('[Index] Failed to start server:', err);
        process.exit(1);
    });

export {serverInstance};
export default serverInstance;
