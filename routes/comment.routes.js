import {Router} from 'express';
import commentController from '../controllers/comment.controller.js';
import * as authMiddleware from '../middleware/auth.middleware.js';
import {validateRequest} from '../middleware/validation.middleware.js';
import {commentSchemas} from '../models/schemas.js';
import {cacheResponse} from '../middleware/cache.middleware.js';

const router = Router();

// Define comment routes for validation
router.validRoutes = [
    '/api/v1/comments',
    '/api/v1/comments/file/:fileId',
    '/api/v1/comments/file/:fileId/count',
    '/api/v1/comments/:commentId',
    '/api/v1/comments/:commentId/replies'
];

// All comment routes require authentication
router.use(authMiddleware.verifyToken());

// Create a comment
router.post('/',
    validateRequest(commentSchemas.createComment),
    commentController.createComment
);

// Get comments for a file
router.get('/file/:fileId',
    commentController.getFileComments
);

// Get comment count for a file
router.get('/file/:fileId/count',
    cacheResponse(30, (req) => {
        const groupId = req.query.groupId || 'all';
        return `comments:count:${req.params.fileId}:${groupId}`;
    }),
    commentController.getCommentCount
);

// Get replies to a comment
router.get('/:commentId/replies',
    commentController.getReplies
);

// Update a comment
router.patch('/:commentId',
    validateRequest(commentSchemas.updateComment),
    commentController.updateComment
);

// Delete a comment
router.delete('/:commentId',
    commentController.deleteComment
);

export default router;
