import Comment from '../models/comment.model.js';
import File from '../models/file.model.js';
import Group from '../models/group.model.js';
import {asyncHandler} from '../middleware/app.middleware.js';
import {AppError} from '../middleware/error.middleware.js';
import {cache} from '../middleware/cache.middleware.js';
import logger from '../utils/app.logger.js';
import {sanitizeHtmlInput} from '../utils/sanitize.js';
import {hasRight, RIGHTS} from '../config/rights.js';

const commentController = {
    /**
     * @desc    Create a comment on a file
     * @route   POST /api/v1/comments
     * @access  Authenticated (must have read access to the file)
     */
    createComment: asyncHandler(async (req, res, next) => {
        const {fileId, body, parentComment, groupId} = req.body;
        const userId = req.user.id;

        // Verify file exists
        const file = await File.findById(fileId).select('_id owner permissions');
        if (!file) {
            return next(new AppError('File not found', 404));
        }

        // If groupId is provided, verify the user is a member of that group
        // and that the file is shared in that group
        if (groupId) {
            const group = await Group.findById(groupId).select('members files');
            if (!group) {
                return next(new AppError('Group not found', 404));
            }
            if (!group.isMember(userId)) {
                return next(new AppError('You must be a group member to comment', 403));
            }
            const fileInGroup = group.files.some(f => f.file.equals(fileId));
            if (!fileInGroup) {
                return next(new AppError('This file is not shared in this group', 400));
            }
        } else {
            // Direct file comment: user must be owner or have read permission
            const isOwner = file.owner.equals(userId);
            const hasRead = file.permissions?.read?.some(id => id.equals(userId));
            const hasWrite = file.permissions?.write?.some(id => id.equals(userId));
            const isAdmin = hasRight(req.user.roles, RIGHTS.MANAGE_ALL_CONTENT);

            if (!isOwner && !hasRead && !hasWrite && !isAdmin) {
                return next(new AppError('You do not have access to comment on this file', 403));
            }
        }

        // If replying, verify parent comment exists and is on the same file
        if (parentComment) {
            const parent = await Comment.findById(parentComment).select('file deleted');
            if (!parent || parent.deleted) {
                return next(new AppError('Parent comment not found', 404));
            }
            if (!parent.file.equals(fileId)) {
                return next(new AppError('Parent comment does not belong to this file', 400));
            }
        }

        const comment = await Comment.create({
            file: fileId,
            author: userId,
            body: sanitizeHtmlInput(body),
            parentComment: parentComment || null,
            group: groupId || null
        });

        await comment.populate('author', 'firstName lastName username profilePhoto');
        await cache.del(`comments:file:${fileId}`);

        logger.info(`[Comment] Comment created on file ${fileId} by ${userId}`);

        res.status(201).json({
            success: true,
            data: comment
        });
    }),

    /**
     * @desc    Get comments for a file
     * @route   GET /api/v1/comments/file/:fileId
     * @access  Authenticated (must have read access)
     */
    getFileComments: asyncHandler(async (req, res) => {
        const {fileId} = req.params;
        const page = Math.max(1, parseInt(req.query.page, 10) || 1);
        const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 20));
        const skip = (page - 1) * limit;
        const groupId = req.query.groupId || null;

        // Build filter: top-level comments only (no parentComment)
        const filter = {file: fileId, parentComment: null, deleted: false};
        if (groupId) {
            filter.group = groupId;
        }

        const [comments, total] = await Promise.all([
            Comment.find(filter)
                .sort({createdAt: -1})
                .skip(skip)
                .limit(limit)
                .populate('author', 'firstName lastName username profilePhoto'),
            Comment.countDocuments(filter)
        ]);

        // Fetch reply counts for each top-level comment
        const commentIds = comments.map(c => c._id);
        const replyCounts = await Comment.aggregate([
            {$match: {parentComment: {$in: commentIds}, deleted: false}},
            {$group: {_id: '$parentComment', count: {$sum: 1}}}
        ]);
        const replyMap = new Map(replyCounts.map(r => [r._id.toString(), r.count]));

        const data = comments.map(c => ({
            ...c.toObject(),
            replyCount: replyMap.get(c._id.toString()) || 0
        }));

        res.status(200).json({
            success: true,
            data,
            pagination: {page, limit, total, pages: Math.ceil(total / limit)}
        });
    }),

    /**
     * @desc    Get replies to a comment
     * @route   GET /api/v1/comments/:commentId/replies
     * @access  Authenticated
     */
    getReplies: asyncHandler(async (req, res) => {
        const {commentId} = req.params;
        const page = Math.max(1, parseInt(req.query.page, 10) || 1);
        const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 20));
        const skip = (page - 1) * limit;

        const filter = {parentComment: commentId, deleted: false};

        const [replies, total] = await Promise.all([
            Comment.find(filter)
                .sort({createdAt: 1})
                .skip(skip)
                .limit(limit)
                .populate('author', 'firstName lastName username profilePhoto'),
            Comment.countDocuments(filter)
        ]);

        res.status(200).json({
            success: true,
            data: replies,
            pagination: {page, limit, total, pages: Math.ceil(total / limit)}
        });
    }),

    /**
     * @desc    Update a comment
     * @route   PATCH /api/v1/comments/:commentId
     * @access  Comment author only
     */
    updateComment: asyncHandler(async (req, res, next) => {
        const {commentId} = req.params;
        const {body} = req.body;
        const userId = req.user.id;

        const comment = await Comment.findById(commentId);
        if (!comment || comment.deleted) {
            return next(new AppError('Comment not found', 404));
        }

        if (!comment.author.equals(userId)) {
            return next(new AppError('You can only edit your own comments', 403));
        }

        comment.body = sanitizeHtmlInput(body);
        comment.editedAt = new Date();
        await comment.save();

        await comment.populate('author', 'firstName lastName username profilePhoto');
        await cache.del(`comments:file:${comment.file}`);

        res.status(200).json({
            success: true,
            data: comment
        });
    }),

    /**
     * @desc    Delete a comment (soft delete)
     * @route   DELETE /api/v1/comments/:commentId
     * @access  Comment author, file owner, or system admin
     */
    deleteComment: asyncHandler(async (req, res, next) => {
        const {commentId} = req.params;
        const userId = req.user.id;

        const comment = await Comment.findById(commentId);
        if (!comment || comment.deleted) {
            return next(new AppError('Comment not found', 404));
        }

        const isAuthor = comment.author.equals(userId);
        const isAdmin = hasRight(req.user.roles, RIGHTS.MANAGE_ALL_CONTENT);

        // Also allow file owner to delete comments on their files
        let isFileOwner = false;
        if (!isAuthor && !isAdmin) {
            const file = await File.findById(comment.file).select('owner');
            if (file) {
                isFileOwner = file.owner.equals(userId);
            }
        }

        if (!isAuthor && !isAdmin && !isFileOwner) {
            return next(new AppError('You do not have permission to delete this comment', 403));
        }

        comment.deleted = true;
        comment.body = '[deleted]';
        await comment.save();

        await cache.del(`comments:file:${comment.file}`);

        res.status(200).json({
            success: true,
            message: 'Comment deleted'
        });
    }),

    /**
     * @desc    Get comment count for a file
     * @route   GET /api/v1/comments/file/:fileId/count
     * @access  Authenticated
     */
    getCommentCount: asyncHandler(async (req, res) => {
        const {fileId} = req.params;
        const groupId = req.query.groupId || null;

        const filter = {file: fileId, deleted: false};
        if (groupId) filter.group = groupId;

        const count = await Comment.countDocuments(filter);

        res.status(200).json({
            success: true,
            data: {count}
        });
    })
};

export default commentController;
