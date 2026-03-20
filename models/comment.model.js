import mongoose from 'mongoose';

const commentSchema = new mongoose.Schema({
    // The file being commented on
    file: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'File',
        required: true,
        index: true
    },
    // Author of the comment
    author: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
        index: true
    },
    // Comment body (plain text; HTML is sanitized on input)
    body: {
        type: String,
        required: [true, 'Comment body is required'],
        trim: true,
        minlength: [1, 'Comment cannot be empty'],
        maxlength: [2000, 'Comment cannot exceed 2000 characters']
    },
    // Optional parent comment for threaded replies
    parentComment: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Comment',
        default: null,
        index: true
    },
    // Soft-delete flag
    deleted: {
        type: Boolean,
        default: false
    },
    // Optional: which group context the comment was made in (null = direct file comment)
    group: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Group',
        default: null,
        index: true
    },
    editedAt: {
        type: Date,
        default: null
    }
}, {
    timestamps: true
});

// Efficient listing: newest comments first per file
commentSchema.index({file: 1, createdAt: -1});
// Thread lookup
commentSchema.index({parentComment: 1, createdAt: 1});

const Comment = mongoose.models.Comment || mongoose.model('Comment', commentSchema);

export default Comment;
