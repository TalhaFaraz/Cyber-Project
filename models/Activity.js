const mongoose = require('mongoose');

const activitySchema = new mongoose.Schema({
  user_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  tool_id: {
    type: Number,
    required: true,
  },
  tool_name: {
    type: String,
  },
  action_type: {
    type: String,
    enum: ['test', 'view', 'bookmark', 'search'],
    default: 'view',
  },
  query_input: {
    type: String,
    default: '',
  },
  timestamp: {
    type: Date,
    default: Date.now,
  },
});

// Index for faster user queries
activitySchema.index({ user_id: 1, timestamp: -1 });

module.exports = mongoose.model('Activity', activitySchema);
