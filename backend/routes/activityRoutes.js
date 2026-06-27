const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/authMiddleware');
const {
  logActivity,
  getUserActivities,
  getActivityStats,
  clearActivities,
} = require('../controllers/activityController');

// All activity routes are protected
router.use(protect);

router.post('/log',       logActivity);         // Log a new action
router.get('/my',         getUserActivities);   // Get current user's activity log
router.get('/stats',      getActivityStats);    // Get aggregated stats
router.delete('/clear',   clearActivities);     // Clear all activity for user

module.exports = router;
