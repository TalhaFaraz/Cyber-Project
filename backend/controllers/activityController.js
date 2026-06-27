const Activity = require('../models/Activity');

// API name lookup table
const API_NAMES = {
  1:'AbuseIPDB', 2:'VirusTotal', 3:'Have I Been Pwned', 4:'IPinfo',
  5:'Shodan', 6:'SecurityTrails', 7:'WhoisXML API', 8:'GreyNoise',
  9:'URLScan', 10:'Hunter.io', 11:'BuiltWith', 12:'Censys',
  13:'OpenPhish', 14:'AlienVault OTX', 15:'NVD API', 16:'IPAPI',
  17:'EmailRep', 18:'DNS Lookup', 19:'Google Safe Browsing', 20:'CVE Details',
};

// ─── LOG ACTIVITY ─────────────────────────────────────────────────────────────
const logActivity = async (req, res) => {
  try {
    const { tool_id, action_type, query_input } = req.body;

    if (!tool_id) {
      return res.status(400).json({ success: false, message: 'tool_id is required.' });
    }

    const activity = await Activity.create({
      user_id: req.user._id,
      tool_id: Number(tool_id),
      tool_name: API_NAMES[tool_id] || 'Unknown',
      action_type: action_type || 'view',
      query_input: query_input || '',
    });

    res.status(201).json({ success: true, activity });
  } catch (err) {
    console.error('[ACTIVITY] Log error:', err.message);
    res.status(500).json({ success: false, message: 'Failed to log activity.' });
  }
};

// ─── GET USER ACTIVITIES ──────────────────────────────────────────────────────
const getUserActivities = async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    const activities = await Activity.find({ user_id: req.user._id })
      .sort({ timestamp: -1 })
      .limit(limit);

    res.status(200).json({ success: true, count: activities.length, activities });
  } catch (err) {
    console.error('[ACTIVITY] Fetch error:', err.message);
    res.status(500).json({ success: false, message: 'Failed to fetch activities.' });
  }
};

// ─── GET ACTIVITY STATS ───────────────────────────────────────────────────────
const getActivityStats = async (req, res) => {
  try {
    const userId = req.user._id;

    const totalCalls = await Activity.countDocuments({ user_id: userId });

    // Today's calls
    const startOfDay = new Date();
    startOfDay.setHours(0, 0, 0, 0);
    const todayCalls = await Activity.countDocuments({
      user_id: userId,
      timestamp: { $gte: startOfDay },
    });

    // Most used APIs
    const topAPIs = await Activity.aggregate([
      { $match: { user_id: userId } },
      { $group: { _id: '$tool_id', name: { $first: '$tool_name' }, count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 5 },
    ]);

    // Action breakdown
    const actionBreakdown = await Activity.aggregate([
      { $match: { user_id: userId } },
      { $group: { _id: '$action_type', count: { $sum: 1 } } },
    ]);

    res.status(200).json({
      success: true,
      stats: { totalCalls, todayCalls, topAPIs, actionBreakdown },
    });
  } catch (err) {
    console.error('[ACTIVITY] Stats error:', err.message);
    res.status(500).json({ success: false, message: 'Failed to fetch stats.' });
  }
};

// ─── CLEAR ACTIVITY LOG ───────────────────────────────────────────────────────
const clearActivities = async (req, res) => {
  try {
    await Activity.deleteMany({ user_id: req.user._id });
    res.status(200).json({ success: true, message: 'Activity log cleared.' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to clear activity log.' });
  }
};

module.exports = { logActivity, getUserActivities, getActivityStats, clearActivities };
