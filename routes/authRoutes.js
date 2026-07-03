const express = require('express');
const router = express.Router();
const {
  register,
  login,
  logout,
  logoutAll,
  getProfile,
  updateProfile,
} = require('../controllers/authController');
const { protect } = require('../middleware/authMiddleware');

// Public routes
router.post('/register', register);
router.post('/login', login);

// Protected routes
router.get('/profile', protect, getProfile);
router.put('/profile', protect, updateProfile);
router.post('/logout', protect, logout);
router.post('/logout-all', protect, logoutAll);

module.exports = router;