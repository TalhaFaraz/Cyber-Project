const jwt = require('jsonwebtoken');
const { UAParser } = require('ua-parser-js'); // npm i ua-parser-js
const User = require('../models/User');
const UserSession = require('../models/UserSession');

// token now carries BOTH the user id and the session id
const generateToken = (userId, sessionId) => {
  return jwt.sign(
    { id: userId, sid: sessionId },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRE || '7d' }
  );
};

// build a session row from the request metadata
const createSession = async (userId, req) => {
  const ua = new UAParser(req.headers['user-agent'] || '').getResult();
  const ipAddress =
    req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
    req.socket?.remoteAddress ||
    req.ip;

  return UserSession.create({
    userId,
    device: ua.device.type || 'desktop',
    browser: [ua.browser.name, ua.browser.version].filter(Boolean).join(' '),
    operatingSystem: [ua.os.name, ua.os.version].filter(Boolean).join(' '),
    ipAddress,
  });
};

// ─── REGISTER ──────────────────────────────────────────────────────────────
const register = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ success: false, message: 'All fields are required.' });
    }
    if (password.length < 6) {
      return res.status(400).json({ success: false, message: 'Password must be at least 6 characters.' });
    }

    const existing = await User.findOne({ email: email.toLowerCase() });
    if (existing) {
      return res.status(409).json({ success: false, message: 'Email already registered.' });
    }

    const user = await User.create({ name, email, password });
    const session = await createSession(user._id, req);
    const token = generateToken(user._id, session._id);

    res.status(201).json({
      success: true,
      message: 'Registration successful.',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        registration_date: user.registration_date,
      },
    });
  } catch (err) {
    console.error('[AUTH] Register error:', err.message);
    res.status(500).json({ success: false, message: 'Server error during registration.' });
  }
};

// ─── LOGIN ──────────────────────────────────────────────────────────────────
const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password are required.' });
    }

    const user = await User.findOne({ email: email.toLowerCase() }).select('+password');
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid email or password.' });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Invalid email or password.' });
    }

    const session = await createSession(user._id, req);
    const token = generateToken(user._id, session._id);

    res.status(200).json({
      success: true,
      message: 'Login successful.',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        registration_date: user.registration_date,
      },
    });
  } catch (err) {
    console.error('[AUTH] Login error:', err.message);
    res.status(500).json({ success: false, message: 'Server error during login.' });
  }
};

// ─── LOGOUT (destroy current session) ────────────────────────────────────────
const logout = async (req, res) => {
  try {
    const session = await UserSession.findOneAndUpdate(
      { _id: req.sessionId, active: true },
      { active: false, logoutTime: new Date() },
      { new: true }
    );

    if (!session) {
      return res.status(404).json({ success: false, message: 'Session not found or already ended.' });
    }

    res.status(200).json({ success: true, message: 'Logged out successfully.' });
  } catch (err) {
    console.error('[AUTH] Logout error:', err.message);
    res.status(500).json({ success: false, message: 'Server error during logout.' });
  }
};

// ─── LOGOUT ALL (destroy every active session for this user) ──────────────────
const logoutAll = async (req, res) => {
  try {
    await UserSession.updateMany(
      { userId: req.user._id, active: true },
      { active: false, logoutTime: new Date() }
    );
    res.status(200).json({ success: true, message: 'Logged out of all devices.' });
  } catch (err) {
    console.error('[AUTH] Logout-all error:', err.message);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
};

// ─── GET PROFILE ──────────────────────────────────────────────────────────────
const getProfile = async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    res.status(200).json({
      success: true,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        registration_date: user.registration_date,
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error fetching profile.' });
  }
};

// ─── UPDATE PROFILE ───────────────────────────────────────────────────────────
const updateProfile = async (req, res) => {
  try {
    const { name } = req.body;
    if (!name) return res.status(400).json({ success: false, message: 'Name is required.' });

    const user = await User.findByIdAndUpdate(
      req.user._id,
      { name },
      { new: true, runValidators: true }
    );

    res.status(200).json({
      success: true,
      message: 'Profile updated successfully.',
      user: { id: user._id, name: user.name, email: user.email },
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error updating profile.' });
  }
};

module.exports = { register, login, logout, logoutAll, getProfile, updateProfile };