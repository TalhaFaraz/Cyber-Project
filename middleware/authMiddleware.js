const jwt = require('jsonwebtoken');
const User = require('../models/User');
const UserSession = require('../models/UserSession');

const protect = async (req, res, next) => {
  let token;

  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  }

  if (!token) {
    return res.status(401).json({ success: false, message: 'Access denied. No token provided.' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // session revocation check — a destroyed session fails here even with a valid JWT
    const session = await UserSession.findOne({ _id: decoded.sid, active: true });
    if (!session) {
      return res.status(401).json({ success: false, message: 'Session ended. Please log in again.' });
    }

    req.user = await User.findById(decoded.id);
    if (!req.user) {
      return res.status(401).json({ success: false, message: 'User not found.' });
    }

    req.sessionId = session._id;
    next();
  } catch (err) {
    return res.status(401).json({ success: false, message: 'Invalid or expired token.' });
  }
};

module.exports = { protect };