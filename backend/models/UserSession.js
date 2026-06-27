const mongoose = require("mongoose");

const sessionSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  device: String,
  browser: String,
  operatingSystem: String,
  ipAddress: String,
  location: String,
  loginTime: { type: Date, default: Date.now },
  logoutTime: Date,
  active: { type: Boolean, default: true },
}, { timestamps: true });

// the two queries you'll hit constantly: "is this session active" + "this user's active sessions"
sessionSchema.index({ userId: 1, active: 1 });

module.exports = mongoose.model("UserSession", sessionSchema);