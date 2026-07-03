const mongoose = require('mongoose');

const securityToolSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  category: {
    type: String,
    required: true,
    enum: [
      'IP Intelligence', 'Threat Detection', 'Malware Analysis',
      'WHOIS Lookup', 'DNS Analysis', 'Security Headers',
      'Breach Detection', 'Email Intelligence', 'URL Scanning',
      'Geolocation', 'Vulnerability',
    ],
  },
  description: { type: String, required: true },
  api_link: { type: String, required: true },
  endpoint: { type: String },
  tags: [{ type: String, lowercase: true }],
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model('SecurityTool', securityToolSchema);
