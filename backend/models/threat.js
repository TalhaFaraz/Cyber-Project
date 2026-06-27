const mongoose = require("mongoose");

const threatSchema = new mongoose.Schema({

    threatId: {
        type: String,
        unique: true
    },

    title: {
        type: String,
        required: true
    },

    description: {
        type: String,
        required: true
    },

    severity: {
        type: String,
        enum: [
            "Low",
            "Medium",
            "High",
            "Critical"
        ],
        default: "Low"
    },

    attackType: {
        type: String,
        enum: [
            "Phishing",
            "Malware",
            "Ransomware",
            "Brute Force",
            "DDoS",
            "Insider Threat",
            "Credential Stuffing",
            "Data Exfiltration"
        ]
    },

    sourceIP: String,

    destinationIP: String,

    country: String,

    status: {
        type: String,
        enum: [
            "Open",
            "Investigating",
            "Contained",
            "Resolved"
        ],
        default: "Open"
    },

    riskScore: {
        type: Number,
        default: 0
    },

    mitreTechnique: String,

    indicators: [{
        type: {
            type: String
        },
        value: String
    }],

    assignedAnalyst: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User"
    },

    timeline: [{
        action: String,
        timestamp: {
            type: Date,
            default: Date.now
        }
    }],

    notes: [String],

    resolvedAt: Date

}, {
    timestamps: true
});

module.exports =
mongoose.model(
    "Threat",
    threatSchema
);