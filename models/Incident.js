const mongoose = require("mongoose");

const incidentSchema = new mongoose.Schema({

    incidentNumber: {
        type: String,
        unique: true
    },

    title: {
        type: String,
        required: true
    },

    description: String,

    category: {
        type: String,
        enum: [
            "Malware",
            "Phishing",
            "Unauthorized Access",
            "Data Breach",
            "DDoS",
            "Insider Threat"
        ]
    },

    severity: {
        type: String,
        enum: [
            "Low",
            "Medium",
            "High",
            "Critical"
        ]
    },

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

    threat: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Threat"
    },

    owner: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User"
    },

    affectedSystems: [String],

    affectedUsers: [String],

    evidence: [String],

    mitigationSteps: [String],

    rootCause: String,

    lessonsLearned: String,

    startedAt: Date,

    resolvedAt: Date

}, {
    timestamps: true
});

module.exports =
mongoose.model(
    "Incident",
    incidentSchema
);