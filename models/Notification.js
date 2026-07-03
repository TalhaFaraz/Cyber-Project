const mongoose = require("mongoose");

const notificationSchema = new mongoose.Schema({

    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User"
    },

    title: {
        type: String,
        required: true
    },

    message: {
        type: String,
        required: true
    },

    priority: {
        type: String,
        enum: [
            "Low",
            "Medium",
            "High",
            "Critical"
        ],
        default: "Low"
    },

    category: {
        type: String,
        enum: [
            "Threat",
            "Incident",
            "Vulnerability",
            "Login",
            "System"
        ]
    },

    read: {
        type: Boolean,
        default: false
    }

}, {
    timestamps: true
});

module.exports =
mongoose.model(
    "Notification",
    notificationSchema
);