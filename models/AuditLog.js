const mongoose = require("mongoose");

const auditLogSchema = new mongoose.Schema({

    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User"
    },

    username: String,

    action: {
        type: String,
        required: true
    },

    endpoint: String,

    method: String,

    ipAddress: String,

    userAgent: String,

    statusCode: Number,

    requestBody: Object,

    metadata: Object

}, {
    timestamps: true
});

module.exports =
mongoose.model(
    "AuditLog",
    auditLogSchema
);