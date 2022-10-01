const mongoose = require('mongoose')
const Schema = mongoose.Schema

const oauth = new Schema(
    {
        userId: {
            type: String,
            required: true,
        },
        token: {
            type: String,
            required: true,
            unique: true,
        },
        expiresAt: {
            type: Date,
            required: true
        }
    },
    {
        timestamps: true,
    }
)

module.exports = mongoose.model('Oauth', oauth)