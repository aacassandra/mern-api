const mongoose = require('mongoose')
const Schema = mongoose.Schema

const userSchema = new Schema(
    {
        name: {
            type: String,
            required: [true, 'Please add a name'],
        },
        email: {
            type: String,
            required: [true, 'Please add an email'],
            unique: true,
        },
        password: {
            type: String,
            required: [true, 'Please add a password'],
        },
        lastSignIn: {
            type: Date,
            required: false
        },
        lastSignOut: {
            type: Date,
            required: false
        }
    },
    {
        timestamps: true,
    }
)

module.exports = mongoose.model('User', userSchema)