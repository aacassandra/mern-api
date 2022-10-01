const jwt = require('jsonwebtoken')
const asyncHandler = require('express-async-handler')
const User = require('../models/user')
const Oauth = require('../models/oauth')
const moment = require('moment')

const protect = asyncHandler(async (req, res, next) => {
    let token
    if (
        req.headers.authorization &&
        req.headers.authorization.startsWith('Bearer')
    ) {
        // Get token from header
        token = req.headers.authorization.split(' ')[1]

        const checkToken = await Oauth.findOne({ token })
        if (checkToken) {
            let beginningTime = moment(checkToken.createdAt);
            let endTime = moment(checkToken.expiresdAt);
            let diff = beginningTime.diff(endTime, 'minutes');

            if (diff < 0){
                // when toke is expired
                const error = new Error('Token is expired')
                error.errorStatus = 400
                throw error
            } else {
                const decoded = jwt.verify(token, process.env.JWT_SECRET)
                User.findById(decoded.id).select('-password')
                    .then((result) => {
                        req.user = result
                        next()
                    })
                    .catch(() => {
                        const error = new Error('Token is invalid')
                        error.errorStatus = 400
                        next(error)
                    })
            }
        } else {
            const error = new Error('Token is invalid')
            error.errorStatus = 400
            throw error
        }
    }

    if (!token) {
        const error = new Error('Token is required!')
        error.errorStatus = 400
        throw error
    }
})

module.exports = { protect }