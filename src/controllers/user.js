const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const asyncHandler = require('express-async-handler')
const User = require('../models/user')
const Oauth = require('../models/oauth')
const {validationResult} = require("express-validator");
const moment = require("moment");

// @desc    Signup new user
// @route   POST /api/users
// @access  Public
const signUp = asyncHandler(async (req, res,next) => {
    const { name, email, password } = req.body

    if (!name || !email || !password) {
        const error = new Error('Please add all fields')
        error.errorStatus = 400
        next(error)
    }

    // Check if user exists
    const userExists = await User.findOne({ email })

    if (userExists) {
        const error = new Error('User already exists')
        error.errorStatus = 400
        next(error)
    }

    // Hash password
    const salt = await bcrypt.genSalt(10)
    const hashedPassword = await bcrypt.hash(password, salt)

    // Create user
    const user = await User.create({
        name,
        email,
        password: hashedPassword,
    })

    if (user) {
        res.status(201).json({
            message: "Register success",
            data: {
                _id: user.id,
                name: user.name,
                email: user.email,
                token: generateToken(user._id),
            }
        })
    } else {
        const error = new Error('Invalid user data')
        error.errorStatus = 400
        next(error)
    }
})

// @desc    Signin a user
// @route   POST /api/v1/users/login
// @access  Public
const signIn = asyncHandler(async (req, res,next) => {
    const { email, password } = req.body

    // Check for user email
    const user = await User.findOne({ email })

    const errors = validationResult(req)
    if (!errors.isEmpty()) {
        const error = new Error('Something went wrong')
        error.errorStatus = 400
        error.data = errors.array()
        next(error)
    }

    if (user && (await bcrypt.compare(password, user.password))) {
        user.lastSignIn = new Date()
        user.lastSignOut = null
        const token = generateToken(user._id)
        await user.save()

        const minutes = process.env.TOKEN_EXPIRED_AT_MINUTES
        let date = moment().add(parseInt(minutes), 'minutes')
        await Oauth.create({
            userId: user.id,
            token,
            expiresAt: date
        })

        res.status(200).json({
            message: 'Login successfully',
            data: {
                _id: user.id,
                name: user.name,
                email: user.email,
                token,
                token_type: 'Bearer',
                last_login: moment(user.lastSignIn).format('YYYY-MM-DD HH:mm:ss')
            }
        })
    } else {
        const error = new Error('Invalid credentials')
        error.errorStatus = 400
        next(error)
    }
})

// @desc    Signout a user
// @route   POST /api/v1/users/logout
// @access  Public
const signOut = asyncHandler(async (req, res, next) => {
    let token
    if (
        req.headers.authorization &&
        req.headers.authorization.startsWith('Bearer')
    ) {
        // Get token from header
        token = req.headers.authorization.split(' ')[1]
        Oauth.findOne({ token })
            .then((result) => {
                if (!result) {
                    const error = new Error('Token is invalid')
                    error.errorStatus = 404
                    next(error)
                }

                const decoded = jwt.verify(token, process.env.JWT_SECRET)
                User.findById(decoded.id)
                    .then(async(user) => {
                        user.lastSignOut = new Date()
                        await user.save()
                        return Oauth.findByIdAndDelete(result._id)
                    })
                    .catch(() => {
                        const error = new Error('Token is invalid')
                        error.errorStatus = 400
                        next(error)
                    })
            })
            .then(() => {
                res.status(200).json({
                    message: "User has been logout",
                })
            })
            .catch((err) => {
                console.log(err)
                const error = new Error('Something went wrong!')
                error.errorStatus = 500
                next(error)
            })
    }

    if (!token) {
        const error = new Error('Token is required!')
        error.errorStatus = 400
        next(error)
    }
})

// @desc    Get user data
// @route   GET /api/v1/users/me
// @access  Private
const getMe = asyncHandler(async (req, res) => {
    res.status(200).json({
        data: req.user
    })
})

// Generate JWT
const generateToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_SECRET, {
        expiresIn: '30d',
    })
}

module.exports = {
    signUp,
    signIn,
    signOut,
    getMe,
}