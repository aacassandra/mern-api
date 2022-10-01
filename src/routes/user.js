const express = require('express')
const { body } = require('express-validator');

const router = express.Router()
const {
    signOut, signIn, signUp, getMe
} = require('../controllers/user')
const { protect } = require('../middleware/auth')

router.post('/', signUp)
router.post('/signin', [
    body('email').notEmpty().withMessage('Email is required'),
    body('password').notEmpty().withMessage('Password is required')
], signIn)
router.get('/signout', signOut)
router.get('/me', protect, getMe)

module.exports = router