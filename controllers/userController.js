const asyncHandler = require('express-async-handler');
const User = require('../models/userModel');
const generateToken = require('../utils/generateToken');
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator');

const register = [
    body('username').isString().trim().escape().withMessage('Name must be a string'),
    body('email').isEmail().normalizeEmail().withMessage("Invalid email format"),
    body('password')
        .isLength({ min: 6 })
        .matches(/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/)
        .withMessage('Password must be at least 6 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character'),
    asyncHandler(async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { username, email, password } = req.body;

        try {
            const userExists = await User.findOne({ email });

            if (userExists) {
                return res.status(400).json({ message: 'User already exists' });
            }

            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(password, salt);

            const user = await User.create({
                username,
                email,
                password: hashedPassword,
            });

            if (user) {
                res.status(201)
                    .cookie('jwt', generateToken(user._id), {
                        httpOnly: true,
                        secure: process.env.NODE_ENV === 'production',
                        sameSite: 'strict',
                        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
                    })
                    .json({
                        id: user._id,
                        username: user.username,
                        email: user.email,
                    });
            } else {
                res.status(400).json({ message: 'Invalid user data' });
            }
        } catch (error) {
            res.status(500).json({ message: 'Server error', error: error.message });
        }
    })
];

const authUser = [
    body('email').isEmail().normalizeEmail(),
    body('password').trim().escape(),
    asyncHandler(async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { email, password } = req.body;

        try {
            const user = await User.findOne({ email });

            if (user && (await bcrypt.compare(password, user.password))) {
                res.cookie('jwt', generateToken(user._id), {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === 'production',
                    sameSite: 'strict',
                    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
                }).json({
                    id: user._id,
                    username: user.username,
                    email: user.email,
                });
            } else {
                res.status(401).json({ message: 'Invalid email or password' });
            }
        } catch (error) {
            res.status(500).json({ message: 'Server error', error: error.message });
        }
    })
];

const getUserProfile = asyncHandler(async (req, res) => {
    try {
        console.log(req.user)
        const user = await User.findById(req.user._id);
        if (user) {
            res.json({
                id: user._id,
                username: user.username,
                email: user.email,
            });
        } else {
            res.status(404).json({ message: 'User not found' });
        }
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

const logoutUser = asyncHandler(async (req, res) => {
    try {
        res.cookie('jwt', '', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            expires: new Date(0),
        }).json({ message: 'Logged out successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

module.exports = { register, authUser, getUserProfile, logoutUser };
