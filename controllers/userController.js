// Import necessary libraries and modules
const jwt = require('jsonwebtoken');
const asyncHandler = require('express-async-handler');
const User = require('../models/userModel');
const { generateAccessToken, generateRefreshToken } = require('../utils/generateToken');
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator');

/**
 * Middleware array for user registration.
 * Includes input validation and registration handler.
 */
const register = [
    // Validation for username, email, and password fields
    body('username').isString().trim().escape().withMessage('Name must be a string'),
    body('email').isEmail().normalizeEmail().withMessage("Invalid email format"),
    body('password')
        .isLength({ min: 6 })
        .matches(/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/)
        .withMessage('Password must be at least 6 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character'),
    
    // Registration handler
    asyncHandler(async (req, res) => {
        // Validate request inputs
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { username, email, password } = req.body;

        try {
            // Check if user already exists
            const userExists = await User.findOne({ email });
            if (userExists) {
                return res.status(400).json({ message: 'User already exists' });
            }

            // Hash the password
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(password, salt);

            // Create new user
            const user = await User.create({
                username,
                email,
                password: hashedPassword
            });

            // Send response with user data
            if (user) {
                res.status(201).json({
                    id: user._id,
                    username: user.username,
                    email: user.email,
                    is_loggedin: user.is_loggedin,
                });
            } else {
                res.status(400).json({ message: 'Invalid user data' });
            }
        } catch (error) {
            res.status(500).json({ message: 'Server error', error: error.message });
        }
    })
];

/**
 * Middleware array for user authentication.
 * Includes input validation and authentication handler.
 */
const authUser = [
    // Validation for email and password fields
    body('email').isEmail().normalizeEmail(),
    body('password').trim().escape(),
    
    // Authentication handler
    asyncHandler(async (req, res) => {
        // Validate request inputs
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { email, password } = req.body;

        try {
            // Find user by email
            const user = await User.findOne({ email });

            if (!user) {
                return res.status(401).json({ message: 'Invalid email or password' });
            }

            // Check if user is already logged in
            if (user.is_loggedin) {
                return res.status(409).json({ message: 'User already logged in' });
            }

            // Compare provided password with stored password
            const passwordMatch = await bcrypt.compare(password, user.password);
            if (!passwordMatch) {
                return res.status(401).json({ message: 'Invalid email or password' });
            }

            // Generate tokens
            const accessToken = generateAccessToken({ id: user._id });
            const refreshToken = generateRefreshToken({ id: user._id });

            // Update user's login status
            user.is_loggedin = true;
            await user.save();

            // Set cookies and send response
            res.cookie('accessToken', accessToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 24 * 60 * 60 * 1000
            })
            .cookie('refreshToken', refreshToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 7 * 24 * 60 * 60 * 1000,
            });

            res.json({
                id: user._id,
                username: user.username,
                email: user.email,
                accessToken,
                refreshToken
            });
        } catch (error) {
            res.status(500).json({ message: 'Server error', error: error.message });
        }
    })
];

/**
 * Handler to get the user profile.
 */
const getUserProfile = asyncHandler(async (req, res) => {
    try {
        // Find user by ID from request object
        const user = await User.findById(req.user._id);
        if (user) {
            res.json({
                id: user._id,
                username: user.username,
                email: user.email,
                is_loggedin: user.is_loggedin
            });
        } else {
            res.status(404).json({ message: 'User not found' });
        }
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

/**
 * Handler to refresh the access token using a refresh token.
 */
const refreshToken = asyncHandler(async (req, res) => {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) {
        return res.status(403).json({ message: 'Refresh token not found, please login again' });
    }

    try {
        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
        const user = await User.findById(decoded.id);
        if (!user) {
            return res.status(403).json({ message: 'User not found' });
        }

        const newAccessToken = generateAccessToken({ id: user._id });
        res.json({ accessToken: newAccessToken });
    } catch (error) {
        res.status(403).json({ message: 'Invalid refresh token' });
    }
});

/**
 * Handler to logout the user.
 */
const logoutUser = asyncHandler(async (req, res) => {
    try {
        const refreshToken = req.cookies.refreshToken;
        const accessToken = req.cookies.accessToken;

        if (!refreshToken || !accessToken) {
            return res.status(400).json({ message: 'Access token or refresh token is missing' });
        }

        let decoded;
        try {
            decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
        } catch (err) {
            return res.status(403).json({ message: 'Invalid refresh token' });
        }

        const user = await User.findById(decoded.id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        if (!user.is_loggedin) {
            return res.status(409).json({ message: 'User already logged out' });
        }

        // Update user's login status
        user.is_loggedin = false;
        await user.save();

        // Clear cookies and send response
        res.cookie('refreshToken', '', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            expires: new Date(0),
        }).cookie('accessToken', '', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            expires: new Date(0),
        });

        res.json({ message: 'Logged out successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Export the functions for use in other parts of the application
module.exports = { register, authUser, getUserProfile, refreshToken, logoutUser };
