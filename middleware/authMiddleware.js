// Import necessary libraries and modules
const jwt = require('jsonwebtoken');
const asyncHandler = require('express-async-handler');
const User = require('../models/userModel');

/**
 * Middleware to secure routes by verifying JWT tokens.
 * Checks both access and refresh tokens for validity and matches their IDs.
 * Attaches the user object to the request if verification is successful.
 * 
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
const secure = asyncHandler(async (req, res, next) => {

    // Check if both refreshToken and accessToken are present in cookies
    if (req.cookies && req.cookies.refreshToken && req.cookies.accessToken) {
        try {
            const refreshToken = req.cookies.refreshToken;
            const accessToken = req.cookies.accessToken;

            // Verify the refreshToken and accessToken
            const decodedRefreshToken = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
            const decodedAccessToken = jwt.verify(accessToken, process.env.JWT_SECRET);

            // Check if the IDs from both tokens match
            if (decodedRefreshToken.id !== decodedAccessToken.id) {
                return res.status(401).json({ message: 'Token IDs do not match' });
            }

            // Find the user by ID from the refreshToken
            req.user = await User.findById(decodedRefreshToken.id).select('-password');
            if (!req.user) {
                return res.status(401).json({ message: 'Not authorized, user not found' });
            }
            next();
        } catch (error) {
            // Catch any errors and respond with an unauthorized message
            res.status(401).json({ message: 'Not authorized, token failed' });
        }
    } else {
        // Respond with an unauthorized message if tokens are not present
        res.status(401).json({ message: 'Please login again!' });
    }
});

// Export the secure middleware for use in other parts of the application
module.exports = { secure };
