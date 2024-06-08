// Import the JSON Web Token library
const jwt = require('jsonwebtoken');

/**
 * Generates an access token for the given user.
 * 
 * @param {Object} user - The user object containing user details
 * @returns {string} The generated access token
 */
const generateAccessToken = (user) => {
    return jwt.sign(user, process.env.JWT_SECRET, { expiresIn: '15m' });
};

/**
 * Generates a refresh token for the given user.
 * 
 * @param {Object} user - The user object containing user details
 * @returns {string} The generated refresh token
 */
const generateRefreshToken = (user) => {
    return jwt.sign(user, process.env.JWT_REFRESH_SECRET, { expiresIn: '7d' });
};

// Export the functions for use in other parts of the application
module.exports = { generateAccessToken, generateRefreshToken };
