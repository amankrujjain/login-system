// Import necessary libraries and modules
const express = require('express');
const router = express.Router();
const { register, authUser, getUserProfile, refreshToken, logoutUser } = require('../controllers/userController');
const { secure } = require('../middleware/authMiddleware');

/**
 * Route to register a new user.
 * @route POST /api/users/register
 * @access Public
 */
router.post('/register', register);

/**
 * Route to authenticate a user and get a token.
 * @route POST /api/users/login
 * @access Public
 */
router.post('/login', authUser);

/**
 * Route to get the profile of the authenticated user.
 * @route GET /api/users/profile
 * @access Private
 */
router.get('/profile', secure, getUserProfile);

/**
 * Route to refresh the access token.
 * @route POST /api/users/refresh-token
 * @access Public
 */
router.post('/refresh-token', refreshToken);

/**
 * Route to logout the authenticated user.
 * @route POST /api/users/logout
 * @access Private
 */
router.post('/logout', secure, logoutUser);

// Export the router for use in other parts of the application
module.exports = router;
