const express = require('express');
const router = express.Router();
const { register, authUser, getUserProfile, refreshToken, logoutUser } = require('../controllers/userController');
const { secure } = require('../middleware/authMiddleware');

router.post('/register', register);
router.post('/login', authUser);
router.get('/profile', secure, getUserProfile);
router.post('/refresh-token', refreshToken);
router.post('/logout', secure, logoutUser);

module.exports = router;
