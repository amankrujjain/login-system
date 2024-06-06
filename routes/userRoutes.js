const express = require("express");
const router = express.Router();
const {register, authUser, getUserProfile, logoutUser} = require('../controllers/userController');
const {secure} = require('../middleware/authMiddleware');

router.route('/').post(register);
router.post('/login', authUser);
router.get('/profile',secure, getUserProfile);
router.post('/logout',secure, logoutUser);

module.exports = router;