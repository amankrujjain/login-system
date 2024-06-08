const jwt = require('jsonwebtoken');
const asyncHandler = require('express-async-handler');
const User = require('../models/userModel');

const secure = asyncHandler(async (req, res, next) => {

    if (req.cookies && req.cookies.refreshToken && req.cookies.accessToken) {
        try {
            const refreshToken = req.cookies.refreshToken;
            const accessToken = req.cookies.accessToken;

            const decodedRefreshToken = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
            const decodedAccessToken = jwt.verify(accessToken, process.env.JWT_SECRET);

            if (decodedRefreshToken.id !== decodedAccessToken.id) {
                return res.status(401).json({ message: 'Token IDs do not match' });
            }

            req.user = await User.findById(decodedRefreshToken.id).select('-password');
            if (!req.user) {
                return res.status(401).json({ message: 'Not authorized, user not found' });
            }
            next();
        } catch (error) {
            res.status(401).json({ message: 'Not authorized, token failed' });
        }
    } else {
        res.status(401).json({ message: 'Please login again!' });
    }
});

module.exports = { secure };
