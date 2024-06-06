const jwt = require('jsonwebtoken');
const asyncHandler = require('express-async-handler');
const User = require('../models/userModel');

const secure = asyncHandler(async (req, res, next) => {
    let token;
    if (req.cookies && req.cookies.jwt) {
        try {
            token = req.cookies.jwt;
            console.log("Token----->", req.user)
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            console.log("Decoded----->", req.user)
            req.user = await User.findById(decoded.id).select('-password');
            console.log("Auth----->", req.user)
            next();
        } catch (error) {
            res.status(401).json({ message: 'Not authorized, token failed' });
        }
    } else {
        res.status(401).json({ message: 'Please login again!' });
    }
});

module.exports = { secure };
