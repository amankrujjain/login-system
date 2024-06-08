// Import the Mongoose library
const mongoose = require('mongoose');

/**
 * User schema definition.
 * Defines the structure of the User documents in MongoDB.
 */
const userSchema = mongoose.Schema({
    username: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
        unique: true,
    },
    password: {
        type: String,
        required: true,
    },
    is_loggedin: {
        type: Boolean,
        required: false,
        default: false,
    }
});

/**
 * User model based on the userSchema.
 * Represents the User collection in MongoDB.
 */
const User = mongoose.model("User", userSchema);

// Export the User model for use in other parts of the application
module.exports = User;
