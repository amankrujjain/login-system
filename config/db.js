// Import necessary libraries
const mongoose = require('mongoose');
const dotenv = require('dotenv');

// Load environment variables from .env file
dotenv.config();

/**
 * Function to connect to the MongoDB database.
 * Utilizes Mongoose to establish the connection.
 */
const connectDB = async () => {
    try {
        // Connect to MongoDB using the connection string from environment variables
        await mongoose.connect(process.env.MONGO_URI);
        console.log('MongoDB connected');
    } catch (error) {
        // Log any errors that occur during connection
        console.log(`Error : ${error}`);
    }
};

// Export the connectDB function for use in other parts of the application
module.exports = connectDB;
