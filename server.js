// Import necessary libraries and modules
const express = require('express');
const dotenv = require('dotenv');
const connectDB = require('./config/db');
const userRoutes = require('./routes/userRoutes');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const xssClean = require('xss-clean');
const ExpressMongoSanitize = require('express-mongo-sanitize');
const cors = require('cors');

// Initialize Express application
const app = express();

// Middleware to parse JSON requests
app.use(express.json());

// Load environment variables from .env file
dotenv.config();

// Connect to MongoDB database
connectDB();

// Define the server port
const port = 8000;

// Enable CORS for the specified origin
app.use(cors({
    origin: process.env.FRONT_END_BASE_URL,
    credentials: true
}));

// Use Helmet to set various HTTP headers for security
app.use(helmet());

// Use xss-clean to sanitize user input
app.use(xssClean());

// Use express-mongo-sanitize to prevent MongoDB operator injection
app.use(ExpressMongoSanitize());

// Middleware to parse cookies
app.use(cookieParser());

// User routes for API endpoints
app.use('/api/users', userRoutes);

// Start the server and listen on the specified port
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
