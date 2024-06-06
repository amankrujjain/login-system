const express = require('express');
const dotenv = require('dotenv');
const connectDB = require('./config/db');
const userRoutes = require('./routes/userRoutes');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const xssClean = require('xss-clean');
const ExpressMongoSanitize = require('express-mongo-sanitize');

dotenv.config();
connectDB();

const port = 8000;

const app = express();

app.use(helmet());
app.use(xssClean());
app.use(ExpressMongoSanitize());

app.use(express.json());
app.use(cookieParser());

app.use('/api/users', userRoutes);

app.listen(port,()=>{
    console.log(`Server running on port ${port}`);
});