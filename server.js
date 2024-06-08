const express = require('express');
const dotenv = require('dotenv');
const connectDB = require('./config/db');
const userRoutes = require('./routes/userRoutes');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const xssClean = require('xss-clean');
const ExpressMongoSanitize = require('express-mongo-sanitize');
const cors = require('cors')

const app = express();
app.use(express.json());
dotenv.config();
connectDB();

const port = 8000;

app.use(cors({
    origin:'http://localhost:3000',
    credentials:true
}))

app.use(helmet());
app.use(xssClean());
app.use(ExpressMongoSanitize());

app.use(cookieParser());

app.use('/api/users', userRoutes);

app.listen(port,()=>{
    console.log(`Server running on port ${port}`);
});