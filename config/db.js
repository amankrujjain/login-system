const mongoose = require('mongoose');
const dotenv =require('dotenv');

dotenv.config();

const connectDB = async()=>{
    try {
        await mongoose.connect(process.env.MONGO_URI);
        console.log('MongoBD connected');
    } catch (error) {
        console.log(`Error : ${error}`);
    };
};

module.exports = connectDB