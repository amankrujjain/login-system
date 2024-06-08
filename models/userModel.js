const mongoose = require('mongoose');

const userSchema = mongoose.Schema({
    username:{
        type:String,
        required:true,
    },
    email:{
        type:String,
        required:true,
        unique:true
    },
    password:{
        type:String,
        required:true
    },
    is_loggedin:{
        type:Boolean,
        required:false,
        default:false,
    }
});

const User = mongoose.model("User", userSchema);

module.exports = User;
