import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    email:{
        type: String,
        required: true
    },
    password:{
        type: String,
        required: true
    },
    role:{
        type: String,
        enum: ["admin", "user"],
        default: "user"
    },
    phone:{
        type: String,
        required: true
    },
    dob:{
        type: Date,
        required: true
    },
    gender:{
        type: String,
        enum: ["male", "female","other"],
        required: true
    }

});

export const User = mongoose.model('User', userSchema);