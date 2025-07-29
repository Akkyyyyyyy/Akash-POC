import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: [true, 'Username is required'],
        trim: true,
        minlength: [3, 'Username must be at least 3 characters long'],
        maxlength: [30, 'Username cannot exceed 30 characters']
    },
    email:{
        type: String,
        required: [true, 'Email is required'],
        unique: true,
        lowercase: true,
        trim: true,
        match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email address'],
        unique: true
    },
    password:{
        type: String,
        required: [true, 'Password is required'],
        minlength: [6, 'Password must be at least 6 characters long']
    },
    role:{
        type: String,
        enum: ["admin", "user"],
        default: "user"
    },
    countryCode: {
        type: String,
        required: [true, 'Country code is required']
    },
    phone:{
        type: String,
        required: [true, 'Phone number is required'],
        unique: true,
        trim: true,
        match: [/^\d{10}$/, 'Phone number must be exactly 10 digits'],
        unique: true
    },
    dob:{
        type: Date,
        required: [true, 'Date of birth is required'],
        validate: {
            validator: function(v) {
                return v <= new Date();
            },
            message: 'Date of birth cannot be in the future'
        }
    },
    gender:{
        type: String,
        enum: {
            values: ["male", "female", "other"],
            message: 'Gender must be male, female, or other'
        },
        required: [true, 'Gender is required']
    },
    otp: {
        type: String,
        required: false
    },
    otpExpires: {
        type: Date,
        required: false
    },
    verified:{
        type: Boolean,
        default: false
    },
    resetPasswordToken: { 
        type: String
    },
    resetPasswordExpires: { 
        type: Date
    }
},{timestamps:true});



export const User = mongoose.model('User', userSchema);