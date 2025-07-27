import express from 'express';
import { getAllUser, login, logout, register, verifyOtp } from '../controllers/user.controller.js';

export const userRoute = express.Router();

userRoute.get('/getAllUser', getAllUser);
userRoute.post('/register', register);
userRoute.post('/login', login);
userRoute.get('/logout', logout);
userRoute.post('/verify-otp', verifyOtp);