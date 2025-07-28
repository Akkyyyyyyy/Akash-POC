import express from 'express';
import { getAllUser, getGenderDistribution, getRegistrationsByPeriod, getTodaysRegistrations, login, logout, register, verifyOtp } from '../controllers/user.controller.js';

export const userRoute = express.Router();

userRoute.get('/getAllUser', getAllUser);
userRoute.post('/register', register);
userRoute.post('/login', login);
userRoute.get('/logout', logout);
userRoute.post('/verify-otp', verifyOtp);
userRoute.get('/dashboard/today', getTodaysRegistrations);
userRoute.get('/dashboard/period', getRegistrationsByPeriod);
userRoute.get('/dashboard/gender', getGenderDistribution);