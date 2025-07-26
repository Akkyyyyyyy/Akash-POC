import express from 'express';
import { getAllUser, login, logout, register } from '../controllers/user.controller.js';

export const userRoute = express.Router();

userRoute.get('/getAllUser', getAllUser);
userRoute.post('/register', register);
userRoute.post('/login', login);
userRoute.get('/logout', logout);