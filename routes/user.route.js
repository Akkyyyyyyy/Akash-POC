import express from 'express';
import { 
  getAllUser, 
  getForgotPassword, 
  getGenderDistribution, 
  getMonthlyRegistrations, 
  getRegistrationsByPeriod, 
  getResetPassword, 
  getThisWeekRegistrations, 
  getTodaysRegistrations, 
  getUserById, 
  login, 
  logout, 
  register, 
  updateUser, 
  verifyOtp,
  createUser,
  deleteUser,
  searchUsers
} from '../controllers/user.controller.js';
import isAuthenticated from '../middleware/isAuthenticated.js';

export const userRoute = express.Router();

// Authentication routes
userRoute.post('/register', register);
userRoute.post('/login', login);
userRoute.get('/logout', logout);
userRoute.post('/verify-otp', verifyOtp);
userRoute.post('/forgot', getForgotPassword);
userRoute.post('/reset-password/:token', getResetPassword);

// Dashboard routes
userRoute.get('/dashboard/today', getTodaysRegistrations);
userRoute.get('/dashboard/week', getThisWeekRegistrations);
userRoute.get('/dashboard/monthly', getMonthlyRegistrations);
userRoute.get('/dashboard/period', getRegistrationsByPeriod);
userRoute.get('/dashboard/gender', getGenderDistribution);

// User management routes (CRUD operations)
userRoute.get('/users', getAllUser); // Get all users with pagination
userRoute.get('/users/search', isAuthenticated, searchUsers); // Search users
userRoute.get('/users/:id', isAuthenticated, getUserById); // Get user by ID
userRoute.post('/users', isAuthenticated, createUser); // Create new user
userRoute.put('/users/:id', isAuthenticated, updateUser); // Update user
userRoute.delete('/users/:id', isAuthenticated, deleteUser); // Delete user

// Legacy route (keep for backward compatibility)
userRoute.get('/getAllUser', getAllUser);
userRoute.post('/updateUser', isAuthenticated, updateUser);
userRoute.get('/getUser/:id', getUserById);