
import { User } from '../models/user.model.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { sendEmail, sendOtpEmail } from '../utils/mailer.js';
import crypto from 'crypto';



// Get all users with pagination, search, and filtering
export const getAllUser = async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const search = req.query.search || '';
    const sortBy = req.query.sortBy || 'createdAt';
    const sortOrder = req.query.sortOrder === 'asc' ? 1 : -1;
    const gender = req.query.gender || '';
    const verified = req.query.verified || '';

    // Build search query
    let searchQuery = {};
    
    if (search) {
      searchQuery = {
        $or: [
          { username: { $regex: search, $options: 'i' } },
          { email: { $regex: search, $options: 'i' } },
          { phone: { $regex: search, $options: 'i' } }
        ]
      };
    }

    // Add filters
    if (gender) {
      searchQuery.gender = gender;
    }
    
    if (verified !== '') {
      searchQuery.verified = verified === 'true';
    }

    // Calculate skip value for pagination
    const skip = (page - 1) * limit;

    // Get total count for pagination
    const totalUsers = await User.countDocuments(searchQuery);
    const totalPages = Math.ceil(totalUsers / limit);

    // Get users with pagination
    const users = await User.find(searchQuery)
      .select('-password')
      .sort({ [sortBy]: sortOrder })
      .skip(skip)
      .limit(limit);

    res.status(200).json({
      users,
      pagination: {
        currentPage: page,
        totalPages,
        totalUsers,
        hasNextPage: page < totalPages,
        hasPrevPage: page > 1,
        limit
      }
    });
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ message: 'Failed to fetch users', error: error.message });
  }
};

// Create a new user (admin only)
export const createUser = async (req, res) => {
  try {
    let { username, email, countryCode, phone, dob, gender, password, role } = req.body;

    // Validation
    if (!username || username.trim() === '') {
      return res.status(400).json({ success: false, error: "Username is required!" });
    }
    if (!email || email.trim() === '') {
      return res.status(400).json({ success: false, error: "Email is required!" });
    }
    if (!countryCode) {
      return res.status(400).json({ success: false, error: "Country code is required!" });
    }
    if (!phone) {
      return res.status(400).json({ success: false, error: "Phone is required!" });
    }
    if (!dob) {
      return res.status(400).json({ success: false, error: "Date of birth is required!" });
    }
    if (!gender) {
      return res.status(400).json({ success: false, error: "Gender is required!" });
    }
    if (!password || password.length < 8) {
      return res.status(400).json({ success: false, error: "Password must be at least 8 characters!" });
    }

    // Clean and validate data
    username = username.trim();
    email = email.trim().toLowerCase();
    phone = phone.trim().replace(/\D/g, '');
    gender = gender.trim().toLowerCase();
    role = role || 'user';

    // Email validation
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ success: false, error: "Please enter a valid email address!" });
    }

    if (username.length < 3 || username.length > 20) {
      return res.status(400).json({ success: false, error: "Username must be 3-20 characters!" });
    }

    if (phone.length !== 10) {
      return res.status(400).json({ success: false, error: "Phone number must be 10 digits!" });
    }

    const dobDate = new Date(dob);
    if (isNaN(dobDate.getTime())) {
      return res.status(400).json({ success: false, error: "Birth date is invalid!" });
    }

    const today = new Date();
    const minAgeDate = new Date(today.getFullYear() - 18, today.getMonth(), today.getDate());
    if (dobDate > minAgeDate) {
      return res.status(400).json({ success: false, error: "You must be at least 18 years old!" });
    }

    // Check for existing user
    const existingUser = await User.findOne({
      $or: [
        { email: email },
        { username: username },
        { phone: phone }
      ]
    });

    if (existingUser) {
      if (existingUser.email === email) {
        return res.status(400).json({ success: false, error: "Email already registered!" });
      }
      if (existingUser.username === username) {
        return res.status(400).json({ success: false, error: "Username taken!" });
      }
      if (existingUser.phone === phone) {
        return res.status(400).json({ success: false, error: "Phone number already used!" });
      }
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create user
    const newUser = new User({
      username,
      email,
      countryCode,
      phone,
      dob: dobDate,
      gender,
      password: hashedPassword,
      role,
      verified: true // Admin created users are verified by default
    });

    await newUser.save();

    // Return user without password
    const userResponse = newUser.toObject();
    delete userResponse.password;

    res.status(201).json({
      success: true,
      message: 'User created successfully',
      user: userResponse
    });

  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).json({ success: false, error: "Failed to create user" });
  }
};

// Get user by ID
export const getUserById = async (req, res) => {
  try {
    const { id } = req.params;
    
    if (!id) {
      return res.status(400).json({ success: false, error: "User ID is required" });
    }

    const user = await User.findById(id).select('-password');
    
    if (!user) {
      return res.status(404).json({ success: false, error: "User not found" });
    }

    res.status(200).json({
      success: true,
      user
    });
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ success: false, error: "Failed to fetch user" });
  }
};

// Update user
export const updateUser = async (req, res) => {
  try {
    const { id } = req.params;
    const { username, email, countryCode, phone, dob, gender, role, verified } = req.body;

    if (!id) {
      return res.status(400).json({ success: false, error: "User ID is required" });
    }

    // Check if user exists
    const existingUser = await User.findById(id);
    if (!existingUser) {
      return res.status(404).json({ success: false, error: "User not found" });
    }

    // Build update object
    const updateData = {};
    
    if (username && username.trim() !== '') {
      if (username.length < 3 || username.length > 20) {
        return res.status(400).json({ success: false, error: "Username must be 3-20 characters!" });
      }
      updateData.username = username.trim();
    }

    if (email && email.trim() !== '') {
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({ success: false, error: "Please enter a valid email address!" });
      }
      updateData.email = email.trim().toLowerCase();
    }

    if (countryCode) {
      updateData.countryCode = countryCode;
    }

    if (phone && phone.trim() !== '') {
      const cleanPhone = phone.trim().replace(/\D/g, '');
      if (cleanPhone.length !== 10) {
        return res.status(400).json({ success: false, error: "Phone number must be 10 digits!" });
      }
      updateData.phone = cleanPhone;
    }

    if (dob) {
      const dobDate = new Date(dob);
      if (isNaN(dobDate.getTime())) {
        return res.status(400).json({ success: false, error: "Birth date is invalid!" });
      }
      updateData.dob = dobDate;
    }

    if (gender && gender.trim() !== '') {
      updateData.gender = gender.trim().toLowerCase();
    }

    if (role) {
      updateData.role = role;
    }

    if (typeof verified === 'boolean') {
      updateData.verified = verified;
    }

    // Check for duplicate email/username/phone if being updated
    if (updateData.email || updateData.username || updateData.phone) {
      const duplicateQuery = {
        _id: { $ne: id } // Exclude current user
      };

      if (updateData.email) {
        duplicateQuery.email = updateData.email;
      }
      if (updateData.username) {
        duplicateQuery.username = updateData.username;
      }
      if (updateData.phone) {
        duplicateQuery.phone = updateData.phone;
      }

      const duplicateUser = await User.findOne(duplicateQuery);
      if (duplicateUser) {
        if (duplicateUser.email === updateData.email) {
          return res.status(400).json({ success: false, error: "Email already registered!" });
        }
        if (duplicateUser.username === updateData.username) {
          return res.status(400).json({ success: false, error: "Username taken!" });
        }
        if (duplicateUser.phone === updateData.phone) {
          return res.status(400).json({ success: false, error: "Phone number already used!" });
        }
      }
    }

    // Update user
    const updatedUser = await User.findByIdAndUpdate(
      id,
      updateData,
      { new: true, runValidators: true }
    ).select('-password');

    res.status(200).json({
      success: true,
      message: 'User updated successfully',
      user: updatedUser
    });

  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({ success: false, error: "Failed to update user" });
  }
};

// Delete user
export const deleteUser = async (req, res) => {
  try {
    const { id } = req.params;

    if (!id) {
      return res.status(400).json({ success: false, error: "User ID is required" });
    }

    // Check if user exists
    const existingUser = await User.findById(id);
    if (!existingUser) {
      return res.status(404).json({ success: false, error: "User not found" });
    }

    // Delete user
    await User.findByIdAndDelete(id);

    res.status(200).json({
      success: true,
      message: 'User deleted successfully'
    });

  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ success: false, error: "Failed to delete user" });
  }
};

// Search users (alternative to getAllUser with search)
export const searchUsers = async (req, res) => {
  try {
    const { q, page = 1, limit = 10 } = req.query;
    
    if (!q || q.trim() === '') {
      return res.status(400).json({ success: false, error: "Search query is required" });
    }

    const searchQuery = {
      $or: [
        { username: { $regex: q.trim(), $options: 'i' } },
        { email: { $regex: q.trim(), $options: 'i' } },
        { phone: { $regex: q.trim(), $options: 'i' } }
      ]
    };

    const skip = (parseInt(page) - 1) * parseInt(limit);
    const totalUsers = await User.countDocuments(searchQuery);
    const totalPages = Math.ceil(totalUsers / parseInt(limit));

    const users = await User.find(searchQuery)
      .select('-password')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    res.status(200).json({
      success: true,
      users,
      pagination: {
        currentPage: parseInt(page),
        totalPages,
        totalUsers,
        hasNextPage: parseInt(page) < totalPages,
        hasPrevPage: parseInt(page) > 1,
        limit: parseInt(limit)
      }
    });

  } catch (error) {
    console.error('Error searching users:', error);
    res.status(500).json({ success: false, error: "Failed to search users" });
  }
};

export const register = async (req, res) => {
  let { username, email, countryCode, phone, dob, gender, password } = req.body;


  if (!username || username.trim() === '') {
    return res.status(400).send({ success: false, error: "Username is required!" });
  }
  if (!email || email.trim() === '') {
    return res.status(400).send({ success: false, error: "Email is required!" });
  }
  if (!countryCode) {
    return res.status(400).send({ success: false, error: "Country code is required!" });
  }
  if (!phone) {
    return res.status(400).send({ success: false, error: "Phone is required!" });
  }
  if (!dob) {
    return res.status(400).send({ success: false, error: "Date of birth is required!" });
  }
  if (!gender) {
    return res.status(400).send({ success: false, error: "Gender is required!" });
  }
  if (!password || password.length < 8) {
    return res.status(400).send({ success: false, error: "Password must be at least 8 characters!" });
  }

  username = username.trim();
  email = email.trim().toLowerCase();
  phone = phone.trim().replace(/\D/g, '');
  gender = gender.trim().toLowerCase();

  // Email validation
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    console.error('Registration Error: Invalid email format', { email });
    return res.status(400).send({ success: false, error: "Please enter a valid email address!" });
  }

  if (username.length < 3 || username.length > 20) {
    console.error('Registration Error: Invalid username length', { username });
    return res.status(400).send({ success: false, error: "Username must be 3-20 characters!" });
  }

  if (phone.length !== 10) {
    console.error('Registration Error: Invalid phone number length', { phone });
    return res.status(400).send({ success: false, error: "Phone number must be 10 digits!" });
  }

  const dobDate = new Date(dob);
  if (isNaN(dobDate.getTime())) {
    console.error('Registration Error: Invalid date format', { dob });
    return res.status(400).send({ success: false, error: "Birth date is invalid!" });
  }

  const today = new Date();
  const minAgeDate = new Date(today.getFullYear() - 18, today.getMonth(), today.getDate());
  if (dobDate > minAgeDate) {
    console.error('Registration Error: User under 18 years old', { dob });
    return res.status(400).send({ success: false, error: "You must be at least 18 years old!" });
  }

  try {
    const existingUser = await User.findOne({
      $or: [
        { email: email },
        { username: username },
        { phone: phone }
      ]
    });

    if (existingUser) {
      if (existingUser.email === email) {
        console.error('Registration Error: Email already exists', { email });
        return res.status(400).send({ success: false, error: "Email already registered!" });
      }
      if (existingUser.username === username) {
        console.error('Registration Error: Username already exists', { username });
        return res.status(400).send({ success: false, error: "Username taken!" });
      }
      if (existingUser.phone === phone) {
        console.error('Registration Error: Phone number already exists', { phone });
        return res.status(400).send({ success: false, error: "Phone number already used!" });
      }
    }
  } catch (err) {
    console.error("Registration Error: Database check failed", { error: err.message, stack: err.stack });
    return res.status(500).send({ success: false, error: "Server error checking user!" });
  }

  let hashedPassword;
  try {
    hashedPassword = await bcrypt.hash(password, 10);
  } catch (err) {
    console.error("Registration Error: Password hashing failed", { error: err.message, stack: err.stack });
    return res.status(500).send({ success: false, error: "Server error!" });
  }

  // Generate OTP
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
  const role = "user";
  try {
    // Save user with OTP and not verified
    const users = await User.find();
    if (users.length == 0) {
      role = "admin";
    }
    const newUser = new User({
      username: username,
      email: email,
      countryCode: countryCode,
      role: role,
      phone: phone,
      dob: dobDate,
      gender: gender,
      password: hashedPassword,
      otp,
      otpExpires
    });
    await newUser.save();
    await sendOtpEmail(email, otp);
    return res.status(201).send({
      success: true,
      message: "OTP sent to your email. Please verify to complete registration.",
      userId: newUser._id
    });
  } catch (err) {
    console.error("Registration Error: User creation failed", {
      error: err.message,
      stack: err.stack,
      userData: {
        username,
        email,
        phone: '***',
        countryCode,
        gender
      }
    });
    return res.status(500).send({ success: false, error: "Error creating account!" });
  }
};

export const verifyOtp = async (req, res) => {
  const { userId, otp } = req.body;
  if (!userId || !otp) {
    return res.status(400).json({ success: false, error: 'User ID and OTP are required.' });
  }
  try {
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found.' });
    }
    if (!user.otp || !user.otpExpires || user.otp !== otp) {
      return res.status(400).json({ success: false, error: 'Invalid OTP.' });
    }
    if (user.otpExpires < new Date()) {
      return res.status(400).json({ success: false, error: 'OTP expired.' });
    }
    user.verified = true;
    user.otp = undefined;
    user.otpExpires = undefined;
    
    await user.save();
    return res.status(200).json({ success: true, message: 'OTP verified. Registration complete.' });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Server error.' });
  }
};

export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email: email.toLowerCase() });

    if (!user) {
      return res.status(401).json({ success: false, error: "Invalid email" });
    }

    const isPasswordMatch = await bcrypt.compare(password, user.password);

    if (!isPasswordMatch) {
      return res.status(401).json({ success: false, error: "Invalid password" });
    }


    if (!user.verified) {
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

      user.otp = otp;
      user.otpExpires = otpExpires;
      await user.save();

      // Send OTP (you must have this implemented)
      await sendOtpEmail(user.email, otp);

      return res.status(403).json({
        success: false,
        requiresOtp: true,
        message: "OTP sent to your email. Please verify to complete login.",
        userId: user._id
      });
    }

    if (user.role !== "admin") {
      return res.status(401).json({ success: false, error: "User Panel Coming soon" });
    }

    const token = jwt.sign({ userId: user._id }, process.env.SECRET_KEY, {
      expiresIn: "7d",
    });

    res
      .status(200)
      .cookie("token", token, {
        httpOnly: true,
        sameSite: "Lax",
        secure: false,
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      })
      .json({
        success: true,
        message: "Login successful",
        user: {
          name: user.username,
          email: user.email,
          _id: user._id,
        },
        token,
      });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ success: false, error: "Internal server error" });
  }
};


export const logout = async (_, res) => {
  try {
    return res.cookie("token", "", { maxAge: 0 }).json({
      message: 'Logged out successfully.',
      success: true
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      message: "Internal server error!",
      success: false,
    });
  }
}



export const getForgotPassword = async (req, res) => {
  try {
    const email = req.body.email;

    if (!email) {
      return res.status(400).json({ success: false, error: 'Email is required' });
    }

    const user = await User.findOne({ email: email.toLowerCase() });

    if (!user) {
      // To prevent email enumeration
      return res.status(200).json({ success: true, message: 'If that email is registered, a reset link will be sent.' });
    }

    // Generate a reset token (random string)
    const resetToken = crypto.randomBytes(32).toString('hex');

    // Hash the token before saving in DB
    const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');

    // Set token expiration (1 hour)
    const resetTokenExpires = Date.now() + 3600000;

    // Save hashed token and expiration to user document
    user.resetPasswordToken = hashedToken;
    user.resetPasswordExpires = resetTokenExpires;

    await user.save();

    // Create reset link with plain token (not hashed)
    const resetUrl = `${process.env.FRONTEND_URL}reset-password/${resetToken}`;

    // Send email
    const message = `
      <p>You requested a password reset. Click the link below to reset your password:</p>
      <a href="${resetUrl}" target="_blank">${resetUrl}</a>
      <p>If you did not request this, please ignore this email.</p>
    `;

    await sendEmail({
      to: email,
      subject: 'Password Reset Request',
      message: message,
    });

    return res.status(200).json({
      success: true,
      message: 'If that email is registered, a reset link will be sent.',
    });

  } catch (error) {
    console.error('Forgot Password Error:', error);
    return res.status(500).json({ success: false, error: 'Server error' });
  }
};

export const getResetPassword = async (req, res) => {
  try {
    const { token } = req.params;
    const { password } = req.body;
    

    if (!password || password.trim().length < 6) {
      return res.status(400).json({
        success: false,
        message: 'New password is required and should be at least 6 characters long'
      });
    }

    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    const user = await User.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ success: false, message: 'Invalid or expired reset token' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    user.password = hashedPassword;

    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;

    await user.save();

    return res.status(200).json({ success: true, message: 'Password has been reset successfully' });

  } catch (error) {
    console.error('Error in getResetPassword:', error);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
};



export const getTodaysRegistrations = async (req, res) => {
  try {
    const start = new Date();
    start.setHours(0, 0, 0, 0);
    const end = new Date();
    end.setHours(23, 59, 59, 999);

    const count = await User.countDocuments({
      createdAt: { $gte: start, $lte: end }
    });

    res.json({ count });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
};

export const getThisWeekRegistrations = async (req, res) => {
  try {
    const today = new Date();
    today.setHours(23, 59, 59, 999);

    const days = [];

    for (let i = 6; i >= 0; i--) {
      const start = new Date(today);
      start.setDate(today.getDate() - i);
      start.setHours(0, 0, 0, 0);

      const end = new Date(start);
      end.setHours(23, 59, 59, 999);

      const count1 = await User.find({
        createdAt: { $gte: start, $lte: end },
      });
      console.log(count1);

      const count = await User.countDocuments({
        createdAt: { $gte: start, $lte: end },
      });

      days.push({

        date: start.toLocaleDateString('en-CA'),
        count,
      });
    }

    res.json({ days });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
};


export const getMonthlyRegistrations = async (req, res) => {
  try {
    const today = new Date();
    const Months = [];

    for (let i = 12; i >= 0; i--) {
      const start = new Date(today.getFullYear(), today.getMonth() - i, 1);
      const end = new Date(today.getFullYear(), today.getMonth() - i + 1, 0, 23, 59, 59, 999);

      const count = await User.countDocuments({
        createdAt: { $gte: start, $lte: end },
      });

      Months.push({
        month: start.toLocaleDateString('en-CA', { year: 'numeric', month: 'short' }), // e.g., "2025-Jul"
        count,
      });
    }

    res.json({ Months });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
};



// 2. Total registrations by period (week, month, year)
export const getRegistrationsByPeriod = async (req, res) => {
  try {
    const { period } = req.query; // 'day', 'week', 'month', 'year'
    const now = new Date();
    let start, end, pipeline;

    if (period === 'day') {
      // Last 7 days
      start = new Date(now.getFullYear(), now.getMonth(), now.getDate() - 6);
      end = new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1);
      
      pipeline = [
        { $match: { createdAt: { $gte: start, $lt: end } } },
        {
          $group: {
            _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
            count: { $sum: 1 }
          }
        },
        { $sort: { _id: 1 } }
      ];
    } else if (period === 'week') {
      // Last 7 weeks
      start = new Date(now.getFullYear(), now.getMonth(), now.getDate() - (7 * 6));
      end = new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1);
      
      pipeline = [
        { $match: { createdAt: { $gte: start, $lt: end } } },
        {
          $group: {
            _id: {
              year: { $year: "$createdAt" },
              week: { $week: "$createdAt" }
            },
            count: { $sum: 1 }
          }
        },
        { $sort: { "_id.year": 1, "_id.week": 1 } }
      ];
    } else if (period === 'month') {
      // Last 12 months
      start = new Date(now.getFullYear(), now.getMonth() - 11, 1);
      end = new Date(now.getFullYear(), now.getMonth() + 1, 1);
      
      pipeline = [
        { $match: { createdAt: { $gte: start, $lt: end } } },
        {
          $group: {
            _id: { $dateToString: { format: "%Y-%m", date: "$createdAt" } },
            count: { $sum: 1 }
          }
        },
        { $sort: { _id: 1 } }
      ];
    } else if (period === 'year') {
      // Last 5 years
      start = new Date(now.getFullYear() - 4, 0, 1);
      end = new Date(now.getFullYear() + 1, 0, 1);
      
      pipeline = [
        { $match: { createdAt: { $gte: start, $lt: end } } },
        {
          $group: {
            _id: { $dateToString: { format: "%Y", date: "$createdAt" } },
            count: { $sum: 1 }
          }
        },
        { $sort: { _id: 1 } }
      ];
    } else {
      // Default: last 5 years
      start = new Date(now.getFullYear() - 4, 0, 1);
      end = new Date(now.getFullYear() + 1, 0, 1);
      
      pipeline = [
        { $match: { createdAt: { $gte: start, $lt: end } } },
        {
          $group: {
            _id: { $dateToString: { format: "%Y", date: "$createdAt" } },
            count: { $sum: 1 }
          }
        },
        { $sort: { _id: 1 } }
      ];
    }

    // MongoDB aggregation
    const data = await User.aggregate(pipeline);

    // Build complete result array with proper labels
    let result = [];
    const range = period === 'day' ? 7 : period === 'week' ? 7 : period === 'month' ? 12 : 5;

    for (let i = 0; i < range; i++) {
      let label, key;
      
      if (period === 'day') {
        const d = new Date(start.getFullYear(), start.getMonth(), start.getDate() + i);
        label = d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
        key = d.toISOString().slice(0, 10);
      } else if (period === 'week') {
        const d = new Date(start.getFullYear(), start.getMonth(), start.getDate() + (i * 7));
        const year = d.getFullYear();
        const week = getWeekNumber(d);
        label = `W${week} ${year}`;
        key = `${year}-${week.toString().padStart(2, '0')}`;
      } else if (period === 'month') {
        const d = new Date(start.getFullYear(), start.getMonth() + i, 1);
        label = d.toLocaleString('en-US', { month: 'short', year: 'numeric' });
        key = d.toISOString().slice(0, 7);
      } else {
        const d = new Date(start.getFullYear() + i, 0, 1);
        label = d.getFullYear().toString();
        key = d.getFullYear().toString();
      }

      // Find matching data
      let found;
      if (period === 'week') {
        const year = parseInt(key.split('-')[0]);
        const week = parseInt(key.split('-')[1]);
        found = data.find(item => item._id.year === year && item._id.week === week);
      } else {
        found = data.find(item => item._id === key);
      }

      result.push({ 
        label, 
        count: found ? found.count : 0 
      });
    }

    res.json({ data: result });
  } catch (err) {
    console.error('Error in getRegistrationsByPeriod:', err);
    res.status(500).json({ error: "Server error" });
  }
};

// Helper to get ISO week number
function getWeekNumber(date) {
  const d = new Date(Date.UTC(date.getFullYear(), date.getMonth(), date.getDate()));
  const dayNum = d.getUTCDay() || 7;
  d.setUTCDate(d.getUTCDate() + 4 - dayNum);
  const yearStart = new Date(Date.UTC(d.getUTCFullYear(),0,1));
  return Math.ceil((((d - yearStart) / 86400000) + 1)/7);
}

// 3. Gender pie chart data
export const getGenderDistribution = async (req, res) => {
  try {
    const genders = await User.aggregate([
      {
        $group: {
          _id: "$gender",
          count: { $sum: 1 }
        }
      }
    ]);
    // Format as { male: X, female: Y }
    const result = {};
    genders.forEach(g => {
      result[g._id] = g.count;
    });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
};
