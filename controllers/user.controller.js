
import { User } from '../models/user.model.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { sendOtpEmail } from '../utils/mailer.js';

console.log("Loaded SECRET_KEY in controller:", process.env.SECRET_KEY);

export const getAllUser = async (req, res) => {
    try {
        const users = await User.find().select('-password');
        res.status(200).json(users);
    } catch (error) {
        res.status(500).json({ message: 'Failed to fetch users', error: error.message });
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

  try {
    // Save user with OTP and not verified
    const newUser = new User({
      username: username,
      email: email,
      countryCode: countryCode,
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
    console.log("Received login:", email, password);

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      console.log("No user found for email:", email);
      return res.status(401).json({ success: false, error: "Invalid email" });
    }

    const isPasswordMatch = await bcrypt.compare(password, user.password);
    console.log("Password match:", isPasswordMatch);

    if (!isPasswordMatch) {
      return res.status(401).json({ success: false, error: "Invalid password" });
    }

    // All good, proceed
  const token = jwt.sign({ userId: user._id }, process.env.SECRET_KEY, {
  expiresIn: "7d",
});

    res
      .status(200)
      .cookie("token", token, {
        httpOnly: true,
        sameSite: "Lax",
        secure: false,
        maxAge: 7 * 24 * 60 * 60 * 1000,
      })
      .json({
        success: true,
        message: "Login successful",
        user: {
          name: user.name,
          email: user.email,
          _id: user._id,
        },
        token,
      });
  } catch (err) {
    console.log("Login error:", err);
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

// 2. Total registrations by period (week, month, year)
export const getRegistrationsByPeriod = async (req, res) => {
  try {
    const { period } = req.query; // 'week', 'month', 'year'
    let start = new Date();

    if (period === 'week') {
      start.setDate(start.getDate() - 7);
    } else if (period === 'month') {
      start.setMonth(start.getMonth() - 1);
    } else if (period === 'year') {
      start.setFullYear(start.getFullYear() - 1);
    } else {
      // Default: all time
      start = new Date(0);
    }

    const count = await User.countDocuments({
      createdAt: { $gte: start }
    });

    res.json({ count });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
};

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

