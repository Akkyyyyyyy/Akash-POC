import User from './User';

// Validation middleware for user registration
export const validateRegistration = async (req, res, next) => {
    try {
        const { username, email, phone, password } = req.body;

        // Check for required fields
        if (!username || !email || !phone || !password) {
            return res.status(400).json({
                message: "All fields are required!",
                success: false,
            });
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({
                message: "Please enter a valid email address!",
                success: false,
            });
        }

        // Validate phone number format (10 digits)
        const phoneRegex = /^\d{10}$/;
        if (!phoneRegex.test(phone)) {
            return res.status(400).json({
                message: "Phone number must be exactly 10 digits!",
                success: false,
            });
        }

        // Validate username length
        if (username.length < 3 || username.length > 30) {
            return res.status(400).json({
                message: "Username must be between 3 and 30 characters!",
                success: false,
            });
        }

        // Validate password length
        if (password.length < 6) {
            return res.status(400).json({
                message: "Password must be at least 6 characters long!",
                success: false,
            });
        }

        // Check if email already exists
        const existingEmail = await User.findOne({ email: email.toLowerCase() });
        if (existingEmail) {
            return res.status(400).json({
                message: "Email already exists!",
                success: false,
            });
        }

        // Check if phone number already exists
        const existingPhone = await User.findOne({ phone });
        if (existingPhone) {
            return res.status(400).json({
                message: "Phone number already exists!",
                success: false,
            });
        }

        // Check if username already exists
        const existingUsername = await User.findOne({ username });
        if (existingUsername) {
            return res.status(400).json({
                message: "Username already exists!",
                success: false,
            });
        }

        next();
    } catch (error) {
        console.error('Validation error:', error);
        return res.status(500).json({
            message: "Validation error occurred!",
            success: false,
        });
    }
};

// Validation middleware for login
export const validateLogin = (req, res, next) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                message: "Email and password are required!",
                success: false,
            });
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({
                message: "Please enter a valid email address!",
                success: false,
            });
        }

        next();
    } catch (error) {
        console.error('Login validation error:', error);
        return res.status(500).json({
            message: "Validation error occurred!",
            success: false,
        });
    }
}; 