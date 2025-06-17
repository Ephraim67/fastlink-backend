const User = require('../models/user');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { validationResult } = require('express-validator');
const sendVerificationEmail = require('../utils/sendVerificationEmail');
const jwt = require("jsonwebtoken");
const SECRET_KEY = process.env.JWT_SECRET;

// Check Secret Key
if (!SECRET_KEY) throw new Error("JWT_SECRET is not configured");

// Function to create a new user
exports.postSignup = async (req, res) => {
    const { name, email, password, confirmPassword } = req.body;
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        return res.status(422).json({ error: errors.array()[0].msg});
    }

    if (password !== confirmPassword) {
        return res.status(422).json({ error: "Passwords do not match" });
    }

    try {
        const existing = await User.findOne({ email });
        if (existing) {
            return res.status(409).json({ error: 'Email already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 12);

        const verificationToken = crypto.randomBytes(32).toString('hex');

        const user = new User({
            name,
            email,
            password: hashedPassword,
            isVerified: false,
            verificationToken,
        });

        await user.save();

        // send a verification email here
        const verificationLink = `http://localhost:3000/verify-email?token=${verificationToken}&email=${email}`;
        await sendVerificationEmail(email, "Verify your email", `Click the link to verify your email: ${verificationLink}`);


        return res.status(201).json({ message: "User created successfully. Please check your email to verify your account." });
    } catch (error) {
        console.error("Error creating user:", error);
        return res.status(500).json({ error: "Internal server error" });
    }

};

// JWT Sing Function
const generateToken = (user) => {
    return jwt.sign(
        {
            userId: user._id,
            email: user.email,
            isAdmin: user.isAdmin,
        },
        SECRET_KEY,
        { expiresIn: process.env.JWT_EXPIRATION || '1h' }
    );
}

// Function to handle user login
exports.postLogin = async (req, res) => {
    const { email, password } = req.body;
    const errors = ValidationResult(req);

    if (!errors.isEmpty()) {
        return res.status(422).json({ error: errors.array()[0].msg})
    }

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ error: 'User not found' });
        }

        if (!user.isVerified) {
            return res.status(403).json({ error: 'Please verify your email first. Check your inbox for the verification link.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Generate a token (if using JWT or similar)
        const token = generateToken(user)

        return res.status(200).json({
            message: 'Login successful',
            token,
            user: user.toDTO(),
            expiresIn: process.env.JWT_EXPIRES_IN || 3600
        });
    } catch (error) {
        console.error("Error during login:", error);
        return res.status(500).json({ error: "Internal server error" });
    }
}

// Email Verification function
exports.verifyEmail = async (req, res) => {
    const { token, email } = req.query;

    if (!token || !email) {
        return res.status(400).json({ error: 'Invalid request' });
    }

    try {
        const user = await User.findOne({
            email,
            verificationToken: token,
        });

        if (!user) {
            return res.status(404).json({ error: 'User not found or invalid token' });
        }

        user.isVerified = true;
        user.verificationToken = undefined; // Clear the token after verification
        await user.save();

        return res.status(200).json({ message: 'Email verified successfully' });
    } catch (error) {
        console.error("Error verifying email:", error);
        return res.status(500).json({ error: 'Internal server error' });
    }
};

// Function to handle password reset request
exports.postPasswordResetRequest = async (req, res) => {
    const { email } = req.body;
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        return res.status(422).json({ error: errors.array()[0].msg });
    }

    try {
        const user = await User.findOne({ email });

        // This function do not reveal if the user exists or not for security reasons
        if (!user) {
            return res.status(200).json({ message: 'If this email is registered, you will receive a password reset link.' });
        }

        // Generate a password reset token
        const resetToken = crypto.randomBytes(32).toString('hex');
        // const resetLink = `http://localhost:3000/reset-password?token=${resetToken}&email=${email}`;
        const resetTokenExpiry = Date.now() + 3600000; // 1 hour from now

        user.resetToken = resetToken;
        user.resetTokenExpiry = resetTokenExpiry;
        await user.save();

        // Send the reset link via email
        const resetLink = `http://localhost:3000/reset-password?token=${resetToken}&email=${email}`;
        await sendVerificationEmail(email, "Password Reset Request", `Click the link to reset your password: ${resetLink}\n\nThis link will expire in 1 hour.`);

        return res.status(200).json({ message: 'If this email is registered, you will receive a password reset link.' });

    } catch (error) {
        console.error("Error during password reset request:", error);
        return res.status(500).json({ error: 'Internal server error' });
    }

};

// Function to handle password reset endpoint
exports.postPasswordReset = async (req, res) => {
    const { token, email, newPassword, confirmPassword } = req.body;
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        return res.status(422).json({ error: errors.array()[0].msg});
    }

    if (newPassword !== confirmPassword) {
        return res.status(422).json({ error: "Passwords do not match" });
    }

    try {
        const user = await User.findOne({
            email,
            resetToken: token,
            resetTokenExpiry: { $gt: Date.now() } // Check if the token is still valid
        });

        if (!user) {
            return res.status(404).json({ error: 'Invalid or expired token' });
        }

        // Update the user's password
        const hashedPassword = await bcrypt.hash(newPassword, 12);
        user.password = hashedPassword;
        user.resetToken = undefined; // Clear the reset token
        user.resetTokenExpiry = undefined; // Clear the reset token expiry
        await user.save();

        return res.status(200).json({ message: 'Password reset successfully' });
    } catch (error) {
        console.error("Error during password reset:", error);
        return res.status(500).json({ error: 'Internal server error' });
    }
};

// Function to handle user logout
// JWT Logout is typically handled on the client side by removing the token from storage.
exports.postLogout = (req, res) => {
    // In a stateless JWT setup, logout is handled by removing the token from the client side.
    // If you are using sessions, you can destroy the session here.
    return res.status(200).json({ 
        message: 'Logged out successfully',
        success: true
    });
};