const User = require('../models/user');
const bcrypt = require('bcrypt');
const { validationResult } = require('express-validator');

exports.postSignup = async (req, res) => {
    const { name, email, password, confirmPassword } = req.body;


    // Run validation result check
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        console.log('Validation errors:', errors.array());
        return res.status(422).json({ error: errors.array()[0].msg });
    }

    // Check if passwords match
    if (password !== confirmPassword) {
        console.log('Password mismatch detected');
        return res.status(422).json({ error: "Password do not match" });
    }

    try {
        // Check for existing user
        const existing = await User.findOne({ email });
        if (existing) {
            console.log('Signup failed: Email already exists');
            return res.status(409).json({ error: "Email already exist." });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 12);

        // Create and save the user
        const user = new User({
            name,
            email,
            password: hashedPassword,
            isVerified: false
        });

        await user.save();

        console.log('User created successfully:', user.email);
        return res.status(201).json({ message: 'User created successfully.' });

    } catch (error) {
        console.error("Error creating user:", error);
        return res.status(500).json({ error: "Internal server error." });
    }
};
