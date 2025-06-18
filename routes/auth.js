const express = require('express');
const authController = require('../controller/authControllers');
const router = express.Router();
const { check } = require('express-validator');

// User Signup Route
router.post(
    '/signup',
    [
        // Validation checks for user signup
        check('name').not().isEmpty().escape().trim().withMessage('Name is required'),

        check('email').isEmail().normalizeEmail().withMessage('Invalid email address'),

        check('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long'),

        check('confirmPassword').custom((value, { req }) => value === req.body.password)
    ],

    authController.postSignup


);

// User Login Route
router.post(
    '/login',
    [
        // Validation checks for user login
        check('email').isEmail().normalizeEmail().withMessage('Invalid email address'),

        check('password').not().isEmpty().withMessage('Password is required')
    ],

    authController.postLogin
);

// Email verification route
router.post(
    '/verify-email',
    [
        // Validation checks for email verification
        check('email').isEmail().normalizeEmail().withMessage('Invalid email address'),

        check('token').not().isEmpty().withMessage('Verification token is required'),

    ],

    authController.verifyEmail
);

// Password Reset Request Route
router.post(
    '/request-password-reset',
    [
        // Validation checks for password reset request
        check('email').isEmail().normalizeEmail().withMessage('Invalid email address')
    ],

    authController.postPasswordResetRequest
);

// Password Reset Route
router.post(
    '/reset-password',
    [
        // Validation checks for password reset
        check('email').isEmail().normalizeEmail().withMessage('Invalid email address'),

        check('token').not().isEmpty().withMessage('Reset token is required'),

        check('newPassword').isLength({ min: 8 }).withMessage('New password must be at least 8 characters long'),

        check('confirmNewPassword').custom((value, { req }) => value === req.body.newPassword)
    ],

    authController.postPasswordReset
);

// Signout Route
router.post('/logout', authController.postLogout);

module.exports = router;