const express = require('express');
const { check } = require('express-validator');
const authController = require('../controller/authController');
// const hashPassword = require('../middlewares/hashPassword');

const router = express.Router();

router.post(
  '/signup',
  [
    check('name').notEmpty().withMessage('Name is required'),
    check('email').isEmail().withMessage('Valid email is required'),
    check('password')
      .isLength({ min: 6 })
      .withMessage('Password must be at least 6 characters'),
    
  ],
  authController.postSignup
);

module.exports = router;
