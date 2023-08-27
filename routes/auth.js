const express = require('express');
const { query, body, check } = require('express-validator');

const authController = require('../controllers/auth');
const User = require('../models/user');

const router = express.Router();

router.get('/login', authController.getLogin);

router.get('/signup', authController.getSignup);

router.post('/login',
	[
		body('email')
			.isEmail()
			.withMessage('Please enter valid email')
			.normalizeEmail(),
		body('password', 'Enter a valid password')
			.trim()
			.isLength({ min: 5 })
	],
	authController.postLogin);

router.post('/signup',
	[
		check('email')
			.isEmail()
			.withMessage('Enter valid email')
			.custom((value, { req }) => {
				return User.findOne({ email: value })
					.then(user => {
						if (user) {
							return Promise.reject('Email already exist')
						}
					});
			})
			.escape()
			.normalizeEmail(),
		check('password', 'password must be of at least 5 characters')
			.trim()
			.isLength({ min: 5 })
			.escape(),
		body('confirmPassword')
			.trim()
			.custom((value, { req }) => {
				if (value !== req.body.password) {
					throw new Error('passwords have to match');
				}
				return true;
			})
			.escape(),
	],
	authController.postSignup);

router.post('/logout', authController.postLogout);

router.get('/reset', authController.getReset);

router.post('/reset', authController.postReset);

router.get('/reset/:token', authController.getNewPassword);

router.post('/new-password', authController.postNewPassword);

module.exports = router;
