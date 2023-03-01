/**
 * User auth controllers
 * @author Zain Asif
 */
const Users = require('../models/Users');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bcryptSalt = process.env.BCRYPT_SALT || 10;
const { REFRESH_TOKEN_SECRET } = process.env;
const { generateAccessToken, generateRefreshToken } = require('../utils/generateTokens');

/**
 * Login
 * @param {object} req
 * @param {object} res
 */
exports.login = async (req, res) => {
  try {
    // Getting email and password
    const { email, password } = req.body;

    // Getting user from db
    const user = await Users.findOne({ email });

    if (!user) {
      // If user not found
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Comparing password
    const isMatched = bcrypt.compareSync(password, user.password);

    if (!isMatched) {
      // If password not matched
      return res.status(400).json({ success: false, message: 'Invalid Password' });
    }

    // Creating payload with user object
    delete user.password; // Removing password from user object

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    user.refreshToken = refreshToken;
    await user.save();

    res.json({ success: true, accessToken, refreshToken, user });
  } catch (err) {
    // Error handling
    // eslint-disable-next-line no-console
    console.log('Error ----> ', err);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

/**
 * Generate new access token
 * @param {object} req
 * @param {object} res
 */
exports.token = async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) return res.sendStatus(401);

    const user = Users.find({ refreshToken, password: 0 });

    if (!user) return res.sendStatus(404);

    jwt.verify(refreshToken, REFRESH_TOKEN_SECRET, (err, decoded) => {
      if (err) return res.sendStatus(403);

      const accessToken = generateAccessToken(decoded.user);

      res.json({
        accessToken,
      });
    });
  } catch (err) {
    // Error handling
    // eslint-disable-next-line no-console
    console.log('Error ----> ', err);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

/**
 * Change Password
 * @param {object} req
 * @param {object} res
 */
exports.changePassword = async (req, res) => {
  try {
    const { userId } = req.params;
    const { oldPassword, newPassword, confirmPassword } = req.body;

    if (newPassword !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message: 'New password and confirm password are not same',
      });
    }

    let user = await Users.findById(userId);

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const isMatched = bcrypt.compareSync(oldPassword, user.password);

    if (!isMatched) {
      return res.status(400).json({ success: false, message: 'Invalid old Password' });
    }

    // Generate token
    user.password = bcrypt.hashSync(newPassword, parseInt(bcryptSalt));

    await user.save();

    res.json({ success: true, user });
  } catch (err) {
    // Error handling
    // eslint-disable-next-line no-console
    console.log('Error ----> ', err);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
};

/**
 * Confirm auth
 * @param {object} req
 * @param {object} res
 */
exports.confirmAuth = async (req, res) => {
  // If user authenticated
  res.json({ success: true, user: req.user });
};
