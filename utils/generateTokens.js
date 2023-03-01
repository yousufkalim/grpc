const jwt = require('jsonwebtoken');
const { ACCESS_TOKEN_SECRET, REFRESH_TOKEN_SECRET } = process.env;

exports.generateAccessToken = (user) => {
  return jwt.sign({ user }, ACCESS_TOKEN_SECRET, { expiresIn: '20m' });
};

exports.generateRefreshToken = (user) => {
  return jwt.sign({ user }, REFRESH_TOKEN_SECRET);
};
