/**
 * User schema
 * @author Zain Asif
 */
const mongoose = require('mongoose');

// Schema
const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
    },
    password: {
      type: String,
      required: true,
      minlength: 8,
    },
    refreshToken: String,
  },
  {
    timestamps: true,
  },
);

// Model
module.exports = mongoose.model('users', userSchema);
