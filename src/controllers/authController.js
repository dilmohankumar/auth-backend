const User = require("../models/User");
const bcrypt = require("bcryptjs");
const otpGenerator = require("otp-generator");
const sendEmail = require("../services/sendEmail");
const generateToken = require("../utils/generateToken");
const Otp = require("../models/Otp");

// ============== SIGNUP (ONLY OTP + META) =================
exports.signup = async (req, res) => {
  const { name, email, phone, password } = req.body;

  const existing = await User.findOne({ $or: [{ email }, { phone }] });

  if (existing) {
    return res.status(400).json({ message: "User already exists" });
  }

  const otp = otpGenerator.generate(6, {
    upperCaseAlphabets: false,
    lowerCaseAlphabets: false,
    specialChars: false,
  });

  await Otp.deleteMany({ email, type: "signup" });

  await Otp.create({
    email,
    otp,
    type: "signup",
    expiresAt: new Date(Date.now() + 5 * 60 * 1000),

    meta: {
      name,
      email,
      phone,
      password,
    },
  });

  await sendEmail(email, otp);

  return res.json({
    message: "OTP sent. Verify OTP to complete signup",
  });
};

// =============== VERIFY OTP (CREATE USER) =================
exports.verifyOTP = async (req, res) => {
  try {
    const { email, otp } = req.body;

    const record = await Otp.findOne({ email, type: "signup" });

    if (!record) {
      return res.status(400).json({ message: "OTP expired or not found" });
    }

    if (record.otp !== otp) {
      return res.status(400).json({ message: "Invalid OTP" });
    }

    const hashedPassword = await bcrypt.hash(record.meta.password, 10);

    const user = await User.create({
      name: record.meta.name,
      email: record.meta.email,
      phone: record.meta.phone,
      password: hashedPassword,
      isEmailVerified: true,
    });

    await Otp.deleteOne({ email, type: "signup" });

    const token = generateToken(user._id);

    res.status(201).json({
      message: "Signup completed successfully",
      user,
      token,
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// ================= LOGIN =================
exports.login = async (req, res) => {
  try {
    const { email, phone, password } = req.body;

    const user = await User.findOne({
      $or: [{ email }, { phone }],
    });

    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const token = generateToken(user._id);

    res.status(200).json({
      success: true,
      token,
      user,
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// ================= SEND OTP =================
exports.sendOTP = async (req, res) => {
  try {
    const { email, name, phone, password } = req.body;
    const existingSignupRecord = await Otp.findOne({ email, type: "signup" });
    const signupMeta = existingSignupRecord?.meta || {
      name,
      email,
      phone,
      password,
    };

    const otp = otpGenerator.generate(6, {
      upperCaseAlphabets: false,
      lowerCaseAlphabets: false,
      specialChars: false,
    });

    await Otp.deleteMany({ email, type: "signup" });

    await Otp.create({
      email,
      otp,
      type: "signup",
      expiresAt: new Date(Date.now() + 5 * 60 * 1000),
      meta: signupMeta,
    });

    await sendEmail(email, otp);

    res.status(200).json({
      message: "OTP sent successfully",
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// ================= FORGOT PASSWORD =================
exports.forgetPassword = async (req, res) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const otp = otpGenerator.generate(6, {
      upperCaseAlphabets: false,
      lowerCaseAlphabets: false,
      specialChars: false,
    });

    await Otp.deleteMany({ email, type: "forgot" });

    await Otp.create({
      email,
      otp,
      type: "forgot",
      expiresAt: new Date(Date.now() + 5 * 60 * 1000),
    });

    await sendEmail(email, otp);

    res.status(200).json({
      message: "Password reset OTP sent",
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// ================= RESET PASSWORD =================
exports.resetPassword = async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;

    const record = await Otp.findOne({ email, type: "forgot" });

    if (!record) {
      return res.status(400).json({
        message: "OTP not found or expired",
      });
    }

    if (record.otp !== otp) {
      return res.status(400).json({
        message: "Invalid OTP",
      });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await User.updateOne({ email }, { password: hashedPassword });

    await Otp.deleteOne({ email, type: "forgot" });

    res.status(200).json({
      message: "Password reset successful",
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// ================= GET ME =================
exports.getMe = async (req, res) => {
  try {
    res.status(200).json({
      success: true,
      user: req.user,
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};
