const express = require("express");

const router = express.Router();
const protect = require("../middlewares/authMiddleware");

const {
  signup,
  login,
  sendOTP,
  verifyOTP,
  forgetPassword,
  resetPassword,
  getMe,
} = require("../controllers/authController");

router.post("/signup", signup);

router.post("/login", login);

router.post("/send-otp", sendOTP);

router.post("/verify-otp", verifyOTP);

router.post("/forget-password", forgetPassword);

router.post("/reset-password", resetPassword);

router.get("/me", protect, getMe);

module.exports = router;
