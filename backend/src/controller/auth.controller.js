import tryCatch from "../utils/tryCatch.js";
import User from "../models/user.model.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import {
  generateAccessToken,
  generateRefreshToken,
} from "../utils/token.js";

const register = tryCatch(async (req, res, next) => {
  const { fullName, email, password, username } = req.body;

  if (!fullName || !email || !password || !username) {
    return res.status(400).json({ message: "All fields are required" });
  }

  const usernameRegex = /^(?!.*\.\.)(?!.*\.$)[a-zA-Z0-9._]{1,30}$/;
  if (!usernameRegex.test(username)) {
    return res.status(400).json({ message: "Invalid username format" });
  }

  const isUsernameTaken = await User.exists({ username: username.toLowerCase() });
  if (isUsernameTaken) {
    return res.status(409).json({ message: "Username already taken" });
  }

  const isEmailTaken = await User.exists({ email });
  if (isEmailTaken) {
    return res.status(409).json({ message: "Email already taken" });
  }

  const salt = bcrypt.genSaltSync(10);
  const hashedPassword = bcrypt.hashSync(password, salt);

  await User.create({
    fullName,
    email,
    username: username.toLowerCase().trim(),
    password: hashedPassword,
  });

  return res
    .status(201)
    .json({ message: "Account created successfully" });
});

const login = tryCatch(async (req, res, next) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Username and password required" });
  }

  const userDoc = await User.findOne({ username: username.toLowerCase() }).select("+password");
  if (!userDoc) {
    return res.status(404).json({ message: "User not found" });
  }

  const isPassOk = bcrypt.compareSync(password, userDoc.password);
  if (!isPassOk) {
    return res.status(401).json({ message: "Incorrect password" });
  }

  const refreshToken = generateRefreshToken(userDoc._id);
  const accessToken = generateAccessToken({ userId: userDoc._id });

  return res
    .cookie("refreshToken", refreshToken, {
      httpOnly: true,
      path: "/",
      secure: process.env.NODE_ENV === "production",
      sameSite: "None",
      maxAge: 30 * 24 * 60 * 60 * 1000,
    })
    .status(200)
    .json({
      message: "Login Successfully",
      accessToken,
      user: {
        id: userDoc._id,
        username: userDoc.username,
        email: userDoc.email,
        fullName: userDoc.fullName,
      },
    });
});

const refreshToken = tryCatch(async (req, res, next) => {
  const _refreshToken = req.cookies.refreshToken;
  if (!_refreshToken) {
    return res.status(401).json({ message: "Please login again" });
  }

  let decoded;
  try {
    decoded = jwt.verify(_refreshToken, process.env.REFRESH_TOKEN_SECRET);
  } catch (err) {
    return res.status(403).json({ message: "Invalid refresh token" });
  }

  const userDoc = await User.findById(decoded.userId);
  if (!userDoc) {
    return res.status(404).json({ message: "Account not found" });
  }

  const newAccessToken = generateAccessToken({ userId: userDoc._id });

  return res.status(200).json({ accessToken: newAccessToken });
});

const logout = tryCatch(async (req, res, next) => {
  res.clearCookie("refreshToken", { path: "/" });
  return res.status(200).json({ message: "Logout successful" });
});

const authController = {
  register,
  login,
  refreshToken,
  logout,
};

export default authController;
