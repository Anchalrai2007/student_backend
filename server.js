const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(cors());

/* ===== MongoDB ===== */
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch(err => console.log(err));

/* ===== Model ===== */
const Student = mongoose.model("Student", {
  name: String,
  email: { type: String, unique: true },
  password: String,
  course: String
});

/* ===== Auth Middleware ===== */
const auth = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json("No Token");

  try {
    const decoded = jwt.verify(token.split(" ")[1], process.env.JWT_SECRET);
    req.user = decoded.id;
    next();
  } catch {
    res.status(400).json("Invalid Token");
  }
};

/* ===== Routes ===== */

// Register
app.post("/api/register", async (req, res) => {
  const { name, email, password, course } = req.body;

  const exist = await Student.findOne({ email });
  if (exist) return res.status(400).json("Email already exists");

  const hash = await bcrypt.hash(password, 10);
  await Student.create({ name, email, password: hash, course });

  res.json("Registered Successfully");
});

// Login
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await Student.findOne({ email });
  if (!user) return res.status(400).json("Invalid Credentials");

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json("Invalid Credentials");

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);

  res.json({ token });
});

// Dashboard
app.get("/api/dashboard", auth, async (req, res) => {
  const user = await Student.findById(req.user).select("-password");
  res.json(user);
});

// Update Password
app.put("/api/update-password", auth, async (req, res) => {
  const { oldPassword, newPassword } = req.body;

  const user = await Student.findById(req.user);

  const match = await bcrypt.compare(oldPassword, user.password);
  if (!match) return res.status(400).json("Wrong old password");

  user.password = await bcrypt.hash(newPassword, 10);
  await user.save();

  res.json("Password Updated");
});

// Update Course
app.put("/api/update-course", auth, async (req, res) => {
  const user = await Student.findByIdAndUpdate(
    req.user,
    { course: req.body.course },
    { new: true }
  );

  res.json(user);
});

/* ===== Server ===== */
app.listen(5000, () => console.log("Server running on port 5000"));