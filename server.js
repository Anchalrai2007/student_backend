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
  .catch(err => console.log("DB ERROR:", err));

/* ===== Model ===== */
const studentSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  course: String
});

const Student = mongoose.model("Student", studentSchema);

/* ===== Auth Middleware ===== */
const auth = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ message: "No Token" });

  try {
    const decoded = jwt.verify(token.split(" ")[1], process.env.JWT_SECRET);
    req.user = decoded.id;
    next();
  } catch {
    res.status(400).json({ message: "Invalid Token" });
  }
};

/* ===== Routes ===== */

// ✅ Register (FIXED)
app.post("/api/register", async (req, res) => {
  try {
    console.log("BODY:", req.body); // debug

    const { name, email, password, course } = req.body;

    // validation
    if (!name || !email || !password) {
      return res.status(400).json({ message: "All fields required" });
    }

    // check duplicate
    const exist = await Student.findOne({ email });
    if (exist) {
      return res.status(400).json({ message: "Email already exists" });
    }

    // hash password
    const hash = await bcrypt.hash(password, 10);

    // create user
    await Student.create({
      name,
      email,
      password: hash,
      course
    });

    res.status(201).json({ message: "Registered Successfully" });

  } catch (err) {
    console.error("REGISTER ERROR:", err);
    res.status(500).json({ message: "Server Error", error: err.message });
  }
});

// ✅ Login (FIXED)
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await Student.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Invalid Credentials" });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(400).json({ message: "Invalid Credentials" });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);

    res.json({ token });

  } catch (err) {
    console.error("LOGIN ERROR:", err);
    res.status(500).json({ message: "Server Error" });
  }
});

// ✅ Dashboard
app.get("/api/dashboard", auth, async (req, res) => {
  try {
    const user = await Student.findById(req.user).select("-password");
    res.json(user);
  } catch {
    res.status(500).json({ message: "Server Error" });
  }
});

// ✅ Update Password
app.put("/api/update-password", auth, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;

    const user = await Student.findById(req.user);

    const match = await bcrypt.compare(oldPassword, user.password);
    if (!match) {
      return res.status(400).json({ message: "Wrong old password" });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    res.json({ message: "Password Updated" });

  } catch {
    res.status(500).json({ message: "Server Error" });
  }
});

// ✅ Update Course
app.put("/api/update-course", auth, async (req, res) => {
  try {
    const user = await Student.findByIdAndUpdate(
      req.user,
      { course: req.body.course },
      { new: true }
    );

    res.json(user);

  } catch {
    res.status(500).json({ message: "Server Error" });
  }
});

/* ===== Server ===== */
app.listen(5000, () => console.log("Server running on port 5000"));