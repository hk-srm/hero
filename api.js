const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const QRCode = require("qrcode");
const bodyParser = require("body-parser");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const os = require("os");
require("dotenv").config();

// Check for required secrets
const requiredSecrets = [
  "EMAIL_USER",
  "EMAIL_PASS",
  "FRONTEND_URL",
  "JWT_SECRET",
  "SESSION_SECRET",
  "MONGO_PASSWORD",
  "MONGO_URI",
];

const missingSecrets = requiredSecrets.filter((key) => !process.env[key]);
if (missingSecrets.length > 0) {
  console.error(
    `Missing required environment variables: ${missingSecrets.join(
      ", "
    )}. Exiting.`
  );
  process.exit(1);
}

const app = express();
app.use(bodyParser.json()); // Ensure this is present and applied early
app.use(bodyParser.urlencoded({ extended: true })); // Add this for form submissions

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false },
    store: MongoStore.create({ mongoUrl: process.env.MONGO_URI }),
  })
);

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("MongoDB connection error:", err));

const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  registrationNumber: { type: String, unique: true, required: true },
  passwordHash: String,
  verified: { type: Boolean, default: false },
  verificationToken: String,
});

const eventSchema = new mongoose.Schema({
  title: String,
  date: Date,
  location: String,
});

const registrationSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  eventId: { type: mongoose.Schema.Types.ObjectId, ref: "Event" },
  qrToken: String,
  scanned: { type: Boolean, default: false },
});

const User = mongoose.model("User", userSchema);
const Event = mongoose.model("Event", eventSchema);
const Registration = mongoose.model("Registration", registrationSchema);

const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Unauthorized" });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ message: "Invalid token" });
  }
};

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

app.get("/", (req, res) => {
  if (req.session.user) {
    // serve public/profile.html if user is logged in
    res.sendFile(__dirname + "/public/profile.html");
  } else {
    res.sendFile(__dirname + "/public/login.html");
  }
});

app.get("/style.css", (req, res) => {
  res.sendFile(__dirname + "/public/style.css");
});

app.get("/login", (req, res) => {
  if (req.session.user) {
    // Redirect to the main page if already logged in
    return res.redirect("/");
  }
  res.sendFile(__dirname + "/public/login.html");
});

app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Error during logout:", err);
      return res.status(500).json({ message: "Logout failed" });
    }
    res.clearCookie("connect.sid");
    res.redirect("/"); // Redirect to the login page after logout
  });
});

app.get("/profile", authMiddleware, async (req, res) => {
  req.sendFile(__dirname + "/public/profile.html");
});

app.post("/api/signup", async (req, res) => {
  const { name, email, registrationNumber, password } = req.body;

  // Validate input fields
  if (!name || !email || !registrationNumber || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  console.log("Received signup request:", req.body);
  try {
    const passwordHash = await bcrypt.hash(password, 10);
    const verificationToken = crypto.randomBytes(20).toString("hex");

    const user = await User.create({
      name,
      email,
      registrationNumber,
      passwordHash,
      verificationToken,
    });

    const verificationLink = `${process.env.FRONTEND_URL}/verify?token=${verificationToken}`;

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Verify your email",
      html: `<p>Hi ${name},</p><p>Please verify your email by clicking the link: <a href="${verificationLink}">Verify Email</a></p><p>or copy paste this link in your browser: ${verificationLink}</p><p>If you did not sign up, please ignore this email.</p><p>Best regards,<br>Team H.K.</p>
      </p><p>Thank you!</p>`,
    });

    res.json({ message: "User created. Check email to verify." });
  } catch (err) {
    console.error("Error during signup:", err);

    if (err.code === 11000) {
      return res
        .status(400)
        .json({ message: "Email or registration number already used" });
    }

    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/api/verify", async (req, res) => {
  const { token } = req.query;
  const user = await User.findOne({ verificationToken: token });
  if (!user) return res.status(400).json({ message: "Invalid token" });
  user.verified = true;
  user.verificationToken = undefined;
  await user.save();
  res.status(200).sendFile(__dirname + "/public/verified.html");
});

app.post("/api/login", async (req, res) => {
  const { loginID, password } = req.body;

  let user = await User.findOne({ email: loginID });
  if (!user) user = await User.findOne({ registrationNumber: loginID });

  if (!user) return res.status(401).json({ message: "Invalid credentials" });

  if (!user.verified)
    return res.status(403).json({ message: "Email not verified" });

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) return res.status(401).json({ message: "Invalid credentials" });

  const token = jwt.sign(
    { id: user._id, email: user.email },
    process.env.JWT_SECRET
  );
  req.session.user = { id: user._id, email: user.email };
  res.redirect("/"); // Redirect to the main page after login
});

app.get("/api/check-session", async (req, res) => {
  if (req.session.user) {
    const token = jwt.sign(
      { id: req.session.user.id, email: req.session.user.email },
      process.env.JWT_SECRET
    );
    res.json({ token });
  } else {
    res.status(401).json({ message: "No active session" });
  }
});

app.post("/api/register-event/:eventId", authMiddleware, async (req, res) => {
  const userId = req.user.id;
  const { eventId } = req.params;
  const qrToken = `${userId}-${eventId}-${Date.now()}`;
  await Registration.create({ userId, eventId, qrToken });
  const qrCodeDataURL = await QRCode.toDataURL(qrToken);
  res.json({ qrCode: qrCodeDataURL });
});

app.get("/api/events", async (req, res) => {
  const events = await Event.find();
  res.json(events);
});

app.get("/api/my-events", authMiddleware, async (req, res) => {
  const registrations = await Registration.find({
    userId: req.user.id,
  }).populate("eventId");
  res.json(registrations);
});

app.post("/api/scan", async (req, res) => {
  const { qrToken } = req.body;
  const reg = await Registration.findOne({ qrToken });
  if (!reg) return res.status(404).json({ message: "Invalid QR token" });
  if (reg.scanned) return res.status(400).json({ message: "Already used" });
  reg.scanned = true;
  await reg.save();
  res.json({ message: "Entry granted" });
});

app.get("/api/profile", async (req, res) => {
  console.log("Session ID:", req.sessionID); // Log session ID
  console.log("Session Data:", req.session); // Log session data

  if (!req.session.user) {
    return res.status(401).json({ message: "Unauthorized: No active session" });
  }

  const user = await User.findById(req.session.user.id).select(
    "id name email registrationNumber verified"
  );
  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  res.json(user);
});

app.post("/api/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Error during logout:", err);
      return res.status(500).json({ message: "Logout failed" });
    }
    res.clearCookie("connect.sid");
    res.json({ message: "Logged out successfully" });
  });
});

app.listen(3000, "0.0.0.0", () => {
  // Log only network-accessible IPv4 addresses
  const interfaces = os.networkInterfaces();
  const addresses = [];
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (
        iface.family === "IPv4" &&
        !iface.internal &&
        !iface.address.startsWith("127.")
      ) {
        addresses.push(iface.address);
      }
    }
  }
  console.log("Server running on the following network-accessible addresses:");
  addresses.forEach((addr) => console.log(`http://${addr}:3000`));
});
