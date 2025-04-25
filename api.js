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
const cookieParser = require("cookie-parser");
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

app.use(cookieParser());

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

// hash setter
userSchema.methods.setPassword = async function (password) {
  this.passwordHash = await bcrypt.hash(password, 10);
};

// comparison function
userSchema.methods.comparePassword = function (password) {
  return bcrypt.compare(password, this.passwordHash);
};

const User = mongoose.model("User", userSchema);
const Event = mongoose.model("Event", eventSchema);
const Registration = mongoose.model("Registration", registrationSchema);

const authMiddleware = async (req, res, next) => {
  const token = req.cookies.token;
  if (!token)
    return res
      .status(401)
      .sendFile(path.join(__dirname, "public", "login.html"));

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findById(decoded.id).select("-passwordHash");
    if (!req.user) return res.status(401).json({ error: "User not found" });
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
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
  if (req.cookies.token) {
    console.log("Token cookie:", req.cookies.token);
    return res.redirect("/home");
  }
  res.sendFile(`${__dirname}/public/index.html`);
});

// Serve login frontend
app.get("/login", (req, res) => {
  res.sendFile(`${__dirname}/public/login.html`);
});

app.get("/logout", (req, res) => {
  res.clearCookie("token", { path: "/" });
  res.redirect("/login");
});

app.get("/profile", authMiddleware, async (req, res) => {
  res.sendFile(`${__dirname}/public/profile.html`);
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

app.post("/api/login", async (req, res) => {
  const { loginID, password } = req.body;
  try {
    const user = await User.findOne({
      $or: [{ email: loginID }, { registrationNumber: loginID }],
    });
    if (!user || !(await user.comparePassword(password))) {
      return res.status(400).json({ error: "Invalid credentials" });
    }
    if (!user.verified) {
      return res.status(401).json({ error: "Account not verified" });
    }
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });
    res
      .cookie("token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      })
      .json({
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          registrationNumber: user.registrationNumber,
        },
      });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/home", authMiddleware, (req, res) => {
  res.send("Welcome to the home page. Implement frontend integration.");
});

app.post("/api/register-event", authMiddleware, async (req, res) => {
  const { eventId } = req.body;
  const userId = req.user.id;

  try {
    const existingRegistration = await Registration.findOne({
      userId,
      eventId,
    });
    if (existingRegistration) {
      return res
        .status(400)
        .json({ message: "Already registered for this event" });
    }

    const qrToken = `${userId}-${eventId}-${Date.now()}`;
    await Registration.create({ userId, eventId, qrToken });
    const qrCodeDataURL = await QRCode.toDataURL(qrToken);

    res.json({ message: "Registered successfully", qrCode: qrCodeDataURL });
  } catch (error) {
    console.error("Error registering for event:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/api/events", async (req, res) => {
  const events = await Event.find();
  res.json(events);
});

app.get("/api/my-events", authMiddleware, async (req, res) => {
  const registrations = await Registration.find({
    userId: req.user._id,
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

app.get("/api/profile", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select(
      "id name email registrationNumber verified"
    );
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const registrations = await Registration.find({
      userId: req.user._id,
    }).populate("eventId");

    const events = registrations.map((reg) => ({
      event: reg.eventId,
      qrCode: reg.qrToken,
    }));

    res.json({ user, events });
  } catch (error) {
    console.error("Error fetching profile:", error);
    res.status(500).json({ message: "Internal server error" });
  }
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
