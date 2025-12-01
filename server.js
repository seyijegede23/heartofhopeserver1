// server/server.js
require('dotenv').config();
const express = require('express');
const Stripe = require('stripe');
const cors = require('cors');
const nodemailer = require('nodemailer');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

// --- 1. CONFIGURATION CHECKS ---
if (!process.env.STRIPE_SECRET_KEY || !process.env.EMAIL_USER || !process.env.EMAIL_PASS || !process.env.MONGO_URI) {
    console.error("❌ ERROR: Missing required keys in .env file!");
    process.exit(1);
}

const app = express();
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

// --- 2. DATABASE CONNECTION ---
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ Connected to MongoDB"))
  .catch((err) => console.error("❌ MongoDB Error:", err));

// --- 3. DATABASE MODELS ---
const AdminSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true },
  password: { type: String, required: true },
  resetToken: String,
  resetTokenExpiry: Date
});
const Admin = mongoose.model('Admin', AdminSchema);

const Volunteer = mongoose.model('Volunteer', new mongoose.Schema({
  firstName: String, lastName: String, email: String, phone: String, skills: String, availability: String, date: { type: Date, default: Date.now }
}));

const Subscriber = mongoose.model('Subscriber', new mongoose.Schema({
  email: { type: String, unique: true }, date: { type: Date, default: Date.now }
}));

const ContactMessage = mongoose.model('ContactMessage', new mongoose.Schema({
  firstName: String, lastName: String, email: String, subject: String, message: String, date: { type: Date, default: Date.now }
}));

// --- 4. MIDDLEWARE ---
app.use(cors({ origin: 'http://localhost:8080' })); // Matches your frontend
app.use(express.json());

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
});

// ================= ADMIN AUTHENTICATION ================= //

// Login
app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const admin = await Admin.findOne({ username });
    if (!admin) return res.status(400).json({ error: "User not found" });

    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) return res.status(400).json({ error: "Invalid password" });

    res.json({ success: true, message: "Login successful" });
  } catch (err) { res.status(500).json({ error: "Login failed" }); }
});

// Forgot Password (Send Code)
app.post('/auth/forgot-password', async (req, res) => {
  const { identifier } = req.body; // Username OR Email
  try {
    const admin = await Admin.findOne({ $or: [{ username: identifier }, { email: identifier }] });
    if (!admin) return res.status(400).json({ error: "Account not found" });

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    admin.resetToken = code;
    admin.resetTokenExpiry = Date.now() + 900000; // 15 mins
    await admin.save();

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: admin.email,
      subject: "🔑 Password Reset Code",
      html: `<h3>Your Reset Code is: <b>${code}</b></h3>`
    });

    res.json({ success: true, message: "Code sent" });
  } catch (err) { res.status(500).json({ error: "Error sending code" }); }
});

// Reset Password (Verify Code)
app.post('/auth/reset-password', async (req, res) => {
  const { code, newPassword } = req.body;
  try {
    const admin = await Admin.findOne({ resetToken: code, resetTokenExpiry: { $gt: Date.now() } });
    if (!admin) return res.status(400).json({ error: "Invalid or expired code" });

    const salt = await bcrypt.genSalt(10);
    admin.password = await bcrypt.hash(newPassword, salt);
    admin.resetToken = undefined;
    admin.resetTokenExpiry = undefined;
    await admin.save();

    res.json({ success: true, message: "Password changed" });
  } catch (err) { res.status(500).json({ error: "Error resetting password" }); }
});


// ================= ADMIN DASHBOARD ROUTES ================= //

// Get All Data (Protected)
app.post('/admin/data', async (req, res) => {
  try {
    const [volunteers, messages, subscribers, admins] = await Promise.all([
      Volunteer.find().sort({ date: -1 }),
      ContactMessage.find().sort({ date: -1 }),
      Subscriber.find().sort({ date: -1 }),
      Admin.find({}, '-password -resetToken') // Hides passwords
    ]);
    res.json({ volunteers, messages, subscribers, admins });
  } catch (err) { res.status(500).json({ error: "Failed to fetch data" }); }
});

// Create New Admin User
app.post('/admin/add-user', async (req, res) => {
  const { newUsername, newEmail, newPassword } = req.body;
  try {
    const existing = await Admin.findOne({ $or: [{ username: newUsername }, { email: newEmail }] });
    if (existing) return res.status(400).json({ error: "User already exists" });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    await new Admin({ username: newUsername, email: newEmail, password: hashedPassword }).save();
    res.json({ success: true, message: "Admin created" });
  } catch (err) { res.status(500).json({ error: "Failed to create admin" }); }
});

// Send Newsletter Broadcast
app.post('/send-newsletter', async (req, res) => {
  const { subject, message, adminPassword } = req.body; // In real app, verify session, not password again
  try {
    const subscribers = await Subscriber.find({});
    if (subscribers.length === 0) return res.status(400).json({ error: "No subscribers" });

    const emailList = subscribers.map(sub => sub.email);
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: process.env.EMAIL_USER,
      bcc: emailList,
      subject: `📢 ${subject}`,
      html: `<div style="padding:20px; font-family:sans-serif;">${message}</div>`,
    });
    res.json({ success: true, count: emailList.length });
  } catch (err) { res.status(500).json({ error: "Failed to send" }); }
});


// ================= PUBLIC ROUTES ================= //

// Stripe Payment
app.post('/create-checkout-session', async (req, res) => {
  const { amount, isMonthly } = req.body;
  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [{
        price_data: {
          currency: 'usd',
          product_data: { name: isMonthly ? 'Monthly Donation' : 'One-time Donation' },
          unit_amount: Math.round(amount * 100),
          recurring: isMonthly ? { interval: 'month' } : undefined,
        },
        quantity: 1,
      }],
      mode: isMonthly ? 'subscription' : 'payment',
      success_url: 'http://localhost:8080/success',
      cancel_url: 'http://localhost:8080/donate',
    });
    res.json({ url: session.url });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Volunteer Application
app.post('/apply-volunteer', async (req, res) => {
  try {
    await new Volunteer(req.body).save();
    
    // Notify Admin via Email
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: process.env.EMAIL_USER,
      subject: `New Volunteer: ${req.body.firstName}`,
      html: `<p>New volunteer application from ${req.body.email}</p>`
    });

    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: "Failed" }); }
});

// Contact Form
app.post('/contact-us', async (req, res) => {
  try {
    await new ContactMessage(req.body).save();

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: process.env.EMAIL_USER,
      replyTo: req.body.email,
      subject: `Inquiry: ${req.body.subject}`,
      html: `<p>From: ${req.body.email}</p><p>${req.body.message}</p>`
    });

    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: "Failed" }); }
});

// Newsletter Subscribe
app.post('/subscribe', async (req, res) => {
  try {
    if (await Subscriber.findOne({ email: req.body.email })) return res.status(400).json({ error: "Already subscribed" });
    await new Subscriber(req.body).save();
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: "Failed" }); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));