require('dotenv').config();
const express = require('express');
const Stripe = require('stripe');
const cors = require('cors');
const nodemailer = require('nodemailer');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

// --- CONFIGURATION CHECKS ---
if (!process.env.STRIPE_SECRET_KEY || !process.env.EMAIL_USER || !process.env.EMAIL_PASS || !process.env.MONGO_URI) {
    console.error("❌ ERROR: Missing keys in .env file!");
    process.exit(1);
}

const app = express();
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

// --- DATABASE CONNECTION ---
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ Connected to MongoDB"))
  .catch((err) => console.error("❌ MongoDB Error:", err));

// --- SCHEMAS ---
const AdminSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true },
  password: { type: String, required: true },
  role: { type: String, default: 'admin', enum: ['superadmin', 'admin'] },
  resetToken: String,
  resetTokenExpiry: Date,
  approvalCode: String // For Broadcast OTP
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

// --- MIDDLEWARE ---
app.use(cors({ origin: 'https://hands-of-hope-2oxs.vercel.app' })); // Adjust to your frontend port
app.use(express.json());

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
});

// ================= AUTHENTICATION ================= //

app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const admin = await Admin.findOne({ username });
    if (!admin) return res.status(400).json({ error: "User not found" });

    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) return res.status(400).json({ error: "Invalid password" });

    res.json({ success: true, username: admin.username, role: admin.role });
  } catch (err) { res.status(500).json({ error: "Login failed" }); }
});

app.post('/auth/forgot-password', async (req, res) => {
  const { identifier } = req.body;
  try {
    const admin = await Admin.findOne({ $or: [{ username: identifier }, { email: identifier }] });
    if (!admin) return res.status(400).json({ error: "Account not found" });

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    admin.resetToken = code;
    admin.resetTokenExpiry = Date.now() + 900000;
    await admin.save();

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: admin.email,
      subject: "🔑 Password Reset Code",
      html: `<h3>Your Code: <b>${code}</b></h3>`
    });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: "Error sending code" }); }
});

app.post('/auth/reset-password', async (req, res) => {
  const { code, newPassword } = req.body;
  try {
    const admin = await Admin.findOne({ resetToken: code, resetTokenExpiry: { $gt: Date.now() } });
    if (!admin) return res.status(400).json({ error: "Invalid code" });

    const salt = await bcrypt.genSalt(10);
    admin.password = await bcrypt.hash(newPassword, salt);
    admin.resetToken = undefined;
    await admin.save();
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: "Error resetting password" }); }
});

// ================= SUPER ADMIN ACTIONS ================= //

app.post('/admin/add-user', async (req, res) => {
  const { currentUser, newUsername, newEmail, newPassword } = req.body;
  try {
    const requestor = await Admin.findOne({ username: currentUser });
    if (!requestor || requestor.role !== 'superadmin') return res.status(403).json({ error: "Access Denied" });

    const existing = await Admin.findOne({ $or: [{ username: newUsername }, { email: newEmail }] });
    if (existing) return res.status(400).json({ error: "User exists" });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await new Admin({ username: newUsername, email: newEmail, password: hashedPassword, role: 'admin' }).save();
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: "Failed" }); }
});

app.post('/admin/delete-user', async (req, res) => {
  const { currentUser, targetId } = req.body;
  try {
    const requestor = await Admin.findOne({ username: currentUser });
    if (!requestor || requestor.role !== 'superadmin') return res.status(403).json({ error: "Access Denied" });
    if (requestor._id.toString() === targetId) return res.status(400).json({ error: "Cannot delete self" });

    await Admin.findByIdAndDelete(targetId);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: "Failed" }); }
});

// ================= NEWSLETTER & BROADCAST ================= //

// 1. Regular Admin Requests Approval
app.post('/admin/request-broadcast-otp', async (req, res) => {
  const { currentUser, subject } = req.body;
  try {
    const superAdmin = await Admin.findOne({ role: 'superadmin' });
    if (!superAdmin) return res.status(500).json({ error: "No Super Admin found" });

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    superAdmin.approvalCode = code;
    await superAdmin.save();

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: superAdmin.email,
      subject: `🛡️ Approval Needed: ${subject}`,
      html: `<p>Admin <b>${currentUser}</b> wants to broadcast.</p><h3>Approval Code: ${code}</h3>`
    });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: "Failed to request" }); }
});

// 2. Send Broadcast (Checks OTP if not SuperAdmin)
app.post('/send-newsletter', async (req, res) => {
  const { subject, message, currentUser, otp } = req.body;
  try {
    const sender = await Admin.findOne({ username: currentUser });
    
    if (sender.role !== 'superadmin') {
      const superAdmin = await Admin.findOne({ role: 'superadmin' });
      if (!otp || otp !== superAdmin.approvalCode) return res.status(403).json({ error: "Invalid OTP" });
      
      superAdmin.approvalCode = undefined; // Clear OTP
      await superAdmin.save();
    }

    const subscribers = await Subscriber.find({});
    if (subscribers.length === 0) return res.status(400).json({ error: "No subscribers" });

    const emailList = subscribers.map(sub => sub.email);
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: process.env.EMAIL_USER,
      bcc: emailList,
      subject: `📢 ${subject}`,
      html: `<div style="padding:20px;">${message}</div>`,
    });
    res.json({ success: true, count: emailList.length });
  } catch (err) { res.status(500).json({ error: "Failed to send" }); }
});

// ================= GENERAL DATA ================= //

app.post('/admin/data', async (req, res) => {
  try {
    const [volunteers, messages, subscribers, admins] = await Promise.all([
      Volunteer.find().sort({ date: -1 }),
      ContactMessage.find().sort({ date: -1 }),
      Subscriber.find().sort({ date: -1 }),
      Admin.find({}, '-password -resetToken -approvalCode')
    ]);
    res.json({ volunteers, messages, subscribers, admins });
  } catch (err) { res.status(500).json({ error: "Error fetching data" }); }
});

// ================= PUBLIC FORMS ================= //

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
      success_url: 'https://hands-of-hope-2oxs.vercel.apps/success',
      cancel_url: 'https://hands-of-hope-2oxs.vercel.app/donate',
    });
    res.json({ url: session.url });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/apply-volunteer', async (req, res) => {
  try {
    await new Volunteer(req.body).save();
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: process.env.EMAIL_USER,
      subject: `New Volunteer: ${req.body.firstName}`,
      html: `<p>New app from ${req.body.email}</p>`
    });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: "Failed" }); }
});

app.post('/contact-us', async (req, res) => {
  try {
    await new ContactMessage(req.body).save();
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: "Failed" }); }
});

app.post('/subscribe', async (req, res) => {
  try {
    if (await Subscriber.findOne({ email: req.body.email })) return res.status(400).json({ error: "Exists" });
    await new Subscriber(req.body).save();
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: "Failed" }); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));