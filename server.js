require('dotenv').config();
const express = require('express');
const Stripe = require('stripe');
const cors = require('cors');
const nodemailer = require('nodemailer');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const morgan = require('morgan');

// --- CONFIG CHECKS ---
if (!process.env.STRIPE_SECRET_KEY || !process.env.EMAIL_USER || !process.env.EMAIL_PASS || !process.env.MONGO_URI) {
    console.error("❌ ERROR: Missing keys in .env file!");
    process.exit(1);
}

const app = express();
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

// --- DB CONNECTION ---
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ Connected to MongoDB"))
  .catch((err) => console.error("❌ MongoDB Error:", err));

// --- MODELS ---
const Admin = mongoose.model('Admin', new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true },
  password: { type: String, required: true },
  role: { type: String, default: 'admin', enum: ['superadmin', 'admin'] },
  resetToken: String, resetTokenExpiry: Date, approvalCode: String
}));

const Volunteer = mongoose.model('Volunteer', new mongoose.Schema({
  firstName: String, lastName: String, email: String, phone: String, skills: String, availability: String, date: { type: Date, default: Date.now }
}));

const Subscriber = mongoose.model('Subscriber', new mongoose.Schema({
  email: { type: String, unique: true }, date: { type: Date, default: Date.now }
}));

const ContactMessage = mongoose.model('ContactMessage', new mongoose.Schema({
  firstName: String, lastName: String, email: String, subject: String, message: String, date: { type: Date, default: Date.now }
}));

const Donation = mongoose.model('Donation', new mongoose.Schema({
  name: String, email: String, amount: Number, type: String, date: { type: Date, default: Date.now }
}));

const Event = mongoose.model('Event', new mongoose.Schema({
  title: String, date: Date, location: String, description: String, imageUrl: String,
  registrants: [{ name: String, email: String, date: { type: Date, default: Date.now } }]
}));

// --- MIDDLEWARE ---
app.use(morgan('dev')); 
app.use(helmet());
app.use(mongoSanitize());
app.use(cors({ origin: 'https://hands-of-hope-main.vercel.app' }));
app.use(express.json());
app.use(rateLimit({ 
  windowMs: 15 * 60 * 1000, 
  max: 100,
  message: { error: "Too many requests, please try again later." }
}));

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
});

// --- TEMPLATES ---
const getEmailTemplate = (subject, content) => `<!DOCTYPE html><html><head><meta charset="utf-8"><style>body{background:#f3f4f6;font-family:sans-serif}.wrapper{width:100%;padding:40px 0}.main{background:#fff;max-width:600px;margin:0 auto;border-radius:8px;padding:40px;box-shadow:0 4px 6px rgba(0,0,0,0.05)}h2{color:#e11d48;margin-top:0}a{color:#e11d48;text-decoration:none;font-weight:bold}.btn{background:#e11d48;color:#fff!important;padding:12px 24px;border-radius:6px;text-decoration:none;display:inline-block;margin:20px 0}</style></head><body><div class="wrapper"><div class="main"><h2>${subject}</h2>${content}<hr style="border:0;border-top:1px solid #eee;margin:30px 0"><p style="font-size:12px;color:#888;text-align:center">Hearts Hands of Hope</p></div></div></body></html>`;
const getTicketTemplate = (event, userName, userEmail) => {
  const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=${encodeURIComponent(`Ticket:${event.title}|User:${userEmail}`)}`;
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><style>body{background:#f3f4f6;font-family:sans-serif;padding:20px}.ticket{max-width:600px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden;border:1px solid #ddd}.header{background:#e11d48;color:#fff;padding:20px;text-align:center}.content{padding:30px;display:flex;justify-content:space-between;align-items:center}.info h2{margin:0 0 10px}.label{font-size:10px;color:#888;text-transform:uppercase;font-weight:bold;display:block}.val{font-size:16px;margin-bottom:10px;display:block}</style></head><body><div class="ticket"><div class="header"><h1>EVENT TICKET</h1></div><div class="content"><div class="info"><h2>${event.title}</h2><span class="label">Attendee</span><span class="val">${userName}</span><span class="label">Date</span><span class="val">${new Date(event.date).toLocaleDateString()}</span><span class="label">Location</span><span class="val">${event.location}</span></div><div><img src="${qrUrl}" width="120" height="120" style="border:4px solid white;box-shadow:0 2px 5px rgba(0,0,0,0.1)"></div></div></div></body></html>`;
};

// ================= ROUTES ================= //

app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const admin = await Admin.findOne({ username });
    if (!admin || !(await bcrypt.compare(password, admin.password))) return res.status(400).json({ error: "Invalid credentials" });
    res.json({ success: true, username: admin.username, role: admin.role });
  } catch (err) { res.status(500).json({ error: "Login failed" }); }
});
app.post('/auth/forgot-password', async (req, res) => {
  const { identifier } = req.body;
  try {
    const admin = await Admin.findOne({ $or: [{ username: identifier }, { email: identifier }] });
    if (!admin) return res.status(400).json({ error: "Account not found" });
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    admin.resetToken = code; admin.resetTokenExpiry = Date.now() + 900000; await admin.save();
    await transporter.sendMail({ from: process.env.EMAIL_USER, to: admin.email, subject: "🔑 Reset Code", html: getEmailTemplate("Reset Password", `<h1>${code}</h1>`) });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: "Error" }); }
});
app.post('/auth/reset-password', async (req, res) => {
  const { code, newPassword } = req.body;
  try {
    const admin = await Admin.findOne({ resetToken: code, resetTokenExpiry: { $gt: Date.now() } });
    if (!admin) return res.status(400).json({ error: "Invalid code" });
    admin.password = await bcrypt.hash(newPassword, 10); admin.resetToken = undefined; await admin.save();
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: "Error" }); }
});

app.post('/admin/add-user', async (req, res) => {
  const { currentUser, newUsername, newEmail, newPassword } = req.body;
  try {
    const requestor = await Admin.findOne({ username: currentUser });
    if (requestor?.role !== 'superadmin') return res.status(403).json({ error: "Access Denied" });
    if (await Admin.findOne({ $or: [{ username: newUsername }, { email: newEmail }] })) return res.status(400).json({ error: "User exists" });
    await new Admin({ username: newUsername, email: newEmail, password: await bcrypt.hash(newPassword, 10), role: 'admin' }).save();
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: "Failed" }); }
});
app.post('/admin/delete-user', async (req, res) => {
  const { currentUser, targetId } = req.body;
  try {
    const requestor = await Admin.findOne({ username: currentUser });
    if (requestor?.role !== 'superadmin') return res.status(403).json({ error: "Access Denied" });
    if (requestor._id.toString() === targetId) return res.status(400).json({ error: "Cannot delete self" });
    await Admin.findByIdAndDelete(targetId);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: "Failed" }); }
});

app.post('/admin/data', async (req, res) => {
  try {
    const [volunteers, messages, subscribers, admins, donations, events] = await Promise.all([
      Volunteer.find().sort({ date: -1 }), ContactMessage.find().sort({ date: -1 }),
      Subscriber.find().sort({ date: -1 }), Admin.find({}, '-password -resetToken -approvalCode'),
      Donation.find().sort({ date: -1 }), Event.find().sort({ date: 1 })
    ]);
    res.json({ volunteers, messages, subscribers, admins, donations, events });
  } catch (err) { res.status(500).json({ error: "Failed" }); }
});
app.post('/admin/request-broadcast-otp', async (req, res) => {
  const { currentUser, subject } = req.body;
  try {
    const superAdmin = await Admin.findOne({ role: 'superadmin' });
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    superAdmin.approvalCode = code; await superAdmin.save();
    await transporter.sendMail({ from: process.env.EMAIL_USER, to: superAdmin.email, subject: `Approval: ${subject}`, html: getEmailTemplate("Broadcast Request", `<p>User <b>${currentUser}</b> needs approval.</p><h1>${code}</h1>`) });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: "Failed" }); }
});
app.post('/send-newsletter', async (req, res) => {
  const { subject, message, currentUser, otp } = req.body;
  try {
    const sender = await Admin.findOne({ username: currentUser });
    if (sender.role !== 'superadmin') {
      const superAdmin = await Admin.findOne({ role: 'superadmin' });
      if (!otp || otp !== superAdmin.approvalCode) return res.status(403).json({ error: "Invalid OTP" });
      superAdmin.approvalCode = undefined; await superAdmin.save();
    }
    const subscribers = await Subscriber.find({});
    await transporter.sendMail({ from: process.env.EMAIL_USER, to: process.env.EMAIL_USER, bcc: subscribers.map(s => s.email), subject, html: getEmailTemplate(subject, message) });
    res.json({ success: true, count: subscribers.length });
  } catch (err) { res.status(500).json({ error: "Failed" }); }
});

app.get('/events', async (req, res) => { res.json(await Event.find().sort({ date: 1 })); });
app.post('/admin/add-event', async (req, res) => {
  if (!(await Admin.findOne({ username: req.body.currentUser }))) return res.status(403).json({ error: "Unauthorized" });
  await new Event(req.body).save(); res.json({ success: true });
});
app.post('/admin/delete-event', async (req, res) => {
  if (!(await Admin.findOne({ username: req.body.currentUser }))) return res.status(403).json({ error: "Unauthorized" });
  await Event.findByIdAndDelete(req.body.eventId); res.json({ success: true });
});
app.post('/events/register', async (req, res) => {
  const { eventId, name, email } = req.body;
  try {
    const event = await Event.findById(eventId);
    if (!event) return res.status(404).json({ error: "Not found" });
    if (event.registrants.find(r => r.email === email)) return res.status(400).json({ error: "Registered" });
    event.registrants.push({ name, email }); await event.save();
    await transporter.sendMail({ from: process.env.EMAIL_USER, to: email, subject: `Ticket: ${event.title}`, html: getTicketTemplate(event, name, email) });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: "Failed" }); }
});

// --- PAYMENT CHECKOUT SESSION (UPDATED FOR ALL PAYMENT METHODS) ---
app.post('/create-checkout-session', async (req, res) => {
  const { amount, isMonthly, name, email } = req.body;
  try {
    const session = await stripe.checkout.sessions.create({
      customer_email: email,
      metadata: { donorName: name, donorEmail: email, donationAmount: amount, donationType: isMonthly ? "Monthly" : "One-time" },
      line_items: [{ price_data: { currency: 'usd', product_data: { name: 'Donation' }, unit_amount: Math.round(amount * 100) }, quantity: 1 }],
      mode: 'payment',
      
      // --- ENABLE AUTOMATIC PAYMENT METHODS (Apple Pay, Google Pay, etc) ---
      automatic_payment_methods: { enabled: true }, 

      // URLs (Update this to your Vercel URL for production)
      success_url: 'http://localhost:8080/success?session_id={CHECKOUT_SESSION_ID}',
      cancel_url: 'http://localhost:8080/donate',
    });
    res.json({ url: session.url });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/verify-payment', async (req, res) => {
  const { sessionId } = req.body;
  try {
    const session = await stripe.checkout.sessions.retrieve(sessionId);
    if (session.payment_status === 'paid') {
      const { donorName, donorEmail, donationAmount, donationType } = session.metadata;
      await new Donation({ name: donorName, email: donorEmail, amount: parseFloat(donationAmount), type: donationType }).save();
      return res.json({ success: true });
    }
    res.status(400).json({ error: "Not paid" });
  } catch (err) { res.status(500).json({ error: "Verification failed" }); }
});

app.post('/apply-volunteer', async (req, res) => { await new Volunteer(req.body).save(); res.json({ success: true }); });
app.post('/contact-us', async (req, res) => { await new ContactMessage(req.body).save(); res.json({ success: true }); });
app.post('/subscribe', async (req, res) => { if (await Subscriber.findOne({ email: req.body.email })) return res.status(400).json({ error: "Exists" }); await new Subscriber(req.body).save(); res.json({ success: true }); });

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));