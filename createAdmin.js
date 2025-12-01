// server/createAdmin.js
require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

mongoose.connect(process.env.MONGO_URI).then(() => console.log("Connected"));

const AdminSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  email: { type: String, required: true },
  password: { type: String },
});
const Admin = mongoose.model('Admin', AdminSchema);

const create = async () => {
  await Admin.deleteMany({}); // WARNING: Deletes existing admins to start fresh

  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash("admin123", salt); // Initial Password

  await new Admin({
    username: "admin",           // Initial Username
    email: process.env.EMAIL_USER, // Uses your .env email
    password: hashedPassword
  }).save();

  console.log("✅ Admin Created!");
  console.log("User: admin");
  console.log("Pass: admin123");
  process.exit();
};

create();