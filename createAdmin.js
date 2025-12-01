// server/createAdmin.js
require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

mongoose.connect(process.env.MONGO_URI).then(() => console.log("Connected"));

const AdminSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  email: { type: String, required: true },
  password: { type: String },
  role: { type: String, default: 'admin' } // <--- Added Role
});
const Admin = mongoose.model('Admin', AdminSchema);

const create = async () => {
  await Admin.deleteMany({}); // Clears old admins

  const salt = await bcrypt.genSalt(10);
  // Set your master password here
  const hashedPassword = await bcrypt.hash("MasterKey123", salt); 

  await new Admin({
    username: "SuperAdmin", // <--- Use a special name
    email: process.env.EMAIL_USER,
    password: hashedPassword,
    role: "superadmin"      // <--- THIS IS KEY
  }).save();

  console.log("✅ Super Admin Created!");
  console.log("User: SuperAdmin");
  console.log("Pass: MasterKey123");
  process.exit();
};

create();