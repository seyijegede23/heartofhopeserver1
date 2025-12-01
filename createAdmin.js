require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

mongoose.connect(process.env.MONGO_URI).then(() => console.log("Connected"));

const AdminSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  email: { type: String, required: true },
  password: { type: String },
  role: { type: String, default: 'admin' }
});
const Admin = mongoose.model('Admin', AdminSchema);

const create = async () => {
  await Admin.deleteMany({}); // Clears database
  const salt = await bcrypt.genSalt(10);
  // --- CHANGE PASSWORD HERE ---
  const hashedPassword = await bcrypt.hash("MasterKey123", salt); 

  await new Admin({
    username: "SuperAdmin",
    email: process.env.EMAIL_USER,
    password: hashedPassword,
    role: "superadmin"
  }).save();

  console.log("✅ Super Admin Created!");
  process.exit();
};

create();