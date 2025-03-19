#!/usr/bin/env node
import fs from "fs-extra";
import inquirer from "inquirer";
import chalk from "chalk";

const userModelTemplate = () => `
import mongoose from 'mongoose';

const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }
}, { timestamps: true });

export default mongoose.model('User', UserSchema);
`;

const authControllerTemplate = () => `
import User from '../models/User.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

export const register = async (req, res) => {
    try {
        const { name, email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ name, email, password: hashedPassword });
        await newUser.save();
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const login = async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ message: 'Invalid email or password' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: 'Invalid email or password' });

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};
`;

const userControllerTemplate = () => `
import User from '../models/User.js';

export const getAllUsers = async (req, res) => {
    try {
        const users = await User.find().select('-password');
        res.json(users);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};
`;

const authMiddlewareTemplate = () => `
import jwt from 'jsonwebtoken';

export const protect = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Unauthorized' });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).json({ message: 'Invalid token' });
    }
};
`;

const authRoutesTemplate = () => `
import express from 'express';
import { register, login } from '../controllers/authController.js';

const router = express.Router();

router.post('/register', register);
router.post('/login', login);

export default router;
`;

const userRoutesTemplate = () => `
import express from 'express';
import { getAllUsers } from '../controllers/userController.js';
import { protect } from '../middleware/authMiddleware.js';

const router = express.Router();

router.get('/', protect, getAllUsers);

export default router;
`;

const dbTemplate = () => `
import mongoose from 'mongoose';

const connectDB = async () => {
    try {
        await mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });
        console.log('MongoDB Connected...');
    } catch (error) {
        console.error(error.message);
        process.exit(1);
    }
};

export default connectDB;
`;

const serverTemplate = () => `
import express from 'express';
import dotenv from 'dotenv';
import connectDB from './config/db.js';
import authRoutes from './routes/authRoutes.js';
import userRoutes from './routes/userRoutes.js';

dotenv.config();
connectDB();

const app = express();
app.use(express.json());

app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(\`Server running on port \${PORT}\`));
`;

const envTemplate = () => `
MONGO_URI=mongodb://localhost:27017/authDB
JWT_SECRET=supersecretkey
PORT=5000
`;

async function createAuthModule() {
  const basePath = `backend`;
  await fs.ensureDir(`${basePath}/models`);
  await fs.ensureDir(`${basePath}/controllers`);
  await fs.ensureDir(`${basePath}/routes`);
  await fs.ensureDir(`${basePath}/middleware`);
  await fs.ensureDir(`${basePath}/config`);

  const files = [
    { path: `${basePath}/models/User.js`, content: userModelTemplate() },
    {
      path: `${basePath}/controllers/authController.js`,
      content: authControllerTemplate(),
    },
    {
      path: `${basePath}/controllers/userController.js`,
      content: userControllerTemplate(),
    },
    {
      path: `${basePath}/middleware/authMiddleware.js`,
      content: authMiddlewareTemplate(),
    },
    { path: `${basePath}/routes/authRoutes.js`, content: authRoutesTemplate() },
    { path: `${basePath}/routes/userRoutes.js`, content: userRoutesTemplate() },
    { path: `${basePath}/config/db.js`, content: dbTemplate() },
    { path: `${basePath}/server.js`, content: serverTemplate() },
    { path: `${basePath}/.env`, content: envTemplate() },
  ];

  for (const file of files) {
    await fs.outputFile(file.path, file.content);
    console.log(chalk.green(`✔ Created: ${file.path}`));
  }
}

async function main() {
  const { moduleName } = await inquirer.prompt([
    {
      type: "input",
      name: "moduleName",
      message: "Enter module name (e.g., AuthModule):",
    },
  ]);
  console.log(chalk.blue("Generating Authentication System..."));
  await createAuthModule();
  console.log(chalk.gray("🎉 Backend Auth module created successfully!"));
}

main();
