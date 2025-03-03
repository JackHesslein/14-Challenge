import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { User } from '../models/user';
import { Router } from 'express';

export const login = async (req: Request, res: Response): Promise<void> => {
  try {
    const { username, password } = req.body; // Expect username instead of email

    // Check if the user exists
    const user = await User.findOne({ where: { username } });
    if (!user) {
      res.status(400).json({ message: 'Invalid username or password' });
      return;
    }

    // Validate password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      res.status(400).json({ message: 'Invalid username or password' });
      return;
    }

    // Generate JWT token
    const secretKey = process.env.JWT_SECRET || 'your-secret-key';
    const token = jwt.sign(
      { id: user.id, username: user.username }, // Removed email
      secretKey,
      { expiresIn: '1h' }
    );

    res.json({ token, user: { id: user.id, username: user.username } });
    return;
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error' });
    return;
  }
};

const router = Router();

// POST /login - Login a user
router.post('/login', login);

export default router;
