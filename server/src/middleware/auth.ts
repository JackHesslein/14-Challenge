import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

interface JwtPayload {
  username: string;
}

export const authenticateToken = (req: Request, res: Response, next: NextFunction): void => {
  // Get the token from the Authorization header
  const authHeader = req.header('Authorization');
  const token = authHeader?.split(' ')[1];

  if (!token) {
    res.status(401).json({ message: 'Access denied. No token provided.' });
    return; // Ensure function execution stops here
  }

  try {
    const secretKey = process.env.JWT_SECRET || 'your-secret-key';

    // Verify the token and assert the correct type
    const decoded = jwt.verify(token, secretKey) as JwtPayload;

    // Attach user data to the request object
    (req as any).user = decoded;

    next(); // Move to the next middleware
  } catch (error) {
    res.status(403).json({ message: 'Invalid or expired token.' });
    return; // Ensure function execution stops on error
  }
};