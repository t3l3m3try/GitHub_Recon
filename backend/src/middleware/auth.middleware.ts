import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { logger } from '../utils/logger';

/**
 * Authentication Middleware
 */

// Extend Express Request type
declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
        email: string;
        role: string;
      };
    }
  }
}

export function authenticateToken(req: Request, res: Response, next: NextFunction) {
  try {
    // For local development, bypass authentication
    if (process.env.NODE_ENV === 'development') {
      req.user = {
        id: 'local-user-id',
        email: 'local@dev.com',
        role: 'USER'
      };
      return next();
    }

    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }

    const secret = process.env.JWT_SECRET || 'default-secret-change-this';

    jwt.verify(token, secret, (err, decoded: any) => {
      if (err) {
        logger.warn('Invalid token:', err.message);
        return res.status(403).json({ error: 'Invalid or expired token' });
      }

      req.user = {
        id: decoded.id,
        email: decoded.email,
        role: decoded.role
      };

      next();
    });
  } catch (error) {
    logger.error('Auth middleware error:', error);
    res.status(500).json({ error: 'Authentication error' });
  }
}

