import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import path from 'path';
import routes from './routes';
import { logger } from './utils/logger';
import { initializeDatabase } from './config/database';
import { getJwtSecret, purgeExpiredSessions } from './services/auth.service';

// Load environment variables — try root .env first
dotenv.config({ path: path.resolve(__dirname, '../../.env') });
dotenv.config(); // fallback: backend/.env

const app = express();
const PORT = process.env.PORT || 3000;

import rateLimit from 'express-rate-limit';

// Trust the first proxy hop so rate limiting and audit logs see the real client IP
app.set('trust proxy', 1);

// Middleware
app.use(helmet());

// Flexible multi-origin CORS support for production deployments
const allowedOrigins = (process.env.FRONTEND_URL || 'http://localhost:5173')
  .split(',')
  .map(o => o.trim().replace(/\/+$/, ''))
  .filter(Boolean);

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin.replace(/\/+$/, ''))) {
      callback(null, true);
    } else {
      callback(new Error('CORS policy: origin not allowed'));
    }
  },
  credentials: true
}));

// Global API rate limiter — protects public deployment against volumetric denial of service
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: Number(process.env.API_RATE_LIMIT_MAX) || 600,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests from this address. Please try again later.' },
});

app.use('/api', apiLimiter);

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(cookieParser());
app.use(morgan('combined', {
  stream: {
    write: (message) => logger.info(message.trim())
  }
}));

// Routes
app.use('/api', routes);

// Error handling middleware — sanitized for production security
app.use((err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  logger.error('Unhandled error:', err);
  const status = typeof err.status === 'number' && err.status >= 400 && err.status < 600 ? err.status : 500;
  const message = process.env.NODE_ENV === 'production' && status === 500
    ? 'Internal server error'
    : (err.message || 'Internal server error');

  res.status(status).json({ error: message });
});

// Start server
app.listen(PORT, async () => {
  logger.info(`🚀 Server running on port ${PORT}`);
  logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
  logger.info(`API: http://localhost:${PORT}/api`);

  if (!process.env.GITHUB_TOKEN) {
    logger.warn('⚠️ GITHUB_TOKEN is not set in environment. GitHub API rate limits will be restricted.');
  }

  // Fail fast at boot if the signing secret is missing in production, rather
  // than at the first login attempt.
  getJwtSecret();

  // Initialize database
  await initializeDatabase();

  // Clear out refresh tokens that have aged past their expiry
  const purged = await purgeExpiredSessions();
  if (purged > 0) logger.info(`Purged ${purged} expired session(s)`);
  setInterval(() => {
    purgeExpiredSessions().catch(err => logger.error('Session purge failed:', err));
  }, 60 * 60 * 1000).unref();
});

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM signal received: closing HTTP server');
  process.exit(0);
});

process.on('SIGINT', () => {
  logger.info('SIGINT signal received: closing HTTP server');
  process.exit(0);
});

export default app;
