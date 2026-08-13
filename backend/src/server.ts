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

// Trust the first proxy hop so rate limiting and audit logs see the real client IP
app.set('trust proxy', 1);

// Middleware
app.use(helmet());
app.use(cors({
  // Credentials mode forbids a wildcard origin — the refresh cookie needs an explicit one
  origin: process.env.FRONTEND_URL || 'http://localhost:5173',
  credentials: true
}));
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

// Error handling middleware
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  logger.error('Unhandled error:', err);
  res.status(err.status || 500).json({
    error: err.message || 'Internal server error'
  });
});

// Start server
app.listen(PORT, async () => {
  logger.info(`🚀 Server running on port ${PORT}`);
  logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
  logger.info(`API: http://localhost:${PORT}/api`);

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
