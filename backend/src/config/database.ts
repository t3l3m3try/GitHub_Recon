import { PrismaClient } from '@prisma/client';
import { logger } from '../utils/logger';

/**
 * Prisma Client Configuration
 */

const prisma = new PrismaClient({
  log: [
    { level: 'warn', emit: 'event' },
    { level: 'error', emit: 'event' }
  ]
});

// Log Prisma warnings
prisma.$on('warn', (e) => {
  logger.warn('Prisma warning:', e);
});

// Log Prisma errors
prisma.$on('error', (e) => {
  logger.error('Prisma error:', e);
});

// Handle graceful shutdown
process.on('beforeExit', async () => {
  await prisma.$disconnect();
  logger.info('Prisma disconnected');
});

// Initialize database
export async function initializeDatabase() {
  try {
    // Check if we can connect to the database
    await prisma.$queryRaw`SELECT 1`;
    logger.info('✅ Database connection successful');

    // Ensure the development user exists
    if (process.env.NODE_ENV === 'development') {
      const user = await prisma.user.upsert({
        where: { email: 'local@dev.com' },
        update: {},
        create: {
          id: 'local-user-id',
          email: 'local@dev.com',
          password: 'test',
          role: 'USER'
        }
      });
      logger.info(`✅ Development user ready: ${user.email}`);
    }
  } catch (error: any) {
    logger.error('⚠️  Database initialization error:', error.message);
    logger.info('This is normal on first run. Please run: npm run db:push && npm run db:seed');
  }
}

export default prisma;
