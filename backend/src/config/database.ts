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

// Handle graceful shutdown.
// `beforeExit` fires again every time the handler queues async work, so guard
// it — otherwise a short-lived script (like the seed) never exits.
let disconnected = false;
process.once('beforeExit', async () => {
  if (disconnected) return;
  disconnected = true;
  await prisma.$disconnect();
  logger.info('Prisma disconnected');
});

// Initialize database
export async function initializeDatabase() {
  try {
    // Check if we can connect to the database
    await prisma.$queryRaw`SELECT 1`;
    logger.info('✅ Database connection successful');

    // No account is ever auto-provisioned — accounts only come from the seed
    // script or an administrator. Just report whether the system is usable.
    const superAdmins = await prisma.user.count({ where: { role: 'SUPER_ADMIN', active: true } });
    if (superAdmins === 0) {
      logger.warn('⚠️  No active super administrator exists. Run: npm run db:seed');
    } else {
      const [orgs, users] = await Promise.all([
        prisma.organization.count(),
        prisma.user.count({ where: { active: true } }),
      ]);
      logger.info(`✅ Access control ready: ${users} active user(s) across ${orgs} organization(s)`);
    }
  } catch (error: any) {
    logger.error('⚠️  Database initialization error:', error.message);
    logger.info('This is normal on first run. Please run: npm run db:push && npm run db:seed');
  }
}

export default prisma;
