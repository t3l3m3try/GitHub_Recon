import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
  console.log('🌱 Seeding database...');

  // Create a test user for development
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

  console.log('✅ Seeding completed');
  console.log('   User:', user.email);
}

main()
  .catch((e) => {
    console.error('❌ Seeding failed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
